# ExecExoRequest write feedback (gaps doc §14, 2026-09-29).
# Set-CASMailbox -ActiveSyncDebugLogging $true came back {"Results":null}: Exchange returns nothing for
# a successful Set-*, so the caller had no way to tell an applied write from a silent no-op. The unified
# audit log later showed the write DID apply (ResultStatus True, 09:03 CDT) while Get-CASMailbox still
# read False hours later - so a read-back mismatch must be REPORTED, never turned into a failure.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    # Fake EXO: Set-* returns nothing; Get-* returns $script:GetResult; errors via $script:Throw.
    function New-ExoRequest {
        param($tenantid, $cmdlet, $cmdParams, $useSystemMailbox, [switch]$Compliance, $Anchor, $Select)
        $script:ExoCalls.Add(@{ Cmdlet = $cmdlet; Params = $cmdParams; Compliance = [bool]$Compliance; Anchor = $Anchor })
        if ($script:Throw -and $cmdlet -eq $script:Throw.Cmdlet) { throw $script:Throw.Message }
        if ($cmdlet -like 'Get-*') { return $script:GetResult }
        return $script:SetResult
    }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs.Add("$Sev|$message") }
    function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$($Exception.Exception.Message)" } }

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper/Get-ExoWriteVerification.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/CIPP/Core/Invoke-ExecExoRequest.ps1')

    function Invoke-Exo {
        param([string]$Cmdlet, $CmdParams, [hashtable]$Extra = @{})
        $Body = @{ TenantFilter = 'contoso.com'; Cmdlet = $Cmdlet } + $Extra
        if ($null -ne $CmdParams) { $Body.CmdParams = [pscustomobject]$CmdParams }
        Invoke-ExecExoRequest -Request ([pscustomobject]@{
                Params  = @{ CIPPEndpoint = 'ExecExoRequest' }
                Headers = @{}
                Query   = [pscustomobject]@{}
                Body    = [pscustomobject]$Body
            })
    }
}

Describe 'Invoke-ExecExoRequest write verification' {
    BeforeEach {
        $script:ExoCalls = [System.Collections.Generic.List[object]]::new()
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:GetResult = $null
        $script:SetResult = $null
        $script:Throw = $null
    }

    It 'never answers a successful Set-* with Results:null' {
        $script:GetResult = [pscustomobject]@{ Identity = 'Sameer Jetly'; ActiveSyncDebugLogging = $true }
        $R = Invoke-Exo -Cmdlet 'Set-CASMailbox' -CmdParams ([ordered]@{ Identity = 'sameer@contoso.com'; ActiveSyncDebugLogging = $true })
        $R.StatusCode | Should -Be 200
        $R.Body.Results | Should -Match 'Set-CASMailbox completed'
    }

    It 'confirms a write whose read-back matches, reading with the Get- twin and the same Identity' {
        $script:GetResult = [pscustomobject]@{ Identity = 'Sameer Jetly'; ActiveSyncDebugLogging = $true; PopEnabled = $false }
        $R = Invoke-Exo -Cmdlet 'Set-CASMailbox' -CmdParams ([ordered]@{ Identity = 'sameer@contoso.com'; ActiveSyncDebugLogging = 'True'; PopEnabled = $false })

        $R.Body.Verification.Status | Should -Be 'Confirmed'
        @($R.Body.Verification.Properties).Count | Should -Be 2
        $script:ExoCalls[1].Cmdlet | Should -Be 'Get-CASMailbox'
        $script:ExoCalls[1].Params.Identity | Should -Be 'sameer@contoso.com'
    }

    It 'REPORTS a mismatch (200 + Mismatch + audit-log hint + warning log) instead of failing' {
        # The real 09-29 case: write applied, Get-CASMailbox still says False.
        $script:GetResult = [pscustomobject]@{ Identity = 'Sameer Jetly'; ActiveSyncDebugLogging = $false }
        $R = Invoke-Exo -Cmdlet 'Set-CASMailbox' -CmdParams ([ordered]@{ Identity = 'sameer@contoso.com'; ActiveSyncDebugLogging = $true })

        $R.StatusCode | Should -Be 200
        $R.Body.Verification.Status | Should -Be 'Mismatch'
        $R.Body.Verification.Properties[0].Observed | Should -BeFalse
        $R.Body.Verification.Note | Should -Match 'Search-UnifiedAuditLog'
        ($script:Logs | Where-Object { $_ -like 'Warning|*ActiveSyncDebugLogging*' }) | Should -Not -BeNullOrEmpty
    }

    It 'treats a property the Get- output does not carry as a mismatch, not a match' {
        $script:GetResult = [pscustomobject]@{ Identity = 'x' }
        $R = Invoke-Exo -Cmdlet 'Set-Mailbox' -CmdParams ([ordered]@{ Identity = 'x'; HiddenFromAddressListsEnabled = $false })
        $R.Body.Verification.Status | Should -Be 'Mismatch'
    }

    It 'compares multi-value properties order- and case-insensitively' {
        $script:GetResult = [pscustomobject]@{ Identity = 'x'; AcceptMessagesOnlyFrom = @('B@x.com', 'a@x.com') }
        $R = Invoke-Exo -Cmdlet 'Set-Mailbox' -CmdParams ([ordered]@{ Identity = 'x'; AcceptMessagesOnlyFrom = @('a@x.com', 'b@x.com') })
        $R.Body.Verification.Status | Should -Be 'Confirmed'
    }

    It 'skips @{Add=...} style edits it cannot compare, and says so' {
        $script:GetResult = [pscustomobject]@{ Identity = 'x' }
        $R = Invoke-Exo -Cmdlet 'Set-Mailbox' -CmdParams ([ordered]@{ Identity = 'x'; EmailAddresses = @{ Add = 'smtp:y@x.com' } })
        $R.Body.Verification.Status | Should -Be 'Skipped'
        $script:ExoCalls.Count | Should -Be 1
    }

    It 'skips (does not fail) when the read-back cmdlet errors' {
        $script:Throw = @{ Cmdlet = 'Get-Widget'; Message = 'not recognized' }
        $R = Invoke-Exo -Cmdlet 'Set-Widget' -CmdParams ([ordered]@{ Identity = 'x'; Colour = 'red' })
        $R.StatusCode | Should -Be 200
        $R.Body.Verification.Status | Should -Be 'Skipped'
        $R.Body.Verification.Note | Should -Match 'not recognized'
    }

    It 'skips when the read-back returns several objects' {
        $script:GetResult = @([pscustomobject]@{ A = 1 }, [pscustomobject]@{ A = 1 })
        $R = Invoke-Exo -Cmdlet 'Set-Thing' -CmdParams ([ordered]@{ A = 1 })
        $R.Body.Verification.Status | Should -Be 'Skipped'
        $script:ExoCalls[1].Params | Should -BeNullOrEmpty
    }

    It 'carries Compliance and Anchor through to the read-back' {
        $script:GetResult = [pscustomobject]@{ Comment = 'x' }
        $null = Invoke-Exo -Cmdlet 'Set-DlpCompliancePolicy' -CmdParams ([ordered]@{ Identity = 'p'; Comment = 'x' }) -Extra @{ Compliance = 'true'; Anchor = 'a@contoso.com' }
        $script:ExoCalls[1].Compliance | Should -BeTrue
        $script:ExoCalls[1].Anchor | Should -Be 'a@contoso.com'
    }

    It 'does no read-back when VerifyWrite=<_>' -ForEach @('false', $false) {
        $R = Invoke-Exo -Cmdlet 'Set-CASMailbox' -CmdParams ([ordered]@{ Identity = 'x'; PopEnabled = $false }) -Extra @{ VerifyWrite = $_ }
        $script:ExoCalls.Count | Should -Be 1
        $R.Body.PSObject.Properties.Name | Should -Not -Contain 'Verification'
    }

    It 'passes Exchange warnings (e.g. "no settings modified") through as Results' {
        $script:SetResult = @('The command completed successfully but no settings of x have been modified.')
        $script:GetResult = [pscustomobject]@{ PopEnabled = $false }
        $R = Invoke-Exo -Cmdlet 'Set-CASMailbox' -CmdParams ([ordered]@{ Identity = 'x'; PopEnabled = $false })
        $R.Body.Results | Should -Match 'no settings'
    }

    It 'leaves Get-* output untouched: no completion message, no verification' {
        $script:GetResult = $null
        $R = Invoke-Exo -Cmdlet 'Get-CASMailbox' -CmdParams ([ordered]@{ Identity = 'x' })
        $R.Body.Results | Should -BeNullOrEmpty
        $R.Body.PSObject.Properties.Name | Should -Not -Contain 'Verification'
    }

    It 'gives Remove-* a completion message but no read-back' {
        $R = Invoke-Exo -Cmdlet 'Remove-TransportRule' -CmdParams ([ordered]@{ Identity = 'r'; Confirm = $false })
        $R.Body.Results | Should -Match 'Remove-TransportRule completed'
        $script:ExoCalls.Count | Should -Be 1
    }

    It 'points Search-AdminAuditLog failures at Search-UnifiedAuditLog' {
        $script:Throw = @{ Cmdlet = 'Search-AdminAuditLog'; Message = '403 - Forbidden' }
        $R = Invoke-Exo -Cmdlet 'Search-AdminAuditLog' -CmdParams ([ordered]@{ ObjectIds = @('x') })
        $R.StatusCode | Should -Be 400
        $R.Body.Results | Should -Match 'use Search-UnifiedAuditLog'
    }
}
