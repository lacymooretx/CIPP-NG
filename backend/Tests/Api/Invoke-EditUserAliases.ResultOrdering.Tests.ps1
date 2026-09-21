# EditUserAliases used to append its "Success. ..." wording as each branch built the new address
# list, before Set-Mailbox had been called at all. A Set-Mailbox that threw therefore produced a
# response carrying both a success line and a failure line, and any caller reading the first entry
# was told a write had landed that never did. Success wording is now staged and only promoted once
# the write returns.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Identity/Administration/Users/Invoke-EditUserAliases.ps1'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs += $message }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

    function New-ExoRequest {
        param($tenantid, $cmdlet, $cmdParams, $UseSystemMailbox)
        if ($cmdlet -eq 'Get-Mailbox') {
            return [pscustomobject]@{
                DisplayName    = 'Test User'
                EmailAddresses = @('SMTP:user@contoso.com', 'SIP:user@contoso.com')
            }
        }
        $script:SetMailboxParams = $cmdParams
        if ($script:SetMailboxThrows) { throw 'The proxy address is already being used' }
        return $null
    }

    . $FunctionPath

    function New-TestRequest {
        param($Added, $Removed)
        $BodyObj = @{ tenantFilter = 'contoso.com'; id = 'user@contoso.com' }
        if ($Added) { $BodyObj.AddedAliases = $Added }
        if ($Removed) { $BodyObj.RemovedAliases = $Removed }
        [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'EditUserAliases' }
            Headers = @{}
            Body    = [pscustomobject]$BodyObj
        }
    }
}

Describe 'Invoke-EditUserAliases result reporting' {
    BeforeEach {
        $script:Logs = @()
        $script:SetMailboxParams = $null
        $script:SetMailboxThrows = $false
    }

    It 'reports success only after Set-Mailbox returns, and sends the new alias' {
        $Response = Invoke-EditUserAliases -Request (New-TestRequest -Added 'alias@contoso.com')
        $Results = @($Response.Body.Results)

        $Results | Should -Contain 'Success. Added new aliases to user.'
        $script:SetMailboxParams.EmailAddresses | Should -Contain 'smtp:alias@contoso.com'
    }

    It 'reports no success wording when the Set-Mailbox write throws' {
        $script:SetMailboxThrows = $true
        $Response = Invoke-EditUserAliases -Request (New-TestRequest -Added 'alias@contoso.com')
        $Results = @($Response.Body.Results)

        ($Results | Where-Object { $_ -like 'Success.*' }) | Should -BeNullOrEmpty
        ($Results | Where-Object { $_ -like 'Failed to manage aliases:*' }) | Should -Not -BeNullOrEmpty
    }

    It 'does the same for a removal that throws' {
        $script:SetMailboxThrows = $true
        $Response = Invoke-EditUserAliases -Request (New-TestRequest -Removed 'alias@contoso.com')
        $Results = @($Response.Body.Results)

        ($Results | Where-Object { $_ -like 'Success.*' }) | Should -BeNullOrEmpty
    }

    It 'warns the caller that an immediate read-back can still show the old addresses' {
        $Response = Invoke-EditUserAliases -Request (New-TestRequest -Added 'alias@contoso.com')
        $Results = @($Response.Body.Results)

        ($Results | Where-Object { $_ -like 'Note: Exchange may take several minutes*' }) | Should -Not -BeNullOrEmpty
    }

    It 'still reports nothing to do when no aliases are supplied' {
        $Response = Invoke-EditUserAliases -Request (New-TestRequest)
        @($Response.Body.Results) | Should -Be @('No alias changes specified.')
    }
}
