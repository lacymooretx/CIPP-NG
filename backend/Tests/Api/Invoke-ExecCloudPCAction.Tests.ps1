# Three of these actions destroy data and one deletes the machine:
#   reprovision    wipes the local disk
#   endGracePeriod deprovisions the Cloud PC - a deletion, not a pause
#   restore        discards everything written since the snapshot
#   resize         retains data but restarts the machine
#
# The protections are deliberately awkward in proportion, and these tests pin them: one Cloud PC
# per call (no bulk reprovision), typed confirmation matching the machine's OWN display name as
# fetched from Graph (so a stale UI cannot satisfy it), and the pre-action state captured in the
# audit log - because after a reprovision nothing is left to tell you what was there.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs += [pscustomobject]@{ Sev = $Sev; Message = $message } }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }
    function New-GraphGetRequest {
        param($uri, $tenantid, $AsApp, $ErrorAction)
        $script:GetAsApp = $AsApp
        return $script:CloudPc
    }
    function New-GraphPOSTRequest {
        param($uri, $tenantid, $body, $AsApp, $ErrorAction)
        $script:PostedUri = $uri; $script:PostedBody = $body; $script:PostAsApp = $AsApp
        return $null
    }

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/CloudPC/Invoke-ExecCloudPCAction.ps1')

    $script:PcName = 'Cloud PC - Lacy Moore'

    function New-ActionRequest {
        param([hashtable]$Body = @{})
        $BodyObj = @{ tenantFilter = 'contoso.com'; CloudPcId = 'pc-1' }
        foreach ($k in $Body.Keys) { $BodyObj[$k] = $Body[$k] }
        [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ExecCloudPCAction' }
            Headers = @{}
            Query   = [pscustomobject]@{}
            Body    = [pscustomobject]$BodyObj
        }
    }
}

Describe 'ExecCloudPCAction guards' {
    BeforeEach {
        $script:Logs = @()
        $script:PostedBody = $null
        $script:PostedUri = $null
        $script:CloudPc = [pscustomobject]@{
            id = 'pc-1'; displayName = $script:PcName; userPrincipalName = 'lacy@contoso.com'
            servicePlanName = 'Cloud PC Enterprise 16vCPU/64GB/512GB'; status = 'provisioned'
            managedDeviceName = 'CPC-lacy-4TGFR'; provisioningPolicyName = 'Cloud PC'
        }
    }

    It 'refuses <_> without the typed confirmation, and calls Graph not at all' -ForEach @('reprovision', 'endGracePeriod', 'restore') {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = $_ })

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'destructive and was not confirmed'
        # The error names the machine and its owner so the operator can check they have the right one.
        $Response.Body.Results | Should -Match ([regex]::Escape($script:PcName))
        $Response.Body.Results | Should -Match 'lacy@contoso.com'
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'refuses a confirmation that is close but not exact' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'reprovision'; ConfirmText = 'cloud pc - lacy moore' })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'refuses "yes" as a confirmation - it must be the machine name' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'reprovision'; ConfirmText = 'yes' })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'proceeds with reprovision when the exact name is given' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'reprovision'; ConfirmText = $script:PcName })

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:PostedUri | Should -Match '/cloudPCs/pc-1/reprovision$'
        $Response.Body.Results | Should -Match 'previous local disk is gone'
        $script:PostAsApp | Should -BeTrue
    }

    It 'refuses a list of Cloud PCs outright - no bulk destructive action' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ CloudPcId = @('pc-1', 'pc-2'); Action = 'reprovision'; ConfirmText = $script:PcName })

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'one Cloud PC at a time'
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'records the pre-action state at Warn, since nothing survives to tell you afterwards' {
        $null = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'reprovision'; ConfirmText = $script:PcName })

        $Warned = $script:Logs | Where-Object { $_.Sev -eq 'Warn' -and $_.Message -match 'reprovision requested' }
        $Warned | Should -Not -BeNullOrEmpty
        $Warned.Message | Should -Match 'CPC-lacy-4TGFR'
        $Warned.Message | Should -Match 'lacy@contoso.com'
    }

    It 'returns the previous state in the response body' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'reprovision'; ConfirmText = $script:PcName })
        $Response.Body.PreviousState.managedDeviceName | Should -Be 'CPC-lacy-4TGFR'
        $Response.Body.PreviousState.status | Should -Be 'provisioned'
    }

    It 'requires a SnapshotId for restore even once confirmed' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'restore'; ConfirmText = $script:PcName })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'requires SnapshotId'
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'sends the snapshot id Graph expects on restore' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'restore'; ConfirmText = $script:PcName; SnapshotId = 'snap-9' })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        ($script:PostedBody | ConvertFrom-Json).cloudPcSnapshotId | Should -Be 'snap-9'
    }

    It 'resize needs Confirm and a target plan, but not the typed name' {
        $NoConfirm = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'resize'; TargetServicePlanId = 'plan-2' })
        $NoConfirm.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $NoConfirm.Body.Results | Should -Match 'Confirm=true'

        $NoPlan = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'resize'; Confirm = $true })
        $NoPlan.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $NoPlan.Body.Results | Should -Match 'requires TargetServicePlanId'

        $Ok = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'resize'; Confirm = $true; TargetServicePlanId = 'plan-2' })
        $Ok.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        ($script:PostedBody | ConvertFrom-Json).targetServicePlanId | Should -Be 'plan-2'
    }

    It 'does not treat Confirm="false" as confirmation' {
        # The -in $TruthyValues idiom this replaced would have read 'false' as true.
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'resize'; Confirm = 'false'; TargetServicePlanId = 'plan-2' })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'lets troubleshoot through without confirmation - it changes nothing' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'troubleshoot' })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:PostedUri | Should -Match '/troubleshoot$'
        ($script:Logs | Where-Object { $_.Sev -eq 'Warn' }) | Should -BeNullOrEmpty
    }

    It 'rejects an unknown action rather than posting it to Graph' {
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'delete'; ConfirmText = $script:PcName })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'Invalid Action'
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'fails closed when the Cloud PC cannot be read' {
        $script:CloudPc = $null
        $Response = Invoke-ExecCloudPCAction -Request (New-ActionRequest @{ Action = 'reprovision'; ConfirmText = $script:PcName })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'was not found'
        $script:PostedBody | Should -BeNullOrEmpty
    }
}
