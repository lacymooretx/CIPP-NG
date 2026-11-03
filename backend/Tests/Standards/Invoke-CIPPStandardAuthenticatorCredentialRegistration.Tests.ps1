# Pester tests for Confirm-CIPPServicePrincipal and Invoke-CIPPStandardAuthenticatorCredentialRegistration (Vikunja CIPP-53)
#   - GET then POST, idempotent, no write on a report run or when the read failed;
#   - delegated create first, then the app token: delegated was refused in the partner tenant on 2026-11-03;
#   - a read-back that lags does not fail the run.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    function Find-SourceFile {
        param([string]$Name)
        $Path = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter $Name -File | Select-Object -First 1 -ExpandProperty FullName
        if (-not $Path) { throw "Could not locate $Name" }
        $Path
    }

    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp) }
    function New-GraphPOSTRequest { param($uri, $tenantid, $body, $type, $AsApp) }
    function Write-LogMessage { [CmdletBinding()] param($API, $tenant, $message, $sev) }
    function Write-StandardsAlert { [CmdletBinding()] param($message, $object, $tenant, $standardName, $standardId) }
    function Set-CIPPStandardsCompareField { [CmdletBinding()] param($FieldName, $CurrentValue, $ExpectedValue, $Tenant) }
    function Set-CIPPDBCacheServicePrincipals { [CmdletBinding()] param($TenantFilter) }

    . (Find-SourceFile 'Confirm-CIPPServicePrincipal.ps1')
    . (Find-SourceFile 'Invoke-CIPPStandardAuthenticatorCredentialRegistration.ps1')

    $script:Tenant = 'contoso.onmicrosoft.com'
    $script:AppId = '6aa00308-ea33-4caa-90d6-ae905d8cb51b'

    function New-TestSp {
        param([bool]$Enabled = $true, [string]$AppId = $script:AppId)
        [pscustomobject]@{ id = 'sp-object-id'; appId = $AppId; displayName = 'Microsoft Authenticator Credential Registration'; accountEnabled = $Enabled }
    }

    # Tenant state read by the mocks. LagReads = how many reads are still empty after a create.
    function Set-TestTenant {
        param([bool]$Exists = $false, [bool]$Enabled = $true, [int]$LagReads = 0, [bool]$ReadFails = $false, [string[]]$RefuseCreate = @(), [string]$CreateError = 'Insufficient privileges')
        $script:Sim = @{ Exists = $Exists; Enabled = $Enabled; LagReads = $LagReads; ReadFails = $ReadFails; RefuseCreate = $RefuseCreate; CreateError = $CreateError }
    }
}

Describe 'Confirm-CIPPServicePrincipal and the standard' {
    BeforeEach {
        $script:Posts = [System.Collections.Generic.List[object]]::new()
        $script:Reads = 0
        $script:Logs = [System.Collections.Generic.List[object]]::new()
        $script:Alerts = [System.Collections.Generic.List[object]]::new()
        $script:Compare = [System.Collections.Generic.List[object]]::new()
        $script:CacheRefreshes = 0

        Mock Start-Sleep { }
        Mock New-GraphGetRequest {
            $script:Reads++
            if ($script:Sim.ReadFails) { throw 'Forbidden' }
            if ($script:Sim.Exists) {
                if ($script:Sim.LagReads -gt 0) { $script:Sim.LagReads--; return }
                return (New-TestSp -Enabled $script:Sim.Enabled)
            }
        }
        Mock New-GraphPOSTRequest {
            $Token = if ($AsApp) { 'AsApp' } else { 'Delegated' }
            $script:Posts.Add([pscustomobject]@{ Token = $Token; Uri = $uri; Body = $body; Type = $type })
            if ($Token -in $script:Sim.RefuseCreate) { throw $script:Sim.CreateError }
            $script:Sim.Exists = $true
            New-TestSp
        }
        Mock Write-LogMessage { $script:Logs.Add([pscustomobject]@{ Message = $message; Sev = $sev }) }
        Mock Write-StandardsAlert { $script:Alerts.Add($message) }
        Mock Set-CIPPStandardsCompareField { $script:Compare.Add([pscustomobject]@{ Field = $FieldName; Current = $CurrentValue; Expected = $ExpectedValue }) }
        Mock Set-CIPPDBCacheServicePrincipals { $script:CacheRefreshes++ }
    }

    Context 'Confirm-CIPPServicePrincipal' {
        It 'does not POST when the service principal exists' {
            Set-TestTenant -Exists $true
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.State | Should -Be 'Present'
            $R.Created | Should -BeFalse
            $script:Posts.Count | Should -Be 0
        }

        It 'does not POST without -Provision' {
            Set-TestTenant
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId
            $R.State | Should -Be 'Absent'
            $R.Present | Should -BeFalse
            $script:Posts.Count | Should -Be 0
        }

        It 'creates with the delegated token, on v1.0, with only the appId, and reads it back' {
            Set-TestTenant
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.State | Should -Be 'Created'
            $R.Method | Should -Be 'Delegated'
            $script:Posts.Count | Should -Be 1
            $script:Posts[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/servicePrincipals'
            $script:Posts[0].Type | Should -Be 'POST'
            ($script:Posts[0].Body | ConvertFrom-Json).appId | Should -Be $script:AppId
        }

        It 'falls back to the app token when delegated is refused, as in the partner tenant' {
            Set-TestTenant -RefuseCreate @('Delegated')
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.State | Should -Be 'Created'
            $R.Method | Should -Be 'AsApp'
            @($script:Posts.Token) | Should -Be @('Delegated', 'AsApp')
        }

        It 'tolerates a read-back that lags, and waits between reads' {
            Set-TestTenant -LagReads 2
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.State | Should -Be 'Created'
            $R.Id | Should -Be 'sp-object-id'
            Should -Invoke Start-Sleep -Times 2 -Exactly
        }

        It 'is CreatedPendingReadBack, not failed, when the read-back never catches up' {
            Set-TestTenant -LagReads 99
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.State | Should -Be 'CreatedPendingReadBack'
            $R.Present | Should -BeTrue
            $R.Error | Should -BeNullOrEmpty
            $script:Posts.Count | Should -Be 1
        }

        It 'treats "already exists" as present, and does not try the other token' {
            Set-TestTenant -RefuseCreate @('Delegated', 'AsApp') -CreateError 'Another object with the same value for property appId already exists.'
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.Present | Should -BeTrue
            $R.Created | Should -BeFalse
            $script:Posts.Count | Should -Be 1
        }

        It 'fails with both errors when neither token can create it, without waiting' {
            Set-TestTenant -RefuseCreate @('Delegated', 'AsApp')
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.State | Should -Be 'Failed'
            $R.Present | Should -BeFalse
            $R.Error | Should -Match 'Delegated: .*AsApp: '
            Should -Invoke Start-Sleep -Times 0 -Exactly
        }

        It 'does not count an empty POST result as created' {
            Set-TestTenant
            Mock New-GraphPOSTRequest { $script:Posts.Add($true) }
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.State | Should -Be 'Failed'
            $R.Present | Should -BeFalse
        }

        It 'returns Unknown and never POSTs when the read fails' {
            Set-TestTenant -ReadFails $true
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId -Provision
            $R.State | Should -Be 'Unknown'
            $R.Error | Should -Match 'Forbidden'
            $script:Posts.Count | Should -Be 0
        }

        It 'reads as the app, then falls back to delegated' {
            Set-TestTenant -Exists $true
            Mock New-GraphGetRequest { if ($AsApp) { throw 'app refused' } New-TestSp }
            $R = Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId
            $R.State | Should -Be 'Present'
            Should -Invoke New-GraphGetRequest -Times 2 -Exactly
        }

        It 'ignores another app if the filter was not applied' {
            Set-TestTenant
            Mock New-GraphGetRequest { New-TestSp -AppId 'ea890292-c8c8-4433-b5ea-b09d0668e1a6' }
            (Confirm-CIPPServicePrincipal -TenantFilter $script:Tenant -AppId $script:AppId).State | Should -Be 'Absent'
        }
    }

    Context 'Standard' {
        It 'report run never writes, and shows it missing' {
            Set-TestTenant
            Invoke-CIPPStandardAuthenticatorCredentialRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ report = $true })
            $script:Posts.Count | Should -Be 0
            $script:Compare[0].Field | Should -Be 'standards.AuthenticatorCredentialRegistration'
            $script:Compare[0].Current.ServicePrincipalPresent | Should -BeFalse
        }

        It 'alert run never writes, and alerts' {
            Set-TestTenant
            Invoke-CIPPStandardAuthenticatorCredentialRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ alert = $true; standardId = 'x' })
            $script:Posts.Count | Should -Be 0
            $script:Alerts.Count | Should -Be 1
        }

        It 'remediates once, refreshes the cache and reports compliant in the same run' {
            Set-TestTenant
            $Settings = [pscustomobject]@{ remediate = $true; alert = $true; report = $true }
            Invoke-CIPPStandardAuthenticatorCredentialRegistration -Tenant $script:Tenant -Settings $Settings
            $script:Posts.Count | Should -Be 1
            $script:CacheRefreshes | Should -Be 1
            $script:Alerts.Count | Should -Be 0
            $script:Compare[0].Current.ServicePrincipalPresent | Should -BeTrue
            $script:Compare[0].Current.AccountEnabled | Should -BeTrue
        }

        It 'a second remediation does not POST or refresh the cache' {
            Set-TestTenant -Exists $true
            Invoke-CIPPStandardAuthenticatorCredentialRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true })
            $script:Posts.Count | Should -Be 0
            $script:CacheRefreshes | Should -Be 0
            @($script:Logs | Where-Object { $_.Message -match 'already exists' }).Count | Should -Be 1
        }

        It 'leaves a disabled service principal alone and reports it' {
            Set-TestTenant -Exists $true -Enabled $false
            Invoke-CIPPStandardAuthenticatorCredentialRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; alert = $true; report = $true; standardId = 'x' })
            $script:Posts.Count | Should -Be 0
            $script:Alerts[0] | Should -Match 'disabled'
            $script:Compare[0].Current.ServicePrincipalPresent | Should -BeTrue
            $script:Compare[0].Current.AccountEnabled | Should -BeFalse
        }

        It 'does not claim absent or compliant when it could not read' {
            Set-TestTenant -ReadFails $true
            Invoke-CIPPStandardAuthenticatorCredentialRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; alert = $true; report = $true })
            $script:Posts.Count | Should -Be 0
            $script:Alerts.Count | Should -Be 0
            $script:Compare[0].Current.Error | Should -Match 'Could not read'
            @($script:Logs | Where-Object Sev -EQ 'Error').Count | Should -Be 1
        }

        It 'logs an error when the create fails, and still alerts' {
            Set-TestTenant -RefuseCreate @('Delegated', 'AsApp')
            Invoke-CIPPStandardAuthenticatorCredentialRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; alert = $true; standardId = 'x' })
            @($script:Logs | Where-Object Sev -EQ 'Error').Count | Should -Be 1
            $script:Alerts.Count | Should -Be 1
            $script:CacheRefreshes | Should -Be 0
        }

        It 'is declared in both copies of standards.json with the same text as its comment block' {
            $Backend = Join-Path $RepoRoot 'Config/standards.json'
            $Frontend = Join-Path (Split-Path -Parent $RepoRoot) 'frontend/src/data/standards.json'
            (Get-FileHash $Backend).Hash | Should -Be (Get-FileHash $Frontend).Hash
            $Entry = @(Get-Content $Backend -Raw | ConvertFrom-Json) | Where-Object { $_.name -eq 'standards.AuthenticatorCredentialRegistration' }
            $Entry | Should -Not -BeNullOrEmpty
            $Source = Get-Content (Find-SourceFile 'Invoke-CIPPStandardAuthenticatorCredentialRegistration.ps1') -Raw
            $Source | Should -Match ([regex]::Escape("(Label) $($Entry.label)"))
            $Source | Should -Match ([regex]::Escape("(Helptext) $($Entry.helpText)"))
            $Source | Should -Match ([regex]::Escape("(DocsDescription) $($Entry.docsDescription)"))
        }
    }
}
