# Pester tests for the GDAP health monitor (Aspendora fork, Vikunja CIPP-2):
# the pure finding rules, and the alert/state behaviour of Invoke-CIPPGDAPHealthCheck.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Dir = Join-Path $RepoRoot 'Modules/CIPPCore/Public/GDAP'
    . (Join-Path $Dir 'Get-CIPPGDAPHealthFindings.ps1')
    . (Join-Path $Dir 'Invoke-CIPPGDAPHealthCheck.ps1')

    $script:Now = [datetime]::new(2026, 10, 31, 12, 0, 0, [DateTimeKind]::Utc)
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'
    function New-Rel {
        param($Id, $Customer, $Status = 'active', $EndDays = 200, $AutoExtend = 'P180D', [string[]]$Roles = @('729827e3-9c14-49f7-bb1b-9608f156bbb8'))
        [pscustomobject]@{
            id                 = $Id
            displayName        = "rel-$Id"
            status             = $Status
            endDateTime        = $script:Now.AddDays($EndDays).ToString('o')
            autoExtendDuration = $AutoExtend
            customer           = [pscustomobject]@{ tenantId = $Customer; displayName = "Cust $Customer" }
            accessDetails      = [pscustomobject]@{ unifiedRoles = @($Roles | ForEach-Object { [pscustomobject]@{ roleDefinitionId = $_ } }) }
        }
    }
    function New-Tenant { param($Id) [pscustomobject]@{ customerId = $Id; defaultDomainName = "$Id.com"; displayName = "Tenant $Id"; delegatedPrivilegeStatus = 'granularDelegatedAdminPrivileges' } }
    function Find { param($Params) Get-CIPPGDAPHealthFindings -Now $script:Now -PartnerTenantId 'partner' @Params }
}

Describe 'Get-CIPPGDAPHealthFindings' {
    It 'reports nothing for a healthy auto-extending relationship' {
        $F = Find @{ Relationships = @(New-Rel 'r1' 'c1'); Tenants = @(New-Tenant 'c1') }
        $F | Should -BeNullOrEmpty
    }

    It 'buckets a non-extending relationship into the right threshold with a stable key' {
        $F = Find @{ Relationships = @(New-Rel 'r1' 'c1' -EndDays 12 -AutoExtend 'PT0S'); Tenants = @(New-Tenant 'c1') }
        $F.Count | Should -Be 1
        $F[0].Key | Should -Be 'Expiring|r1|14'
        $F[0].AutoExtendEligible | Should -BeTrue
        $F[0].Severity | Should -Be 'Warning'
    }

    It 'is an Error at 7 days when it is the only relationship for a managed tenant' {
        $F = Find @{ Relationships = @(New-Rel 'r1' 'c1' -EndDays 5 -AutoExtend 'PT0S'); Tenants = @(New-Tenant 'c1') }
        $F[0].Key | Should -Be 'Expiring|r1|7'
        $F[0].Severity | Should -Be 'Error'
    }

    It 'stays a Warning when another auto-extending relationship covers the customer' {
        $F = Find @{ Relationships = @((New-Rel 'r1' 'c1' -EndDays 5 -AutoExtend 'PT0S'), (New-Rel 'r2' 'c1')); Tenants = @(New-Tenant 'c1') }
        $F.Count | Should -Be 1
        $F[0].Severity | Should -Be 'Warning'
        $F[0].Covered | Should -BeTrue
    }

    It 'treats a Global Admin relationship as non-extending and not auto-extend eligible' {
        $F = Find @{ Relationships = @(New-Rel 'r1' 'c1' -EndDays 25 -Roles @($script:GA)); Tenants = @(New-Tenant 'c1') }
        $F[0].Key | Should -Be 'Expiring|r1|30'
        $F[0].AutoExtendEligible | Should -BeFalse
        $F[0].Message | Should -Match 'Global Administrator'
    }

    It 'flags auto-extend that Microsoft has not applied, after the grace day' {
        $F = Find @{ Relationships = @(New-Rel 'r1' 'c1' -EndDays -3); Tenants = @(New-Tenant 'c1') }
        $F[0].Key | Should -Be 'AutoExtendOverdue|r1'
        $F[0].Severity | Should -Be 'Error'
        $F[0].Realert | Should -BeTrue
        (Find @{ Relationships = @(New-Rel 'r1' 'c1' -EndDays 0); Tenants = @(New-Tenant 'c1') }) | Should -BeNullOrEmpty
    }

    It 'is only a Warning for a customer not managed in CIPP' {
        $F = Find @{ Relationships = @(New-Rel 'r1' 'x9' -EndDays -3); Tenants = @() }
        $F[0].Severity | Should -Be 'Warning'
        $F[0].Message | Should -Match 'not managed in CIPP'
    }

    It 'reports a managed tenant with no active relationship' {
        $F = Find @{ Relationships = @(New-Rel 'r1' 'c1' -Status 'expired'); Tenants = @(New-Tenant 'c1') }
        $F.Key | Should -Contain 'NoActiveRelationship|c1'
    }

    It 'ignores direct tenants and the partner tenant for coverage' {
        $Direct = [pscustomobject]@{ customerId = 'd1'; displayName = 'Direct'; delegatedPrivilegeStatus = 'directTenant' }
        $F = Find @{ Relationships = @(); Tenants = @($Direct, (New-Tenant 'partner')) }
        $F | Should -BeNullOrEmpty
    }

    It 'reports pending relationships as Info only' {
        $F = Find @{ Relationships = @((New-Rel 'p1' 'c1' -Status 'approvalPending'), (New-Rel 'r1' 'c1')); Tenants = @(New-Tenant 'c1') }
        $F.Count | Should -Be 1
        $F[0].Severity | Should -Be 'Info'
    }

    It 'reports a relationship that was active last run and is not now' {
        $Prev = @{ ActiveRelationshipIds = @('r1', 'r2'); AssignmentIds = @{} }
        $F = Find @{ Relationships = @((New-Rel 'r1' 'c1' -Status 'terminated'), (New-Rel 'r2' 'c1')); Tenants = @(New-Tenant 'c1'); Previous = $Prev }
        $F.Key | Should -Be @('RelationshipLost|r1')
        $F[0].Severity | Should -Be 'Error'
    }

    It 'reports a removed access assignment, but not when assignments were not read' {
        $Prev = @{ ActiveRelationshipIds = @('r1'); AssignmentIds = @{ r1 = @('a1', 'a2') } }
        $F = Find @{ Relationships = @(New-Rel 'r1' 'c1'); Tenants = @(New-Tenant 'c1'); Previous = $Prev; AccessAssignments = @{ r1 = @([pscustomobject]@{ id = 'a1' }) } }
        $F.Key | Should -Be @('AssignmentRemoved|r1|a2')
        (Find @{ Relationships = @(New-Rel 'r1' 'c1'); Tenants = @(New-Tenant 'c1'); Previous = $Prev; AccessAssignments = @{} }) | Should -BeNullOrEmpty
    }

    It 'reports tenant probe failures and SAM problems' {
        $Sam = @{ Ready = $false; Message = 'AADSTS700082 refresh token expired'; CredentialType = 'Secret'; CredentialExpires = $script:Now.AddDays(10).ToString('o') }
        $F = Find @{ Relationships = @(New-Rel 'r1' 'c1'); Tenants = @(New-Tenant 'c1'); TenantProbeErrors = @{ c1 = 'AADSTS50020' }; SamStatus = $Sam }
        $F.Key | Should -Contain 'TenantAccessFailing|c1'
        $F.Key | Should -Contain 'SamAuthFailing'
        $F.Key | Should -Contain 'SamCredentialExpiring|Secret'
        @($F | Where-Object Severity -NE 'Error') | Should -BeNullOrEmpty
    }

    It 'reports nothing at all for an ignored customer, managed or not' {
        $Prev = @{ ActiveRelationshipIds = @('r1', 'r2'); AssignmentIds = @{} }
        $Rels = @((New-Rel 'r1' 'c1' -EndDays -3), (New-Rel 'r2' 'x9' -Status 'terminated'), (New-Rel 'p1' 'x9' -Status 'created'))
        $F = Find @{ Relationships = $Rels; Tenants = @(New-Tenant 'c1'); Previous = $Prev; IgnoredCustomers = @('c1', 'x9') }
        $F | Should -BeNullOrEmpty
        (Find @{ Relationships = @(); Tenants = @(New-Tenant 'c1'); IgnoredCustomers = @('c1') }) | Should -BeNullOrEmpty
    }

    It 'does not flag a SAM credential with more than 14 days left' {
        $Sam = @{ Ready = $true; CredentialType = 'Secret'; CredentialExpires = $script:Now.AddDays(40).ToString('o') }
        (Find @{ Relationships = @(New-Rel 'r1' 'c1'); Tenants = @(New-Tenant 'c1'); SamStatus = $Sam }) | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-CIPPGDAPHealthCheck alerting and state' {
    BeforeEach {
        $script:Store = @{}
        $script:Sent = [System.Collections.Generic.List[object]]::new()
        $script:Rels = @(New-Rel 'r1' 'c1' -EndDays 12 -AutoExtend 'PT0S')
        $script:RelFail = $false
        $env:TenantID = 'partner'
        $env:CertificateAuthMode = $null

        function Get-CIPPTable { param($tablename) @{ TableName = $tablename } }
        function Get-CIPPAzDataTableEntity {
            param($TableName, $Filter)
            if ($Filter -match "PartitionKey eq '(\w+)' and RowKey eq '(\w+)'") { return $script:Store["$($Matches[1])|$($Matches[2])"] }
            if ($Filter -match "PartitionKey eq '(\w+)'") { $P = $Matches[1]; return @($script:Store.Keys | Where-Object { $_ -like "$P|*" } | ForEach-Object { $script:Store[$_] }) }
        }
        function Add-CIPPAzDataTableEntity { param($TableName, $Entity, [switch]$Force) $script:Store["$($Entity.PartitionKey)|$($Entity.RowKey)"] = [pscustomobject]$Entity }
        function Remove-AzDataTableEntity { param($TableName, $Entity, [switch]$Force) foreach ($E in $Entity) { $script:Store.Remove("$($E.PartitionKey)|$($E.RowKey)") } }
        function New-GraphGetRequest { param($uri, $tenantid, $NoAuthCheck) if ($uri -match 'delegatedAdminRelationships') { if ($script:RelFail) { throw 'boom' }; return $script:Rels }; return @{ id = 'x' } }
        function New-GraphBulkRequest { param($tenantid, $NoAuthCheck, $Requests) foreach ($R in $Requests) { @{ id = $R.id; status = 200; body = @{ value = @(@{ id = 'a1'; status = 'active' }) } } } }
        function Get-Tenants { param([switch]$IncludeAll) @(New-Tenant 'c1'); if ($IncludeAll) { [pscustomobject]@{ customerId = 'partner'; defaultDomainName = 'partner.com'; delegatedPrivilegeStatus = 'directTenant' } } }
        function Get-CIPPAuthentication { }
        function Test-CIPPSAMSecret { param([switch]$IncludeRefreshGrant) @{ ready = $true; reason = 'ready' } }
        function Get-CIPPSAMCredentials { [pscustomobject]@{ OwnSecretKeyId = 'k1'; Credentials = @([pscustomobject]@{ keyId = 'k1'; type = 'Secret'; endDateTime = $script:Now.AddDays(300).ToString('o') }) } }
        function Get-CippException { param($Exception) @{ NormalizedError = "$Exception" } }
        function Send-CIPPAlert { param($Type, $Title, $HTMLContent, $JSONContent, $TenantFilter, $APIName, $PSAConsolidationKey) $script:Sent.Add([pscustomobject]@{ Type = $Type; Title = $Title; Tenant = $TenantFilter }) }
        function Write-LogMessage { param($API, $tenant, $message, $Sev, $LogData) }
    }

    It 'alerts once per finding across all three channels, then stays quiet' {
        $R = Invoke-CIPPGDAPHealthCheck
        $R.Alerted | Should -Be @('Expiring|r1|14')
        $script:Sent.Type | Should -Be @('email', 'psa', 'webhook')
        # The PSA lookup matches on default domain, so the partner's domain must be sent, not its id.
        @($script:Sent.Tenant | Select-Object -Unique) | Should -Be @('partner.com')
        $script:Sent.Clear()
        $null = Invoke-CIPPGDAPHealthCheck
        $script:Sent | Should -BeNullOrEmpty
    }

    It 'alerts again when the relationship crosses the next threshold' {
        $null = Invoke-CIPPGDAPHealthCheck
        $script:Sent.Clear()
        $script:Rels = @(New-Rel 'r1' 'c1' -EndDays 6 -AutoExtend 'PT0S')
        $R = Invoke-CIPPGDAPHealthCheck
        $R.Alerted | Should -Be @('Expiring|r1|7')
        $script:Store.Keys | Should -Not -Contain 'Finding|Expiring|r1|14'
    }

    It 'reports a lost relationship using the stored snapshot' {
        $script:Rels = @((New-Rel 'r1' 'c1'), (New-Rel 'r2' 'c1'))
        $null = Invoke-CIPPGDAPHealthCheck
        $script:Rels = @((New-Rel 'r1' 'c1' -Status 'expired'), (New-Rel 'r2' 'c1'))
        $R = Invoke-CIPPGDAPHealthCheck
        $R.Alerted | Should -Contain 'RelationshipLost|r1'
    }

    It 'keeps state and the snapshot when relationships cannot be listed, and says so' {
        $null = Invoke-CIPPGDAPHealthCheck
        $Snapshot = $script:Store['Snapshot|Latest'].Data
        $script:Sent.Clear()
        $script:RelFail = $true
        $R = Invoke-CIPPGDAPHealthCheck
        $script:Store['Snapshot|Latest'].Data | Should -Be $Snapshot
        $script:Store.Keys | Should -Contain 'Finding|Expiring|r1|14'
        $R.Alerted | Should -Contain 'SamAuthFailing'
        $R.Findings.Key | Should -Not -Contain 'NoActiveRelationship|c1'
    }

    It 'Resend re-sends findings that were already alerted' {
        $null = Invoke-CIPPGDAPHealthCheck
        $script:Sent.Clear()
        $R = Invoke-CIPPGDAPHealthCheck -Resend
        $R.Alerted | Should -Be @('Expiring|r1|14')
        $script:Sent[0].Title | Should -Match 'open issue'
    }

    It 'clears an ignored customer''s open finding and lists it in the report' {
        $null = Invoke-CIPPGDAPHealthCheck
        $script:Store['Ignore|c1'] = [pscustomobject]@{ PartitionKey = 'Ignore'; RowKey = 'c1'; Name = 'Cust c1'; Reason = 'left' }
        $R = Invoke-CIPPGDAPHealthCheck
        $R.Findings | Should -BeNullOrEmpty
        $R.Ignored.TenantId | Should -Be @('c1')
        $script:Store.Keys | Should -Not -Contain 'Finding|Expiring|r1|14'
    }

    It 'SkipAlerts sends nothing and writes nothing' {
        $R = Invoke-CIPPGDAPHealthCheck -SkipAlerts
        $R.Findings.Count | Should -Be 1
        $script:Sent | Should -BeNullOrEmpty
        $script:Store.Count | Should -Be 0
    }
}
