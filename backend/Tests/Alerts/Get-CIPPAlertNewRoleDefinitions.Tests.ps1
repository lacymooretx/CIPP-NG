# Aspendora fork (Vikunja CIPP-15): new directory role definitions. First run seeds silently; afterwards a new
# custom role notifies once, new built-in roles only when asked for. Runs on the real AlertLifecycle.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertNewRoleDefinitions.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Alerts/Get-CIPPAlertFailureSeverity.ps1')

    function New-GraphGetRequest {
        [CmdletBinding()] param($uri, $tenantid)
        if ($script:GraphThrows) { throw 'Forbidden' }
        $script:Defs
    }
    function Def { param($Id, $Name, $BuiltIn = $true) [pscustomobject]@{ id = $Id; displayName = $Name; description = "$Name role"; isBuiltIn = $BuiltIn; isEnabled = $true; isPrivileged = $false; rolePermissions = @(@{ allowedResourceActions = @('microsoft.directory/users/password/update', 'microsoft.directory/users/basic/update') }) } }
    function Run { param($InputValue) @(Get-CIPPAlertNewRoleDefinitions -TenantFilter 'contoso.com' -InputValue $InputValue | Where-Object { $_ }) }
}

Describe 'Get-CIPPAlertNewRoleDefinitions' {
    BeforeEach {
        Reset-AlertStore
        $script:GraphThrows = $false
        $script:Defs = @((Def 'ga' 'Global Administrator'), (Def 'ex' 'Exchange Administrator'))
    }

    It 'seeds silently on the first run' {
        Run | Should -BeNullOrEmpty
        @($script:Store['KnownRoleDefinitions'].Values).Count | Should -Be 2
        $script:Store['AlertLifecycle'] | Should -BeNullOrEmpty
    }

    It 'raises a new custom role once as a Warning' {
        $null = Run
        $script:Defs += Def 'c1' 'Helpdesk Lite' $false
        $Out = Run
        $Out.Id | Should -Be @('NewRoleDefinition|c1')
        $Out[0].Severity | Should -Be 'Warning'
        $Out[0].Message | Should -Match 'users/password/update'
        Run | Should -BeNullOrEmpty
    }

    It 'records new built-in roles silently unless RoleDefinitionsIncludeBuiltIn is on' {
        $null = Run
        $script:Defs += Def 'b1' 'Agent ID Administrator'
        Run | Should -BeNullOrEmpty
        $script:Store['KnownRoleDefinitions'].Keys | Should -Contain 'contoso.com|b1'

        $script:Defs += Def 'b2' 'Another New Role'
        $Out = Run -InputValue @{ RoleDefinitionsIncludeBuiltIn = 'true' }
        $Out.Id | Should -Be @('NewRoleDefinition|b2')
        $Out[0].Severity | Should -Be 'Info'
    }

    It 'treats a "false" string input as off' {
        $null = Run
        $script:Defs += Def 'b3' 'Yet Another Role'
        Run -InputValue @{ RoleDefinitionsIncludeBuiltIn = 'false' } | Should -BeNullOrEmpty
    }

    It 'does not seed or alert when Graph fails' {
        $script:GraphThrows = $true
        Run | Should -BeNullOrEmpty
        $script:Store['KnownRoleDefinitions'] | Should -BeNullOrEmpty
        $script:Logs.Message | Should -Match 'check failed'
    }
}
