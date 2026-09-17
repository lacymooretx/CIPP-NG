# Reverse assignment lookup: "what policies land on this object".
#
# The behaviours that are silent when wrong, and so are asserted here:
#   - TRANSITIVE group membership, so a policy assigned to a parent group is found even though the
#     object is only a nested member. Matching on direct membership would quietly under-report.
#   - Virtual targets scoped to the right object type. All Users must not match a device, or every
#     device page shows policies that never land on it.
#   - EXCLUSION WINS. Intune resolves an exclusion over an include, so a policy that is both must
#     report as not effective - but must still be LISTED, because "assigned but excluded" is a
#     different problem from "not assigned" and is the more confusing of the two.
#   - A managedDevice id is not a directory object id; group membership lives on the Entra device,
#     so the Intune record must be translated first or no groups are ever found.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/MEM/Invoke-ListPolicyTargets.ps1'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext { [int]$StatusCode; [object]$Body }

    function Get-CIPPIntunePolicyListDefinitions {
        @([PSCustomObject]@{ Id = 'DeviceConfigurations'; GraphUri = '/deviceManagement/deviceConfigurations?$expand=assignments'; PolicyTypeName = 'Device Configuration' })
    }
    function New-GraphGetRequest {
        param($uri, $tenantid)
        switch -Regex ($uri) {
            'managedDevices/'       { return $script:ManagedDevice }
            'devices\?\$filter'     { return $script:EntraDevice }
            'devices/[^/]+/transitiveMemberOf' { return $script:ObjectGroups }
            'users/[^/]+/transitiveMemberOf'   { return $script:ObjectGroups }
            'groups/[^/]+/transitiveMemberOf'  { return $script:ObjectGroups }
            'users/'                { return [pscustomobject]@{ id = 'u1'; displayName = 'Amber'; userPrincipalName = 'amber@contoso.com' } }
            'groups/'               { return [pscustomobject]@{ id = 'g-self'; displayName = 'Sales' } }
            'devices/'              { return [pscustomobject]@{ displayName = 'LAPTOP-1' } }
        }
        return @()
    }
    function New-GraphBulkRequest {
        param($Requests, $tenantid)
        @(
            [pscustomobject]@{ id = 'Groups'; status = 200; body = [pscustomobject]@{ value = $script:AllGroups } }
            [pscustomobject]@{ id = 'DeviceConfigurations'; status = 200; body = [pscustomobject]@{ value = $script:Policies } }
        )
    }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs += $message }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

    . $FunctionPath

    function New-Target { param($Type, $GroupId) [pscustomobject]@{ '@odata.type' = $Type; groupId = $GroupId } }
    function New-Policy {
        param($Name = 'Policy A', $Id = 'p1', $Targets = @())
        [pscustomobject]@{ id = $Id; displayName = $Name; assignments = @($Targets | ForEach-Object { [pscustomobject]@{ target = $_ } }) }
    }
    function Invoke-Lookup {
        param($DeviceId, $UserId, $GroupId)
        $q = @{ TenantFilter = 'contoso.com' }
        if ($DeviceId) { $q.DeviceId = $DeviceId }
        if ($UserId) { $q.UserId = $UserId }
        if ($GroupId) { $q.GroupId = $GroupId }
        Invoke-ListPolicyTargets -Request ([pscustomobject]@{
                Params = @{ CIPPEndpoint = 'ListPolicyTargets' }; Headers = @{}
                Query = [pscustomobject]$q; Body = [pscustomobject]@{}
            })
    }
}

Describe 'Invoke-ListPolicyTargets' {
    BeforeEach {
        $script:Logs = @()
        $script:ManagedDevice = [pscustomobject]@{ id = 'md1'; deviceName = 'LAPTOP-1'; azureADDeviceId = 'aad-1' }
        $script:EntraDevice = @([pscustomobject]@{ id = 'dir-1'; displayName = 'LAPTOP-1' })
        $script:ObjectGroups = @([pscustomobject]@{ id = 'g-nested' }, [pscustomobject]@{ id = 'g-parent' })
        $script:AllGroups = @(
            [pscustomobject]@{ id = 'g-nested'; displayName = 'Nested Group' }
            [pscustomobject]@{ id = 'g-parent'; displayName = 'Parent Group' }
            [pscustomobject]@{ id = 'g-other'; displayName = 'Other Group' }
        )
        $script:Policies = @()
    }

    Context 'validation' {
        It 'requires a tenant' {
            $r = Invoke-ListPolicyTargets -Request ([pscustomobject]@{ Params = @{}; Headers = @{}; Query = [pscustomobject]@{}; Body = [pscustomobject]@{} })
            $r.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }
        It 'requires exactly one target object' {
            (Invoke-Lookup).StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
            (Invoke-Lookup -DeviceId 'd' -UserId 'u').StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }
    }

    It 'finds a policy assigned to a PARENT group the object only nests into' {
        $script:Policies = @(New-Policy -Targets @(New-Target '#microsoft.graph.groupAssignmentTarget' 'g-parent'))

        $r = Invoke-Lookup -DeviceId 'md1'

        $r.Body.Results | Should -HaveCount 1
        $r.Body.Results[0].MatchedVia | Should -Be 'Group: Parent Group'
        $r.Body.Results[0].Effective | Should -BeTrue
    }

    It 'ignores a policy assigned to a group the object is not in' {
        $script:Policies = @(New-Policy -Targets @(New-Target '#microsoft.graph.groupAssignmentTarget' 'g-other'))

        (Invoke-Lookup -DeviceId 'md1').Body.Results | Should -BeNullOrEmpty
    }

    Context 'exclusion wins' {
        It 'lists a policy that is both included and excluded, but marks it not effective' {
            $script:Policies = @(New-Policy -Targets @(
                    (New-Target '#microsoft.graph.groupAssignmentTarget' 'g-parent')
                    (New-Target '#microsoft.graph.exclusionGroupAssignmentTarget' 'g-nested')
                ))

            $Row = (Invoke-Lookup -DeviceId 'md1').Body.Results[0]

            # Dropping it would hide the more confusing of the two states.
            $Row | Should -Not -BeNullOrEmpty
            $Row.Effective | Should -BeFalse
            $Row.Status | Should -Be 'Excluded (assigned but cancelled)'
            $Row.MatchedVia | Should -Be 'Group: Parent Group'
            $Row.ExcludedVia | Should -Be 'Excluded group: Nested Group'
        }
    }

    Context 'virtual targets are scoped to the right object type' {
        It 'applies All Devices to a device but not All Users' {
            $script:Policies = @(
                (New-Policy -Name 'AllDev' -Id 'p1' -Targets @(New-Target '#microsoft.graph.allDevicesAssignmentTarget'))
                (New-Policy -Name 'AllUsr' -Id 'p2' -Targets @(New-Target '#microsoft.graph.allUsersAssignmentTarget'))
            )

            $Names = @((Invoke-Lookup -DeviceId 'md1').Body.Results.PolicyName)

            $Names | Should -Contain 'AllDev'
            $Names | Should -Not -Contain 'AllUsr'
        }

        It 'applies All Users and All Licensed Users to a user but not All Devices' {
            $script:Policies = @(
                (New-Policy -Name 'AllDev' -Id 'p1' -Targets @(New-Target '#microsoft.graph.allDevicesAssignmentTarget'))
                (New-Policy -Name 'AllUsr' -Id 'p2' -Targets @(New-Target '#microsoft.graph.allUsersAssignmentTarget'))
                (New-Policy -Name 'AllLic' -Id 'p3' -Targets @(New-Target '#microsoft.graph.allLicensedUsersAssignmentTarget'))
            )

            $Names = @((Invoke-Lookup -UserId 'amber@contoso.com').Body.Results.PolicyName)

            $Names | Should -Contain 'AllUsr'
            $Names | Should -Contain 'AllLic'
            $Names | Should -Not -Contain 'AllDev'
        }
    }

    It 'translates an Intune managedDevice id to the Entra device before resolving groups' {
        # Matching on the managedDevice id would find no groups at all - silently empty, not an error.
        $script:Policies = @(New-Policy -Targets @(New-Target '#microsoft.graph.groupAssignmentTarget' 'g-nested'))

        $r = Invoke-Lookup -DeviceId 'md1'

        $r.Body.Metadata.ObjectName | Should -Be 'LAPTOP-1'
        $r.Body.Metadata.GroupCount | Should -Be 2
        $r.Body.Results | Should -HaveCount 1
    }

    It 'reports a group lookup against the group itself' {
        $script:ObjectGroups = @()
        $script:Policies = @(New-Policy -Targets @(New-Target '#microsoft.graph.groupAssignmentTarget' 'g-self'))

        $r = Invoke-Lookup -GroupId 'g-self'

        $r.Body.Metadata.ObjectType | Should -Be 'Group'
        $r.Body.Results | Should -HaveCount 1
    }

    It 'summarises counts and sorts effective policies first' {
        $script:Policies = @(
            (New-Policy -Name 'Cancelled' -Id 'p1' -Targets @(
                (New-Target '#microsoft.graph.groupAssignmentTarget' 'g-parent')
                (New-Target '#microsoft.graph.exclusionGroupAssignmentTarget' 'g-parent')))
            (New-Policy -Name 'Applies' -Id 'p2' -Targets @(New-Target '#microsoft.graph.groupAssignmentTarget' 'g-nested'))
        )

        $r = Invoke-Lookup -DeviceId 'md1'

        $r.Body.Metadata.PolicyCount | Should -Be 2
        $r.Body.Metadata.EffectiveCount | Should -Be 1
        $r.Body.Results[0].PolicyName | Should -Be 'Applies'
    }

    It 'returns an error status instead of throwing when Graph fails' {
        Mock New-GraphBulkRequest { throw 'graph exploded' }

        $r = Invoke-Lookup -DeviceId 'md1'

        $r.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        ($script:Logs -join ' ') | Should -Match 'Policy target lookup failed'
    }
}
