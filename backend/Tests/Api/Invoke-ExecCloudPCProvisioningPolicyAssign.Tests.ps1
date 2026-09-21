# Graph's POST provisioningPolicies/{id}/assign is REPLACE-mode: the array you send becomes the
# entire assignment set, and anything omitted is unassigned. Sending one group to a policy that
# already serves five detaches the other four, and detaching a provisioning policy from the group
# whose users own Cloud PCs is not a paperwork change.
#
# These tests pin the protections: Add is the default and unions with what is already there,
# Replace is opt-in by name, and Replace-with-nothing needs a second explicit flag because an empty
# GroupIds array is indistinguishable from a caller whose array failed to serialize.

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
        return [pscustomobject]@{ assignments = $script:ExistingAssignments }
    }
    function New-GraphPOSTRequest {
        param($uri, $tenantid, $body, $AsApp, $ErrorAction)
        $script:PostedUri = $uri
        $script:PostedBody = $body
        $script:PostAsApp = $AsApp
        return $null
    }

    # The entrypoint calls ConvertTo-CIPPBoolean; the compiled module has it, a dot-sourced test does not.
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/CloudPC/Invoke-ExecCloudPCProvisioningPolicyAssign.ps1')

    function New-AssignRequest {
        param($GroupIds, $AssignmentMode, $AllowRemoveAll)
        $BodyObj = @{ tenantFilter = 'contoso.com'; PolicyId = 'policy-1' }
        if ($PSBoundParameters.ContainsKey('GroupIds')) { $BodyObj.GroupIds = $GroupIds }
        if ($AssignmentMode) { $BodyObj.AssignmentMode = $AssignmentMode }
        if ($PSBoundParameters.ContainsKey('AllowRemoveAll')) { $BodyObj.AllowRemoveAll = $AllowRemoveAll }
        [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ExecCloudPCProvisioningPolicyAssign' }
            Headers = @{}
            Query   = [pscustomobject]@{}
            Body    = [pscustomobject]$BodyObj
        }
    }

    function Get-PostedGroupIds {
        # Filter nulls explicitly: on an empty assignments array, .target.groupId yields $null and
        # @($null) is a one-element array, which would read as "one group was posted" when none was.
        if (-not $script:PostedBody) { return @() }
        @(($script:PostedBody | ConvertFrom-Json).assignments.target.groupId | Where-Object { $_ })
    }

    function Set-ExistingGroups {
        param([string[]]$GroupIds)
        $script:ExistingAssignments = @(foreach ($g in $GroupIds) {
                [pscustomobject]@{ target = [pscustomobject]@{ groupId = $g } }
            })
    }
}

Describe 'ExecCloudPCProvisioningPolicyAssign' {
    BeforeEach {
        $script:Logs = @()
        $script:PostedBody = $null
        $script:PostedUri = $null
        $script:ExistingAssignments = @()
    }

    It 'defaults to Add and keeps the groups that were already assigned' {
        Set-ExistingGroups 'group-a', 'group-b'
        $Response = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @('group-c'))

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $Posted = Get-PostedGroupIds
        $Posted | Should -Contain 'group-a'
        $Posted | Should -Contain 'group-b'
        $Posted | Should -Contain 'group-c'
        $Posted.Count | Should -Be 3
    }

    It 'does not duplicate a group that is already assigned' {
        Set-ExistingGroups 'group-a'
        $null = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @('group-a'))
        @(Get-PostedGroupIds).Count | Should -Be 1
    }

    It 'discards existing assignments only when Replace is asked for by name' {
        Set-ExistingGroups 'group-a', 'group-b'
        $null = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @('group-c') -AssignmentMode 'Replace')

        $Posted = Get-PostedGroupIds
        $Posted | Should -Be @('group-c')
        ($script:Logs | Where-Object { $_.Sev -eq 'Warn' -and $_.Message -match 'removing 2 existing assignment' }) | Should -Not -BeNullOrEmpty
    }

    It 'refuses Replace with no groups - that would unassign the policy from everything' {
        Set-ExistingGroups 'group-a', 'group-b'
        $Response = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @() -AssignmentMode 'Replace')

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'AllowRemoveAll'
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'allows clearing every assignment when AllowRemoveAll is explicit' {
        Set-ExistingGroups 'group-a'
        $Response = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @() -AssignmentMode 'Replace' -AllowRemoveAll $true)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        @(Get-PostedGroupIds).Count | Should -Be 0
    }

    It 'rejects an unknown AssignmentMode rather than guessing' {
        $Response = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @('g') -AssignmentMode 'Overwrite')
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'Invalid AssignmentMode'
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'requires GroupIds in Add mode' {
        $Response = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @())
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'sends the Cloud PC group assignment target type Graph expects' {
        Set-ExistingGroups @()
        $null = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @('group-a'))
        $script:PostedBody | Should -Match 'cloudPcManagementGroupAssignmentTarget'
        $script:PostedUri | Should -Match '/provisioningPolicies/policy-1/assign$'
    }

    It 'reads and writes app-only' {
        Set-ExistingGroups @()
        $null = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @('group-a'))
        $script:GetAsApp | Should -BeTrue
        $script:PostAsApp | Should -BeTrue
    }

    It 'reports what changed, including the previous group count' {
        Set-ExistingGroups 'group-a', 'group-b'
        $Response = Invoke-ExecCloudPCProvisioningPolicyAssign -Request (New-AssignRequest -GroupIds @('group-c'))
        $Response.Body.PreviousGroups.Count | Should -Be 2
        $Response.Body.AssignedGroups.Count | Should -Be 3
        $Response.Body.Mode | Should -Be 'Add'
    }
}
