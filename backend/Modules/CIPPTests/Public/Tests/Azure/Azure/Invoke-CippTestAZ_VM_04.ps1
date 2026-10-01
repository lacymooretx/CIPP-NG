function Invoke-CippTestAZ_VM_04 {
    <#
    .SYNOPSIS
    Azure - Managed disks are not exportable from any network
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_VM_04' -Name 'Managed disks are not exportable from any network' -Risk 'Low' -Category 'Compute' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.compute/disks') -FailStatus 'Failed' -Requirement 'disk network access policy is not AllowAll' -Check {
            param($R)
            if ($R.properties.networkAccessPolicy -eq 'AllowAll' -and $R.properties.publicNetworkAccess -ne 'Disabled') { 'Disk can be exported/imported (SAS) from any network' }
        }
    }
}
