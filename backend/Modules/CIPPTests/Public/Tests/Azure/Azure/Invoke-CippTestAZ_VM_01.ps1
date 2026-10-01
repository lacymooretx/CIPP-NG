function Invoke-CippTestAZ_VM_01 {
    <#
    .SYNOPSIS
    Azure - Virtual machines use managed disks
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_VM_01' -Name 'Virtual machines use managed disks' -Risk 'Medium' -Category 'Compute' -UserImpact 'Medium' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.compute/virtualmachines') -FailStatus 'Failed' -Requirement 'OS disk is a managed disk' -Check {
            param($R)
            if (-not $R.properties.storageProfile.osDisk.managedDisk) { 'Unmanaged (page-blob VHD) OS disk' }
        }
    }
}
