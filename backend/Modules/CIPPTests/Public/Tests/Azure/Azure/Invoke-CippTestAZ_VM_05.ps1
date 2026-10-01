function Invoke-CippTestAZ_VM_05 {
    <#
    .SYNOPSIS
    Azure - No unattached managed disks
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_VM_05' -Name 'No unattached managed disks' -Risk 'Low' -Category 'Compute' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.compute/disks') -FailStatus 'Investigate' -Requirement 'disk is attached to a VM' -Check {
            param($R)
            if ($R.properties.diskState -eq 'Unattached') { "Unattached, $($R.properties.diskSizeGB) GB" }
        }
    }
}
