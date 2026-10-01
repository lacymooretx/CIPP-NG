function Invoke-CippTestAZ_VM_03 {
    <#
    .SYNOPSIS
    Azure - Virtual machines are protected by Azure Backup
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_VM_03' -Name 'Virtual machines are protected by Azure Backup' -Risk 'High' -Category 'Compute' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.compute/virtualmachines') -FailStatus 'Investigate' -Requirement 'an Azure Backup protected item exists for the VM' -Check {
            param($R)
            $Item = $Ctx.BackupItems | Where-Object { $_.sourceResourceId -eq ([string]$R.id).ToLower() } | Select-Object -First 1
            if (-not $Item) { 'Not protected by Azure Backup' }
            elseif ($Item.protectionState -eq 'ProtectionStopped') { 'Azure Backup protection stopped' }
        }
    }
}
