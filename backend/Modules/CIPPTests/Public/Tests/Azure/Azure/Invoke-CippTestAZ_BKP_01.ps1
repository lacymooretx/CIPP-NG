function Invoke-CippTestAZ_BKP_01 {
    <#
    .SYNOPSIS
    Azure - Recovery Services vaults have soft delete on
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_BKP_01' -Name 'Recovery Services vaults have soft delete on' -Risk 'Medium' -Category 'Backup & Recovery' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.recoveryservices/vaults') -FailStatus 'Failed' -Requirement 'soft delete enabled (or always-on)' -Check {
            param($R)
            if ($R.properties.securitySettings.softDeleteSettings.softDeleteState -notin @('Enabled', 'AlwaysON')) { "Soft delete: $($R.properties.securitySettings.softDeleteSettings.softDeleteState ?? 'unknown')" }
        }
    }
}
