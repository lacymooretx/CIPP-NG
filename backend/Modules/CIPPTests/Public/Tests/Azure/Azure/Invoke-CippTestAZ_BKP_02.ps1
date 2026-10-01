function Invoke-CippTestAZ_BKP_02 {
    <#
    .SYNOPSIS
    Azure - Recovery Services vaults are immutable
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_BKP_02' -Name 'Recovery Services vaults are immutable' -Risk 'Low' -Category 'Backup & Recovery' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.recoveryservices/vaults') -FailStatus 'Investigate' -Requirement 'immutable vault enabled' -Check {
            param($R)
            if ($R.properties.securitySettings.immutabilitySettings.state -notin @('Locked', 'Unlocked')) { 'Immutability off' }
        }
    }
}
