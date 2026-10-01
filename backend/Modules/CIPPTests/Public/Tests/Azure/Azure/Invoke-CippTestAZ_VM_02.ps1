function Invoke-CippTestAZ_VM_02 {
    <#
    .SYNOPSIS
    Azure - Virtual machines use Trusted Launch with Secure Boot
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_VM_02' -Name 'Virtual machines use Trusted Launch with Secure Boot' -Risk 'Medium' -Category 'Compute' -UserImpact 'Medium' -ImplementationEffort 'High' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.compute/virtualmachines') -FailStatus 'Investigate' -Requirement 'security type TrustedLaunch or ConfidentialVM with Secure Boot on' -Check {
            param($R)
            $Sec = $R.properties.securityProfile
            if ($Sec.securityType -notin @('TrustedLaunch', 'ConfidentialVM')) { 'Standard security type (no Secure Boot / vTPM)' }
            elseif ($Sec.uefiSettings.secureBootEnabled -ne $true) { 'Trusted Launch without Secure Boot' }
        }
    }
}
