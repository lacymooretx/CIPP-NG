function Invoke-CippTestAZ_ACR_02 {
    <#
    .SYNOPSIS
    Azure - Container registries disallow anonymous pull
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_ACR_02' -Name 'Container registries disallow anonymous pull' -Risk 'Medium' -Category 'Containers' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.containerregistry/registries') -FailStatus 'Failed' -Requirement 'anonymous pull disabled' -Check {
            param($R)
            if ($R.properties.anonymousPullEnabled -eq $true) { 'Anyone can pull images without signing in' }
        }
    }
}
