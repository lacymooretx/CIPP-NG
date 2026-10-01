function Invoke-CippTestAZ_ACR_01 {
    <#
    .SYNOPSIS
    Azure - Container registries have the admin user disabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_ACR_01' -Name 'Container registries have the admin user disabled' -Risk 'Medium' -Category 'Containers' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.containerregistry/registries') -FailStatus 'Failed' -Requirement 'admin user disabled' -Check {
            param($R)
            if ($R.properties.adminUserEnabled -eq $true) { 'Admin user (shared username/password) enabled' }
        }
    }
}
