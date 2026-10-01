function Invoke-CippTestAZ_AI_01 {
    <#
    .SYNOPSIS
    Azure - Azure AI services disable key-based authentication
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_AI_01' -Name 'Azure AI services disable key-based authentication' -Risk 'Low' -Category 'AI Services' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.cognitiveservices/accounts') -FailStatus 'Investigate' -Requirement 'local (API key) authentication disabled' -Check {
            param($R)
            if ($R.properties.disableLocalAuth -ne $true) { 'API keys accepted' }
        }
    }
}
