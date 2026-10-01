function Invoke-CippTestAZ_STG_08 {
    <#
    .SYNOPSIS
    Azure - Container soft delete is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_STG_08' -Name 'Container soft delete is enabled' -Risk 'Low' -Category 'Storage' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.storage/storageaccounts') -FailStatus 'Failed' -Requirement 'container soft delete enabled' -Check {
            param($R)
            if ($R.kind -eq 'FileStorage') { return '#skip:file-only account' }
            $C = $Ctx.Config[([string]$R.id).ToLower()]
            if (-not $C -or $C.errors.blobService) { return '#skip:blob service settings unavailable' }
            if ($C.config.blobService.properties.containerDeleteRetentionPolicy.enabled -ne $true) { 'Container soft delete off' }
        }
    }
}
