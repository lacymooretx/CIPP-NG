function Invoke-CippTestAZ_STG_07 {
    <#
    .SYNOPSIS
    Azure - Blob soft delete is enabled (7+ days)
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_STG_07' -Name 'Blob soft delete is enabled (7+ days)' -Risk 'Medium' -Category 'Storage' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.storage/storageaccounts') -FailStatus 'Failed' -Requirement 'blob soft delete enabled with at least 7 days retention' -Check {
            param($R)
            if ($R.kind -eq 'FileStorage') { return '#skip:file-only account' }
            $C = $Ctx.Config[([string]$R.id).ToLower()]
            if (-not $C -or $C.errors.blobService) { return '#skip:blob service settings unavailable' }
            $P = $C.config.blobService.properties.deleteRetentionPolicy
            if ($P.enabled -ne $true) { 'Blob soft delete off' } elseif ([int]$P.days -lt 7) { "Blob soft delete only $($P.days) day(s)" }
        }
    }
}
