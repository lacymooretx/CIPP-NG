function Invoke-CippTestAZ_KV_04 {
    <#
    .SYNOPSIS
    Azure - Key vault audit logging is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_KV_04' -Name 'Key vault audit logging is enabled' -Risk 'Medium' -Category 'Key Vault' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.keyvault/vaults') -FailStatus 'Failed' -Requirement 'diagnostic setting sends AuditEvent logs somewhere' -Check {
            param($R)
            $C = $Ctx.Config[([string]$R.id).ToLower()]
            if (-not $C -or $C.errors.diagnosticSettings) { return '#skip:diagnostic settings unavailable' }
            $Ok = @($C.config.diagnosticSettings | Where-Object { @($_.properties.logs | Where-Object { $_.enabled -and ($_.category -eq 'AuditEvent' -or $_.categoryGroup -in @('audit', 'allLogs')) }).Count -gt 0 })
            if ($Ok.Count -eq 0) { 'No diagnostic setting captures AuditEvent' }
        }
    }
}
