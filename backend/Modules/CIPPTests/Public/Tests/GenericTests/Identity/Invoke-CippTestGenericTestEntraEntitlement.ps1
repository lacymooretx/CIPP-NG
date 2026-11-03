function Invoke-CippTestGenericTestEntraEntitlement {
    <#
    .SYNOPSIS
    Entra ID P1/P2 seats cover the users in scope of Conditional Access (Aspendora fork, Vikunja CIPP-47)
    #>
    param($Tenant)

    $Common = @{
        TenantFilter         = $Tenant
        TestId               = 'GenericTestEntraEntitlement'
        TestType             = 'Identity'
        Name                 = 'Entra ID P1/P2 seats cover Conditional Access scope'
        UserImpact           = 'Low'
        ImplementationEffort = 'Low'
        Category             = 'Tenant Overview'
    }
    try {
        # Tests only read stored data, and group and role expansion is not in the CIPP cache, so this reads the summary
        # stored by the report or the EntraEntitlementGap alert.
        $Table = Get-CIPPTable -tablename 'EntraEntitlement'
        $SafeTenant = ConvertTo-CIPPODataFilterValue -Value ([string]$Tenant) -Type String
        $S = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Summary' and RowKey eq '$SafeTenant'" | Select-Object -First 1
        if (-not $S) {
            Add-CippTestResult @Common -Status 'Skipped' -Risk 'Medium' -ResultMarkdown 'Not checked yet. Open **Identity > Reports > Entra ID P1/P2 True-Up** for this tenant, or schedule the Entra ID P1/P2 alert.'
            return
        }
        $Covered = [bool]$S.CoveredP1 -and [bool]$S.CoveredP2
        $Checked = try {
            $Zone = [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago')
            $Local = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetimeoffset][string]$S.CheckedUtc).UtcDateTime, $Zone)
            "$($Local.ToString('yyyy-MM-dd HH:mm')) US Central"
        } catch { [string]$S.CheckedUtc }
        $Lead = if ($Covered) { 'The tenant owns enough seats for the users in scope of enforced policies.' } else { 'The tenant owns fewer seats than the users in scope of enforced policies.' }
        $Md = [System.Text.StringBuilder]::new("$Lead`n`n")
        $null = $Md.Append("| Tier | Seats owned | Users in scope | Short | In scope with no plan assigned | In scope if report-only policies were enabled |`n")
        $null = $Md.Append("|---|---|---|---|---|---|`n")
        $null = $Md.Append("| P1 | $($S.P1Pool) | $($S.P1InScope) | $($S.P1Shortfall) | $($S.P1UserGaps) | $($S.P1InScopeWithReportOnly) |`n")
        $null = $Md.Append("| P2 | $($S.P2Pool) | $($S.P2InScope) | $($S.P2Shortfall) | $($S.P2UserGaps) | $($S.P2InScopeWithReportOnly) |`n`n")
        $null = $Md.Append("Checked $Checked. Guests are billed on monthly active users and are not counted. Users with no plan assigned are advisory true-up evidence.")
        Add-CippTestResult @Common -Status $(if ($Covered) { 'Passed' } else { 'Failed' }) -Risk 'Medium' -ResultMarkdown $Md.ToString()
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Tests' -tenant $Tenant -message "Failed to run test GenericTestEntraEntitlement: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        Add-CippTestResult @Common -Status 'Failed' -Risk 'Medium' -ResultMarkdown "Test failed: $($ErrorMessage.NormalizedError)"
    }
}
