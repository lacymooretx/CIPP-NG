function Invoke-CIPPStandardPrinterCatalog {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) PrinterCatalog
    .SYNOPSIS
        (Label) Deploy the tenant's printer catalogue
    .DESCRIPTION
        (Helptext) Checks that every printer in the tenant's CIPP printer catalogue has been deployed to Intune, and optionally deploys the ones that are missing. Universal Print entries become a settings catalog policy; direct IP and print-server entries become an Intune platform script.
        (DocsDescription) Compares the tenant's CIPP printer catalogue against what is actually deployed in Intune and reports any printer that has no corresponding policy or script. Remediation deploys the missing ones using the same path as the Deploy action on the catalogue page. Printers are never removed by this standard.
    .NOTES
        CAT
            Intune Standards
        TAG
        EXECUTIVETEXT
            Ensures every printer the customer is supposed to have is actually published to their staff, so a new starter or a rebuilt laptop gets the right printers without a support call.
        ADDEDCOMPONENT
            {"type":"switch","name":"standards.PrinterCatalog.AssignOnDeploy","label":"Apply the group assignment stored on each catalogue entry"}
        IMPACT
            Medium Impact
        ADDEDDATE
            2026-09-14
        POWERSHELLEQUIVALENT
            Portal or Graph API
        RECOMMENDEDBY
        UPDATECOMMENTBLOCK
            Run the tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/alignment/templates/available-standards
    #>

    param($Tenant, $Settings)

    $AssignOnDeploy = $Settings.AssignOnDeploy -eq $true

    try {
        $TenantObj = Get-Tenants -TenantFilter $Tenant
        $CustomerId = $TenantObj.customerId ?? $Tenant
        $Table = Get-CIPPTable -TableName 'PrinterCatalog'
        $Catalog = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$CustomerId'")
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "PrinterCatalog: could not read the catalogue. Error: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return
    }

    if ($Catalog.Count -eq 0) {
        # Nothing catalogued is not drift - it is a tenant that does not use this yet.
        Write-LogMessage -API 'Standards' -tenant $Tenant -message 'PrinterCatalog: no printers catalogued for this tenant; nothing to enforce.' -sev Info
        if ($Settings.report -eq $true) {
            Set-CIPPStandardsCompareField -FieldName 'standards.PrinterCatalog' -CurrentValue @{ Catalogued = 0; Missing = @() } -ExpectedValue @{ Catalogued = 0; Missing = @() } -TenantFilter $Tenant
            Add-CIPPBPAField -FieldName 'PrinterCatalog' -FieldValue $true -StoreAs bool -Tenant $Tenant
        }
        return
    }

    # Read both target surfaces once rather than per printer.
    $ReadFailures = [System.Collections.Generic.List[string]]::new()
    try {
        $Policies = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -tenantid $Tenant)
    } catch {
        $Policies = @()
        $ReadFailures.Add('configurationPolicies')
    }
    try {
        $Scripts = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' -tenantid $Tenant)
    } catch {
        $Scripts = @()
        $ReadFailures.Add('deviceManagementScripts')
    }

    $Missing = [System.Collections.Generic.List[object]]::new()
    foreach ($Printer in $Catalog) {
        if ($Printer.PrinterType -eq 'UniversalPrint') {
            $Expected = "CIPP: Universal Print - $($Printer.Name)"
            $Found = $Policies | Where-Object { $_.name -eq $Expected }
        } else {
            $Expected = "CIPP: Printer - $($Printer.Name)"
            $Found = $Scripts | Where-Object { $_.displayName -eq $Expected }
        }
        if (-not $Found) {
            $Missing.Add([PSCustomObject]@{ id = $Printer.RowKey; Name = $Printer.Name; PrinterType = $Printer.PrinterType })
        }
    }

    # A surface we could not read is not evidence of compliance, so it must not count as correct.
    $StateIsCorrect = ($Missing.Count -eq 0) -and ($ReadFailures.Count -eq 0)

    if ($Settings.remediate -eq $true) {
        if ($ReadFailures.Count -gt 0) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "PrinterCatalog: skipping remediation because $($ReadFailures -join ' and ') could not be read; deploying now could duplicate existing objects." -sev Error
        } elseif ($StateIsCorrect) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'PrinterCatalog: every catalogued printer is already deployed.' -sev Info
        } else {
            foreach ($Item in $Missing) {
                try {
                    $Entry = $Catalog | Where-Object { $_.RowKey -eq $Item.id } | Select-Object -First 1
                    $AssignTarget = if ($AssignOnDeploy) { $Entry.AssignTo } else { '' }
                    $DeployResult = Set-CIPPCatalogPrinter -Printer $Entry -TenantFilter $Tenant -AssignTo $AssignTarget -APIName 'Standards'
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "PrinterCatalog: $DeployResult" -sev Info
                } catch {
                    $ErrorMessage = Get-CippException -Exception $_
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "PrinterCatalog: failed to deploy '$($Item.Name)'. Error: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
                }
            }
        }
    }

    if ($Settings.alert -eq $true) {
        if ($StateIsCorrect) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'PrinterCatalog: every catalogued printer is deployed.' -sev Info
        } else {
            Write-StandardsAlert -message "PrinterCatalog: $($Missing.Count) catalogued printer(s) are not deployed" -object @{ Missing = @($Missing.Name); ReadFailures = @($ReadFailures) } -tenant $Tenant -standardName 'PrinterCatalog' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "PrinterCatalog: $($Missing.Count) catalogued printer(s) are not deployed." -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        $CurrentValue = @{ Catalogued = $Catalog.Count; Missing = @($Missing.Name | Sort-Object); ReadFailures = @($ReadFailures) }
        $ExpectedValue = @{ Catalogued = $Catalog.Count; Missing = @(); ReadFailures = @() }
        Set-CIPPStandardsCompareField -FieldName 'standards.PrinterCatalog' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
        Add-CIPPBPAField -FieldName 'PrinterCatalog' -FieldValue $StateIsCorrect -StoreAs bool -Tenant $Tenant
    }
}
