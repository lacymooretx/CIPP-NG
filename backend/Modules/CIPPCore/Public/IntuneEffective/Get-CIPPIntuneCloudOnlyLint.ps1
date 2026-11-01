function Get-CIPPIntuneCloudOnlyLint {
    <#
    .SYNOPSIS
        Lints a tenant's Intune policies, or one saved CIPP Intune template, for settings that misbehave on
        Entra joined (cloud-only) devices.
    .DESCRIPTION
        Read-only. Tenant mode reads every policy family with assignments (Get-CIPPIntuneAssignablePolicies), then in
        one batch the Settings Catalog settings (/configurationPolicies/{id}/settings), the custom OMA-URI device
        configurations (/deviceConfigurations/{id}) and the Administrative Template values
        (/groupPolicyConfigurations/{id}/definitionValues?$expand=definition). An OMA-URI value Intune returns
        encrypted is decrypted (Get-CIPPOmaSettingDecryptedValue) only when its URI matches a lint rule.
        Template mode reads one row of the 'templates' table (PartitionKey IntuneTemplate) by GUID.

        Both modes add tenant context when a tenant is given: Windows devices by Entra trustType (AzureAd = Entra
        joined / cloud-only, ServerAd = hybrid joined, Workplace = registered) and whether the tenant syncs from
        on-premises AD (organization.onPremisesSyncEnabled). A finding only matters when cloud-only devices exist;
        the per-finding Relevance says so. Evaluated with Test-CIPPIntuneCloudOnlyLint.
        Returns @{ Mode; Tenant; Template; Findings; Summary; Context; Errors }. Aspendora fork addition (Vikunja CIPP-28).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$TenantFilter,
        # A saved CIPP Intune template GUID (templates table RowKey). When set, the template is linted instead of
        # the tenant's live policies.
        [string]$TemplateId
    )

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Msg = { param($E) (Get-CippException -Exception $E).NormalizedError }
    $HasTenant = [bool]($TenantFilter -and $TenantFilter -ne 'AllTenants')
    if (-not $TemplateId -and -not $HasTenant) { throw 'Pick a single tenant, or a template to lint.' }

    $RulesPath = Join-Path $env:CIPPRootPath 'Config/IntuneCloudOnlyLintRules.json'
    $Rules = @((Get-Content -Path $RulesPath -Raw -ErrorAction Stop | ConvertFrom-Json).rules)

    # --- tenant context ---------------------------------------------------------------------------------
    $Context = $null
    if ($HasTenant) {
        $Context = [ordered]@{ CloudOnlyDevices = $null; HybridDevices = $null; RegisteredDevices = $null; WindowsDevices = $null; DirectorySynced = $null }
        try {
            $Devices = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/devices?$select=id,trustType,operatingSystem&$top=999' -tenantid $TenantFilter -ErrorAction Stop)
            $Windows = @($Devices | Where-Object { [string]$_.operatingSystem -like 'Windows*' })
            $Context.WindowsDevices = $Windows.Count
            $Context.CloudOnlyDevices = @($Windows | Where-Object { $_.trustType -eq 'AzureAd' }).Count
            $Context.HybridDevices = @($Windows | Where-Object { $_.trustType -eq 'ServerAd' }).Count
            $Context.RegisteredDevices = @($Windows | Where-Object { $_.trustType -eq 'Workplace' }).Count
        } catch { $Errors.Add("Device join types: $(& $Msg $_)") }
        try {
            $Org = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/organization?$select=id,onPremisesSyncEnabled' -tenantid $TenantFilter -ErrorAction Stop) | Select-Object -First 1
            # onPremisesSyncEnabled is null for a tenant that never synced: that is "no", not "unknown".
            $Context.DirectorySynced = ($Org.onPremisesSyncEnabled -eq $true)
        } catch { $Errors.Add("Directory sync state: $(& $Msg $_)") }
    }

    # --- policies to lint -------------------------------------------------------------------------------
    $Policies = [System.Collections.Generic.List[object]]::new()
    $TemplateInfo = $null
    $PoliciesRead = 0

    if ($TemplateId) {
        $Table = Get-CippTable -tablename 'templates'
        $SafeId = $TemplateId -replace "'", "''"
        $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'IntuneTemplate' and RowKey eq '$SafeId'" | Select-Object -First 1
        if (-not $Row) { throw "No Intune template with id $TemplateId was found." }
        $J = $Row.JSON | ConvertFrom-Json -Depth 100 -ErrorAction Stop
        $TypeLabel = switch ([string]$J.Type) {
            'Catalog' { 'Settings Catalog' }
            'Device' { 'Device Configuration' }
            'Admin' { 'Administrative Templates' }
            default { [string]$J.Type }
        }
        $TemplateInfo = [pscustomobject]@{ GUID = [string]$Row.RowKey; DisplayName = [string]$J.Displayname; Type = $TypeLabel; Package = [string]$Row.Package }
        # RAWJson stays a string: Test-CIPPIntuneCloudOnlyLint parses it and treats invalid JSON as "no findings".
        $Policies.Add([pscustomobject]@{ Id = [string]$Row.RowKey; Name = [string]$J.Displayname; Type = $TypeLabel; Assigned = $null; Body = [string]$J.RAWJson })
        $PoliciesRead = 1
    } else {
        $Collected = Get-CIPPIntuneAssignablePolicies -TenantFilter $TenantFilter
        foreach ($E in $Collected.Errors) { $Errors.Add($E) }
        $Targets = @($Collected.Policies | Where-Object {
                $_.Family -in @('ConfigurationPolicies', 'GroupPolicyConfigurations') -or
                ($_.Family -eq 'DeviceConfigurations' -and $_.ODataType -like '*windows10CustomConfiguration')
            })
        $PoliciesRead = $Targets.Count
        $Requests = [System.Collections.Generic.List[object]]::new()
        foreach ($P in $Targets) {
            $Url = switch ($P.Family) {
                'ConfigurationPolicies' { "/deviceManagement/configurationPolicies('$($P.Id)')/settings" }
                'DeviceConfigurations' { "/deviceManagement/deviceConfigurations('$($P.Id)')" }
                'GroupPolicyConfigurations' { "/deviceManagement/groupPolicyConfigurations('$($P.Id)')/definitionValues?`$expand=definition" }
            }
            $Requests.Add([pscustomobject]@{ id = $P.Id; method = 'GET'; url = $Url })
        }
        $ById = @{}
        if ($Requests.Count -gt 0) {
            foreach ($Reply in @(New-GraphBulkRequest -Requests @($Requests) -tenantid $TenantFilter)) { $ById[[string]$Reply.id] = $Reply }
        }
        # OMA URIs any rule cares about, to decide whether an encrypted value is worth decrypting.
        $OmaPatterns = @($Rules | ForEach-Object { @($_.match.omaUris) } | Where-Object { $_ })
        foreach ($P in $Targets) {
            $Reply = $ById[[string]$P.Id]
            if (-not $Reply -or ($null -ne $Reply.status -and ($Reply.status -lt 200 -or $Reply.status -ge 300))) {
                $Errors.Add("$($P.Type) '$($P.Name)': settings could not be read$(if ($Reply.status) { " (HTTP $($Reply.status))" })")
                continue
            }
            $Body = switch ($P.Family) {
                'ConfigurationPolicies' { [pscustomobject]@{ settings = @($Reply.body.value) } }
                'GroupPolicyConfigurations' { [pscustomobject]@{ definitionValues = @($Reply.body.value) } }
                default { $Reply.body }
            }
            if ($P.Family -eq 'DeviceConfigurations') {
                $NeedsDecrypt = @($Body.omaSettings | Where-Object {
                        $Oma = $_
                        ($Oma.isEncrypted -eq $true -or $Oma.secretReferenceValueId -or "$($Oma.value)" -eq 'PGEvPg==') -and
                        @($OmaPatterns | Where-Object { [string]$Oma.omaUri -like $_ }).Count -gt 0
                    }).Count -gt 0
                if ($NeedsDecrypt) {
                    try { $Body = Get-CIPPOmaSettingDecryptedValue -DeviceConfiguration $Body -DeviceConfigurationId $P.Id -TenantFilter $TenantFilter }
                    catch { $Errors.Add("'$($P.Name)': encrypted OMA-URI value could not be read, so it is matched on the URI only.") }
                }
            }
            $Assigned = if ($P.AssignmentsUnknown) { $null } else { @($P.Assignments | Where-Object { $_ }).Count -gt 0 }
            $Type = if ($P.Family -eq 'DeviceConfigurations') { 'Custom (OMA-URI)' } else { $P.Type }
            $Policies.Add([pscustomobject]@{ Id = $P.Id; Name = $P.Name; Type = $Type; Assigned = $Assigned; Body = $Body })
        }
    }

    $Findings = @(Test-CIPPIntuneCloudOnlyLint -Policies @($Policies) -Rules $Rules -Context $Context)

    $BySeverity = [ordered]@{}
    foreach ($S in 'High', 'Medium', 'Low', 'Info') { $BySeverity[$S] = @($Findings | Where-Object Severity -EQ $S).Count }
    $Summary = [pscustomobject]@{
        PoliciesChecked = $PoliciesRead
        Findings        = $Findings.Count
        Relevant        = @($Findings | Where-Object { $_.Relevance -in @('Applies', 'Check', 'Unknown') }).Count
        BySeverity      = [pscustomobject]$BySeverity
        RulesLoaded     = $Rules.Count
    }

    [pscustomobject]@{
        Mode     = if ($TemplateId) { 'Template' } else { 'Tenant' }
        Tenant   = if ($HasTenant) { $TenantFilter } else { $null }
        Template = $TemplateInfo
        Findings = $Findings
        Summary  = $Summary
        Context  = if ($Context) { [pscustomobject]$Context } else { $null }
        Rules    = @($Rules | ForEach-Object { [pscustomobject]@{ Id = $_.id; Title = $_.title; Severity = $_.severity; AppliesWhen = $_.appliesWhen } })
        Errors   = @($Errors)
    }
}
