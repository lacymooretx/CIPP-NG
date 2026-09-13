function Invoke-CIPPStandardTeamsPolicyTemplate {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) TeamsPolicyTemplate
    .SYNOPSIS
        (Label) Enforce a captured Teams policy template
    .DESCRIPTION
        (Helptext) Compares the tenant's Teams configuration against a template captured with AddTeamsPolicyTemplate, and optionally corrects any drift. Where the individual Teams standards each pin a handful of properties, this enforces an entire captured baseline - every property the template holds. Capture the template from a reference tenant under Teams > Teams Policies, then select it here.
        (DocsDescription) Compares the tenant's Teams configuration against a saved Teams policy template and optionally remediates drift. The template is captured from a reference tenant with AddTeamsPolicyTemplate and may cover any of the 48 Teams ConfigAPI policy types. Remediation writes only the properties that actually differ, then reads each policy back to confirm the write landed - the Teams ConfigAPI returns 204 whether or not it applied a change, so a write is never reported as successful on the status code alone.
    .NOTES
        CAT
            Teams Standards
        TAG
        EXECUTIVETEXT
            Keeps Microsoft Teams settings consistent across every managed customer by comparing each tenant against an approved reference configuration. Differences are reported, and can be corrected automatically, so a tenant cannot quietly drift away from the agreed standard.
        ADDEDCOMPONENT
            {"type":"autoComplete","required":true,"multiple":false,"creatable":false,"name":"standards.TeamsPolicyTemplate.TemplateId","label":"Teams policy template","api":{"url":"/api/ListTeamsPolicyTemplates","labelField":"name","valueField":"GUID","queryKey":"ListTeamsPolicyTemplates"}}
        IMPACT
            High Impact
        ADDEDDATE
            2026-09-13
        POWERSHELLEQUIVALENT
            Get-CsTeamsMeetingPolicy / Set-CsTeamsMeetingPolicy (per policy type in the template)
        RECOMMENDEDBY
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/alignment/templates/available-standards
    #>
    param($Tenant, $Settings)

    $TestResult = Test-CIPPStandardLicense -StandardName 'TeamsPolicyTemplate' -TenantFilter $Tenant -Preset Teams
    if ($TestResult -eq $false) {
        return $true
    }

    $TemplateId = $Settings.TemplateId.value ?? $Settings.TemplateId
    if (-not $TemplateId) {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message 'TeamsPolicyTemplate: no template selected; nothing to enforce.' -sev Error
        return
    }

    try {
        $Table = Get-CippTable -tablename 'templates'
        $Entity = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'TeamsPolicyTemplate' and RowKey eq '$TemplateId'"
        if (-not $Entity) { throw "No Teams policy template with GUID $TemplateId." }
        $Template = $Entity.JSON | ConvertFrom-Json
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "TeamsPolicyTemplate: could not load the template. Error: $ErrorMessage" -sev Error
        return
    }

    $FederationTypes = @('TenantFederationSettings', 'TenantFederationConfiguration', 'TeamsAcsFederationConfiguration')
    $Drift = [System.Collections.Generic.List[object]]::new()
    $ReadFailures = [System.Collections.Generic.List[object]]::new()

    # Pass 1: read every policy in the template and collect what differs.
    foreach ($Policy in @($Template.policies)) {
        $Type = $Policy.PolicyType
        $PolicyIdentity = $Policy.Identity ?? 'Global'
        $Normalized = $Type -replace '^(Get|Set|New|Remove|Grant|Revoke)-Cs', ''
        $Splat = @{ TenantFilter = $Tenant; Type = $Type; Identity = $PolicyIdentity }
        if ($Normalized -in $FederationTypes) { $Splat.UseServiceDiscovery = $true }

        try {
            $Current = New-TeamsRequestV2 @Splat -Action Get
            foreach ($Prop in $Policy.Parameters.PSObject.Properties) {
                $CurrentJson = ConvertTo-Json $Current.($Prop.Name) -Depth 10 -Compress
                $DesiredJson = ConvertTo-Json $Prop.Value -Depth 10 -Compress
                if ($CurrentJson -ne $DesiredJson) {
                    $Drift.Add([pscustomobject]@{
                            PolicyType = $Normalized
                            Identity   = $PolicyIdentity
                            Property   = $Prop.Name
                            Current    = $Current.($Prop.Name)
                            Expected   = $Prop.Value
                        })
                }
            }
        } catch {
            $ReadFailures.Add([pscustomobject]@{ PolicyType = $Normalized; Error = (Get-NormalizedError -Message $_.Exception.Message) })
        }
    }

    # A policy we could not read is not evidence of compliance, so it must not count as correct.
    $StateIsCorrect = ($Drift.Count -eq 0) -and ($ReadFailures.Count -eq 0)

    if ($Settings.remediate -eq $true) {
        if ($StateIsCorrect) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "TeamsPolicyTemplate: '$($Template.name)' already matches." -sev Info
        } else {
            # Group the drift back into one Set per policy, writing only what differs.
            foreach ($Group in ($Drift | Group-Object PolicyType, Identity)) {
                $First = $Group.Group[0]
                $ChangeSet = @{}
                foreach ($Item in $Group.Group) { $ChangeSet[$Item.Property] = $Item.Expected }

                $Splat = @{ TenantFilter = $Tenant; Type = $First.PolicyType; Identity = $First.Identity }
                if ($First.PolicyType -in $FederationTypes) { $Splat.UseServiceDiscovery = $true }

                try {
                    $null = New-TeamsRequestV2 @Splat -Action Set -Parameters $ChangeSet

                    # Read back. The ConfigApi 204s whether or not it applied anything.
                    $After = New-TeamsRequestV2 @Splat -Action Get
                    $Failed = foreach ($Key in $ChangeSet.Keys) {
                        if ((ConvertTo-Json $After.$Key -Depth 10 -Compress) -ne (ConvertTo-Json $ChangeSet[$Key] -Depth 10 -Compress)) { $Key }
                    }
                    if ($Failed) {
                        Write-LogMessage -API 'Standards' -tenant $Tenant -sev Error `
                            -message "TeamsPolicyTemplate: $($First.PolicyType)/$($First.Identity) reported success but these properties did not apply: $($Failed -join ', ')."
                    } else {
                        Write-LogMessage -API 'Standards' -tenant $Tenant -sev Info `
                            -message "TeamsPolicyTemplate: corrected $($First.PolicyType)/$($First.Identity) ($(($ChangeSet.Keys | Sort-Object) -join ', '))."
                    }
                } catch {
                    $ErrorMessage = Get-CippException -Exception $_
                    Write-LogMessage -API 'Standards' -tenant $Tenant -sev Error -LogData $ErrorMessage `
                        -message "TeamsPolicyTemplate: failed to correct $($First.PolicyType)/$($First.Identity). Error: $($ErrorMessage.NormalizedError)"
                }
            }
        }
    }

    if ($Settings.alert -eq $true) {
        if ($StateIsCorrect) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "TeamsPolicyTemplate: '$($Template.name)' matches." -sev Info
        } else {
            $Reason = if ($ReadFailures.Count -gt 0 -and $Drift.Count -gt 0) {
                "$($Drift.Count) setting(s) drifted from '$($Template.name)', and $($ReadFailures.Count) policy type(s) could not be read"
            } elseif ($ReadFailures.Count -gt 0) {
                "$($ReadFailures.Count) policy type(s) in '$($Template.name)' could not be read, so compliance is unknown"
            } else {
                "$($Drift.Count) setting(s) drifted from '$($Template.name)'"
            }
            Write-StandardsAlert -message "Teams configuration drift: $Reason." -object @{ Drift = @($Drift); ReadFailures = @($ReadFailures) } -tenant $Tenant -standardName 'TeamsPolicyTemplate' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "TeamsPolicyTemplate: $Reason." -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        $CurrentValue = @{
            TemplateName  = $Template.name
            DriftCount    = $Drift.Count
            ReadFailures  = $ReadFailures.Count
            DriftedValues = @($Drift | ForEach-Object { "$($_.PolicyType).$($_.Property)=$(ConvertTo-Json $_.Current -Depth 5 -Compress)" })
        }
        $ExpectedValue = @{
            TemplateName  = $Template.name
            DriftCount    = 0
            ReadFailures  = 0
            DriftedValues = @()
        }
        Set-CIPPStandardsCompareField -FieldName 'standards.TeamsPolicyTemplate' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -Tenant $Tenant
        Add-CIPPBPAField -FieldName 'TeamsPolicyTemplate' -FieldValue $StateIsCorrect -StoreAs bool -Tenant $Tenant
    }
}
