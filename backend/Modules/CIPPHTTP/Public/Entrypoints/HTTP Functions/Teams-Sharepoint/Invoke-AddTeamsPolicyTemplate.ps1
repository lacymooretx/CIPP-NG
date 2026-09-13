function Invoke-AddTeamsPolicyTemplate {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Teams.Config.ReadWrite
    .DESCRIPTION
        Captures a tenant's live Teams policy configuration as a reusable template, or
        saves a hand-built one. Templates are deployed to other tenants with
        ExecTeamsPolicyTemplate.

        Two modes.

        Capture from a live tenant (the usual case):
          TenantFilter (required) - the tenant to read from
          PolicyTypes  (required) - array of ConfigAPI types to capture, e.g.
                                    ['TeamsMeetingPolicy','TeamsMessagingPolicy'].
                                    Pass ['*'] to capture every type in the catalog.
          Identity                - which instance to capture. Default 'Global'.
          Name         (required) - template name
          Description             - free text

        Save a supplied template:
          Name         (required)
          Description
          Policies     (required) - array of { PolicyType, Identity, Parameters }

        The capture strips the ConfigAPI scope/identity envelope (Key, ConfigId,
        ConfigMetadata...) via ConvertTo-CIPPTeamsPolicyTemplate, so the result is
        portable. Types that fail to read are recorded on the template with their error
        rather than silently omitted - a template that quietly captured 3 of 5 policies
        would deploy an incomplete baseline.

    .EXAMPLE
        POST /api/AddTeamsPolicyTemplate
        { "TenantFilter": "aspendora.com", "Name": "Aspendora Teams Baseline",
          "PolicyTypes": ["TeamsMeetingPolicy","TeamsMessagingPolicy","ExternalAccessPolicy"] }
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.TenantFilter
    $Name = $Request.Body.Name
    $Description = $Request.Body.Description
    $PolicyTypes = $Request.Body.PolicyTypes
    $Identity = $Request.Body.Identity ?? 'Global'
    $Policies = $Request.Body.Policies

    if (-not $Name) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Name is required.' }
            })
    }
    if (-not $Policies -and (-not $TenantFilter -or -not $PolicyTypes)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Supply either Policies (a prebuilt template), or TenantFilter + PolicyTypes to capture from a live tenant.' }
            })
    }

    try {
        $Captured = [System.Collections.Generic.List[object]]::new()
        $Failures = [System.Collections.Generic.List[object]]::new()

        if ($Policies) {
            foreach ($Entry in $Policies) {
                $ParamHash = @{}
                foreach ($Prop in $Entry.Parameters.PSObject.Properties) { $ParamHash[$Prop.Name] = $Prop.Value }
                $Captured.Add([pscustomobject]@{
                        PolicyType = $Entry.PolicyType
                        Identity   = $Entry.Identity ?? 'Global'
                        Parameters = $ParamHash
                    })
            }
        } else {
            # '*' means every type in the catalog.
            $TypeList = @($PolicyTypes)
            if ($TypeList -contains '*') {
                $CatalogPath = Join-Path $env:CIPPRootPath 'Config' 'TeamsPolicyTypes.json'
                $TypeList = (([System.IO.File]::ReadAllText($CatalogPath) | ConvertFrom-Json).types).type
            }

            $FederationTypes = @('TenantFederationSettings', 'TenantFederationConfiguration', 'TeamsAcsFederationConfiguration')

            foreach ($Type in $TypeList) {
                try {
                    $Splat = @{ TenantFilter = $TenantFilter; Type = $Type; Action = 'Get'; Identity = $Identity }
                    if (($Type -replace '^(Get|Set|New|Remove|Grant|Revoke)-Cs', '') -in $FederationTypes) { $Splat.UseServiceDiscovery = $true }
                    $Live = New-TeamsRequestV2 @Splat
                    $Clean = $Live | ConvertTo-CIPPTeamsPolicyTemplate
                    if (-not $Clean) { throw 'Policy returned no settable properties.' }

                    $ParamHash = @{}
                    foreach ($Prop in $Clean.PSObject.Properties) { $ParamHash[$Prop.Name] = $Prop.Value }

                    $Captured.Add([pscustomobject]@{
                            PolicyType = $Type
                            Identity   = $Identity
                            Parameters = $ParamHash
                        })
                } catch {
                    $Failures.Add([pscustomobject]@{
                            PolicyType = $Type
                            Error      = (Get-NormalizedError -Message $_.Exception.Message)
                        })
                }
            }
        }

        if ($Captured.Count -eq 0) {
            $Detail = if ($Failures.Count -gt 0) { " Failures: $(($Failures | ForEach-Object { "$($_.PolicyType): $($_.Error)" }) -join '; ')" } else { '' }
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ Results = "Captured nothing - template not saved.$Detail" }
                })
        }

        $GUID = (New-Guid).GUID
        $Template = [pscustomobject]@{
            name           = $Name
            description    = $Description
            capturedFrom   = $TenantFilter
            capturedAt     = (Get-Date).ToUniversalTime().ToString('o')
            policyCount    = $Captured.Count
            policies       = $Captured
            captureFailures = $Failures
        }

        $Table = Get-CippTable -tablename 'templates'
        $Table.Force = $true
        Add-CIPPAzDataTableEntity @Table -Entity @{
            JSON         = ($Template | ConvertTo-Json -Depth 25 -Compress)
            RowKey       = "$GUID"
            PartitionKey = 'TeamsPolicyTemplate'
        }

        $Result = "Created Teams policy template '$Name' with $($Captured.Count) policies (GUID $GUID)."
        if ($Failures.Count -gt 0) { $Result += " $($Failures.Count) type(s) could not be captured and are recorded on the template." }
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Info'

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{ Results = $Result; GUID = $GUID; Captured = $Captured.PolicyType; Failures = $Failures }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to create Teams policy template: $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = $Result }
            })
    }
}
