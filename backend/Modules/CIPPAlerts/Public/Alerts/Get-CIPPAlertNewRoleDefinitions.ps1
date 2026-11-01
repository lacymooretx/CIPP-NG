function Get-CIPPAlertNewRoleDefinitions {
    <#
    .SYNOPSIS
        Weekly alert on directory role definitions that were not there last time
    .DESCRIPTION
        Compares the tenant's roleManagement/directory/roleDefinitions with the ids recorded in table
        KnownRoleDefinitions (PartitionKey = tenant, RowKey = role definition id). The first run for a tenant only
        records what exists (silent seed). After that, each new definition is raised once:
          custom role (isBuiltIn false)   Warning: someone created a role; check what it grants and who holds it
          new built-in role               Info, and only when RoleDefinitionsIncludeBuiltIn is on: Microsoft adds
                                          built-in roles often, and every tenant sees them at once
        New ids are recorded as soon as they are seen, so a definition notifies once. Rows go through the lifecycle
        in append mode (events, not state) with a stable Id per definition. Report only: nothing in the tenant is
        changed; the table is CIPP's own. Aspendora fork addition (Vikunja CIPP-15).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )
    try {
        $IncludeBuiltIn = ConvertTo-CIPPBoolean -Value $InputValue.RoleDefinitionsIncludeBuiltIn
        $Definitions = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,isEnabled,isPrivileged,rolePermissions' -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
        if ($Definitions.Count -eq 0) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message 'New role definitions: the tenant returned no role definitions; skipped.' -sev Warning
            return
        }

        $Table = Get-CIPPTable -tablename 'KnownRoleDefinitions'
        $SafeTenant = ConvertTo-CIPPODataFilterValue -Value ([string]$TenantFilter) -Type String
        $Known = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$SafeTenant'")
        $KnownIds = @{}
        foreach ($K in $Known) { $KnownIds[([string]$K.RowKey).ToLower()] = $true }
        $Seeding = $Known.Count -eq 0
        $New = @($Definitions | Where-Object { -not $KnownIds.ContainsKey(([string]$_.id).ToLower()) })
        if ($New.Count -eq 0) { return }

        $NowIso = [datetime]::UtcNow.ToString('o')
        $Entities = @($New | ForEach-Object {
                @{ PartitionKey = [string]$TenantFilter; RowKey = ([string]$_.id).ToLower(); DisplayName = [string]$_.displayName; IsBuiltIn = [bool]$_.isBuiltIn; FirstSeenUtc = $NowIso; Seeded = $Seeding }
            })
        if ($Seeding) {
            Add-CIPPAzDataTableEntity @Table -Force -Entity $Entities | Out-Null
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "New role definitions: first run, recorded $($New.Count) existing role definition(s) silently." -sev Info
            return
        }

        $Rows = foreach ($D in $New) {
            if ($D.isBuiltIn -eq $true -and -not $IncludeBuiltIn) { continue }
            $Actions = @($D.rolePermissions.allowedResourceActions | Where-Object { $_ })
            $Sample = (@($Actions | Select-Object -First 8) -join ', ') + $(if ($Actions.Count -gt 8) { " and $($Actions.Count - 8) more" })
            if ($D.isBuiltIn -eq $true) {
                [pscustomobject]@{ Id = "NewRoleDefinition|$($D.id)"; Severity = 'Info'; Role = $D.displayName; BuiltIn = $true; Privileged = $D.isPrivileged -eq $true
                    Message = "Microsoft added built-in role '$($D.displayName)'$(if ($D.isPrivileged -eq $true) { ' (marked privileged)' }). $($D.description)" }
            } else {
                [pscustomobject]@{ Id = "NewRoleDefinition|$($D.id)"; Severity = 'Warning'; Role = $D.displayName; BuiltIn = $false; Privileged = $D.isPrivileged -eq $true
                    Message = "A custom directory role '$($D.displayName)' was created$(if ($D.isEnabled -eq $false) { ' (disabled)' }). It allows: $Sample. Check who created it (Entra audit log, 'Add role definition') and who it is assigned to." }
            }
        }
        $Rows = @($Rows)
        $Notify = if ($Rows.Count -gt 0) { @(Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows -Append | Where-Object { $_ }) } else { @() }
        # Recorded after the lifecycle write, so a failure above re-raises next run (the lifecycle de-duplicates).
        Add-CIPPAzDataTableEntity @Table -Force -Entity $Entities | Out-Null
        $Notify
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "New role definitions check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$((Get-CippException -Exception $_).NormalizedError) $_") -LogData (Get-CippException -Exception $_)
    }
}
