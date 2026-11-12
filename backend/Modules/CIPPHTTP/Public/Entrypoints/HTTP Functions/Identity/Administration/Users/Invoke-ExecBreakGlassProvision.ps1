function Invoke-ExecBreakGlassProvision {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.SuperAdmin.ReadWrite
    .SYNOPSIS
        Plan, approve and track creation of Aspendora break-glass accounts in Managed Client tenants
    .DESCRIPTION
        Action=List      (default) every stored plan (Pending/Blocked/Approved/Done/Failed) and the settings.
        Action=Plan      builds (or refreshes) the plan for tenantFilter and alerts if it is new. Changes nothing.
        Action=Approve   approves the stored Pending plan for tenantFilter and runs it now: 2 cloud-only
                         *.onmicrosoft.com permanent Global Admins, the role-assignable exclusion group, the group
                         excluded from every CA policy (snapshotted), registry, ControlR/Keeper hand-off, alert + CW ticket.
        Action=Status    the stored plan and runs for tenantFilter.
        Action=Settings  reads the kill switch; with Enabled=true/false sets it.
        Plans come from the daily detector (Start-BreakGlassProvisionTimer) or Action=Plan. Only Managed Client
        tenants, never the partner tenant or a tenant on CIPP's exclusion list. Aspendora fork addition
        (onboarding Phase 3, 2026-11-12).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Headers = $Request.Headers
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action ?? 'List')
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $Table = Get-CIPPTable -tablename 'BreakGlassProvision'
    $Respond = { param($Code, $Body) [HttpResponseContext]@{ StatusCode = $Code; Body = $Body } }
    $Actor = try { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json).userDetails } catch { $null }
    if (-not $Actor) { $Actor = 'API client' }
    $Parse = { param($Row) if ($Row.PlanJson) { $Row.PlanJson | ConvertFrom-Json } }

    try {
        switch ($Action) {
            'List' {
                $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Plan'")
                $Plans = @($Rows | ForEach-Object { [pscustomobject]@{ TenantId = $_.RowKey; Tenant = $_.Tenant; Status = $_.Status; ApprovedBy = $_.ApprovedBy; UpdatedUtc = $_.UpdatedUtc; LastRunId = $_.LastRunId; Plan = (& $Parse $_) } })
                return (& $Respond ([HttpStatusCode]::OK) @{ Results = $Plans; Settings = (Get-CIPPBreakGlassProvisionSettings) })
            }
            'Settings' {
                $Enabled = $Request.Body.Enabled ?? $Request.Query.Enabled
                if ($null -ne $Enabled) {
                    $Value = [bool](ConvertTo-CIPPBoolean $Enabled)
                    Add-CIPPAzDataTableEntity @Table -Entity @{ PartitionKey = 'Settings'; RowKey = 'Settings'; Enabled = $Value; UpdatedBy = $Actor; UpdatedUtc = (Get-Date).ToUniversalTime().ToString('o') } -Force
                    Write-LogMessage -headers $Headers -API 'BreakGlassProvision' -tenant 'Global' -message "Break-glass provisioning switched $(if ($Value) { 'ON' } else { 'OFF' }) by $Actor" -Sev 'Warning'
                }
                return (& $Respond ([HttpStatusCode]::OK) @{ Results = (Get-CIPPBreakGlassProvisionSettings) })
            }
        }

        if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = "$Action needs a single tenantFilter." }) }
        $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
        if (-not $Tenant.customerId) { return (& $Respond ([HttpStatusCode]::NotFound) @{ Results = "Tenant $TenantFilter not found." }) }
        $TenantId = ([string]$Tenant.customerId).ToLower()
        $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Plan' and RowKey eq '$TenantId'"

        switch ($Action) {
            'Plan' {
                $null = Invoke-CIPPBreakGlassDetector -TenantFilter $Tenant.defaultDomainName
                $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Plan' and RowKey eq '$TenantId'"
                $Result = if ($Row) { [pscustomobject]@{ Status = $Row.Status; Plan = (& $Parse $Row) } } else { [pscustomobject]@{ Status = 'NoPlan'; Plan = (Get-CIPPBreakGlassProvisionPlan -TenantFilter $Tenant.defaultDomainName) } }
                return (& $Respond ([HttpStatusCode]::OK) @{ Results = $Result })
            }
            'Status' {
                $Runs = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Run' and TenantId eq '$TenantId'" | Sort-Object FinishedUtc -Descending | ForEach-Object { $_.ResultJson | ConvertFrom-Json })
                return (& $Respond ([HttpStatusCode]::OK) @{ Results = [pscustomobject]@{ Status = $Row.Status; Plan = (& $Parse $Row); Runs = $Runs } })
            }
            'Approve' {
                if (-not $Row -or $Row.Status -ne 'Pending') { return (& $Respond ([HttpStatusCode]::Conflict) @{ Results = "No Pending plan for $($Tenant.defaultDomainName) (status: $($Row.Status ?? 'none')). Run Action=Plan first and review it." }) }
                if (-not (Get-CIPPBreakGlassProvisionSettings).Enabled) { return (& $Respond ([HttpStatusCode]::Conflict) @{ Results = 'Break-glass provisioning is switched off (Action=Settings).' }) }
                $Approved = & $Parse $Row
                $Row.Status = 'Running'
                $Row | Add-Member -NotePropertyName ApprovedBy -NotePropertyValue $Actor -Force
                $Row | Add-Member -NotePropertyName ApprovedUtc -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
                Add-CIPPAzDataTableEntity @Table -Entity $Row -Force
                Write-LogMessage -headers $Headers -API 'BreakGlassProvision' -tenant $Tenant.defaultDomainName -message "Break-glass plan approved by $Actor: $(@($Approved.AccountsToCreate) -join ', ')" -Sev 'Warning'
                $Run = Invoke-CIPPBreakGlassProvision -TenantFilter $Tenant.defaultDomainName -ApprovedPlan $Approved -ApprovedBy $Actor -Headers $Headers
                # A run stopped by the re-plan or kill switch creates nothing; put the plan back so it can be re-planned.
                if (@($Run.Accounts).Count -eq 0) {
                    $Back = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Plan' and RowKey eq '$TenantId'"
                    if ($Back.Status -eq 'Running') { $Back.Status = 'Failed'; Add-CIPPAzDataTableEntity @Table -Entity $Back -Force }
                }
                return (& $Respond ([HttpStatusCode]::OK) @{ Results = $Run })
            }
            default { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = "Unknown Action '$Action'. Use List, Plan, Approve, Status or Settings." }) }
        }
    } catch {
        $Err = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API 'BreakGlassProvision' -tenant $TenantFilter -message "ExecBreakGlassProvision $Action failed: $($Err.NormalizedError)" -Sev 'Error' -LogData $Err
        return (& $Respond ([HttpStatusCode]::InternalServerError) @{ Results = "Failed: $($Err.NormalizedError)" })
    }
}
