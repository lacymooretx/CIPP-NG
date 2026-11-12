function Invoke-CIPPBreakGlassDetector {
    <#
    .SYNOPSIS
        Finds Managed Client tenants with fewer than 2 registered break-glass accounts and prepares a plan for
        Lacy to approve. Creates nothing.
    .DESCRIPTION
        Scans every tenant CIPP can reach, so tenants onboarded by hand are caught as well as wizard onboardings
        (it does not depend on service-orders). A plan is stored in table BreakGlassProvision (PartitionKey 'Plan',
        RowKey tenant id) with Status Pending, and alerted once (email + CW ticket on the client). A Pending plan
        is refreshed each run, but only re-alerted when what it would do changes. Approved, Running or Done plans
        are left alone.
        Lacy's decision (2026-11-12): plan + approve, not automatic. Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([string]$TenantFilter)

    $APIName = 'BreakGlassProvision'
    if (-not (Get-CIPPBreakGlassProvisionSettings).Enabled) { Write-Information 'Break-glass detector: switched off.'; return @() }
    $Table = Get-CIPPTable -tablename 'BreakGlassProvision'
    $Tenants = if ($TenantFilter) { @(Get-Tenants -TenantFilter $TenantFilter) } else { @(Get-Tenants) }
    $Out = [System.Collections.Generic.List[object]]::new()

    foreach ($T in $Tenants) {
        if ([string]$T.customerId -eq [string]$env:TenantID) { continue }
        # Cheap gates first, so unmanaged tenants cost no Graph calls.
        if (-not (Test-CIPPTenantManaged -TenantFilter $T.defaultDomainName).IsManaged) { continue }
        if (@(Get-CIPPBreakGlassAccounts -TenantFilter $T.customerId).Count -ge 2) { continue }

        $Plan = Get-CIPPBreakGlassProvisionPlan -TenantFilter $T.defaultDomainName
        $Id = ([string]$T.customerId).ToLower()
        $Existing = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Plan' and RowKey eq '$Id'"
        if ($Existing -and $Existing.Status -in 'Approved', 'Running') { continue }

        # What the plan would do, ignoring the random account names, so a refresh does not re-alert.
        $Shape = '{0}|{1}|{2}|{3}' -f $Plan.Status, $Plan.AccountsToCreate.Count, $Plan.GroupAction, ((@($Plan.PolicyEdits.Id) | Sort-Object) -join ',')
        $Unchanged = $Existing -and $Existing.Status -eq 'Pending' -and $Existing.Shape -eq $Shape
        # Keep the stored plan (and its account names) so what Lacy reviewed is exactly what an approval runs.
        if ($Unchanged) { $Out.Add(($Existing.PlanJson | ConvertFrom-Json)); continue }

        Add-CIPPAzDataTableEntity @Table -Entity @{
            PartitionKey = 'Plan'; RowKey = $Id; Tenant = $Plan.Tenant; Status = $(if ($Plan.Status -eq 'Ready') { 'Pending' } else { $Plan.Status })
            Shape = $Shape; PlanJson = (ConvertTo-Json -InputObject $Plan -Depth 6 -Compress); UpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        } -Force
        $Out.Add($Plan)

        $Title = if ($Plan.Status -eq 'Ready') { "Break-glass plan ready for approval: $($Plan.DisplayName)" } else { "Break-glass needed but blocked: $($Plan.DisplayName)" }
        $Enc = { param($S) [System.Net.WebUtility]::HtmlEncode([string]$S) }
        $Html = @"
<p>$(& $Enc $Plan.DisplayName) ($(& $Enc $Plan.Tenant)) is a Managed Client with $($Plan.Registered.Count) registered break-glass account(s); the standard is 2.</p>
<p><b>Status:</b> $(& $Enc $Plan.Status). $(($Plan.Reasons | ForEach-Object { & $Enc $_ }) -join ' ')</p>
<p><b>Accounts to create</b> (cloud-only, permanent Global Admin, no licence): $((($Plan.AccountsToCreate | ForEach-Object { & $Enc $_ }) -join ', '))</p>
<p><b>Exclusion group:</b> $(& $Enc $Plan.GroupAction) $(& $Enc $Plan.GroupId)</p>
<p><b>Conditional Access policies to edit</b> (break-glass group added to excludeGroups, snapshotted first):</p>
$(if (@($Plan.PolicyEdits).Count) { $Plan.PolicyEdits | Select-Object DisplayName, State | ConvertTo-Html -Fragment | Out-String } else { '<p>None.</p>' })
$(if ($Plan.Warnings.Count) { "<p><b>Warnings:</b> $(($Plan.Warnings | ForEach-Object { & $Enc $_ }) -join ' ')</p>" })
<p>Nothing has been changed. To approve: POST /api/ExecBreakGlassProvision {"tenantFilter":"$(& $Enc $Plan.Tenant)","Action":"Approve"}. The password goes to Keeper through ControlR; FIDO2 keys are registered afterwards by a tech.</p>
"@
        foreach ($Channel in 'email', 'psa') {
            try { $null = Send-CIPPAlert -Type $Channel -Title $Title -HTMLContent $Html -TenantFilter $Plan.Tenant -APIName $APIName }
            catch { Write-LogMessage -API $APIName -tenant $Plan.Tenant -message "Could not send $Channel alert for '$Title': $($_.Exception.Message)" -Sev 'Warning' }
        }
        Write-LogMessage -API $APIName -tenant $Plan.Tenant -message "$Title" -Sev 'Info'
    }
    return @($Out)
}
