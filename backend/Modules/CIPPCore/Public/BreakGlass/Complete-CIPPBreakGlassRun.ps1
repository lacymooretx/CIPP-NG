function Complete-CIPPBreakGlassRun {
    <#
    .SYNOPSIS
        Records a break-glass provisioning run, marks the plan and alerts Lacy (email + a CW ticket on the client).
    .DESCRIPTION
        The alert lists the accounts, the group, every CA policy touched, the Keeper record pointers and the
        keys-pending steps for the tech. It never contains a password or a TAP.
        Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Tenant,
        [string]$APIName = 'BreakGlassProvision'
    )
    $R = [pscustomobject]$Result
    $Enc = { param($S) [System.Net.WebUtility]::HtmlEncode([string]$S) }
    $Table = Get-CIPPTable -tablename 'BreakGlassProvision'
    $TenantId = ([string](Get-Tenants -TenantFilter $Tenant | Select-Object -First 1).customerId).ToLower()

    Add-CIPPAzDataTableEntity @Table -Entity @{
        PartitionKey = 'Run'; RowKey = $R.RunId; TenantId = $TenantId; Tenant = $Tenant; Status = $R.Status; ApprovedBy = $R.ApprovedBy
        FinishedUtc = (Get-Date).ToUniversalTime().ToString('o'); ResultJson = (ConvertTo-Json -InputObject $R -Depth 8 -Compress)
    } -Force
    $PlanRow = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Plan' and RowKey eq '$TenantId'"
    if ($PlanRow) {
        $PlanRow.Status = if ($R.Status -eq 'Succeeded') { 'Done' } else { 'Failed' }
        $PlanRow | Add-Member -NotePropertyName LastRunId -NotePropertyValue $R.RunId -Force
        Add-CIPPAzDataTableEntity @Table -Entity $PlanRow -Force
    }

    $Created = @($R.Accounts)
    $Title = if ($R.Status -eq 'Succeeded') { "Break-glass accounts created for $Tenant (keys pending)" }
    elseif ($Created.Count -gt 0) { "Break-glass provisioning for $Tenant needs attention ($($R.Status))" }
    else { "Break-glass provisioning for $Tenant failed before any account was created" }

    $StepsHtml = ($R.Steps | Select-Object Step, Ok, Detail | ConvertTo-Html -Fragment | Out-String)
    $PoliciesHtml = if (@($R.PolicyResults).Count) { ($R.PolicyResults | Select-Object Policy, Result | ConvertTo-Html -Fragment | Out-String) } else { '<p>No Conditional Access policy was touched.</p>' }
    $KeeperHtml = if (@($R.Keeper).Count) { ($R.Keeper | Select-Object UserPrincipalName, Status, KeeperRecordUid, HuduPasswordId | ConvertTo-Html -Fragment | Out-String) } else { '' }
    $Todo = if ($Created.Count) {
        @"
<h3>Tech: finish the keys (the accounts cannot reach the admin portals until this is done)</h3>
<ol>
<li>Have two FIDO2 security keys (or plan two passkeys kept in the Keeper MSP shared folder) ready.</li>
<li>In CIPP, create a Temporary Access Pass for each account below only when you are ready to register (Identity &gt; Users &gt; Create TAP). Do not paste the TAP into the ticket.</li>
<li>Sign in at https://aka.ms/mysecurityinfo as the account with the TAP and register the key. Do not add a phone, Authenticator or OTP method.</li>
<li>Run the posture check (Identity &gt; Administration &gt; Break-glass Accounts &gt; Posture). "No FIDO2" must be gone for both accounts, then close this ticket.</li>
</ol>
<p>Accounts: $((($Created | ForEach-Object { & $Enc $_.UserPrincipalName }) -join ', '))</p>
"@
    } else { '' }
    $Html = "<p>Run $(& $Enc $R.RunId), approved by $(& $Enc $R.ApprovedBy). Status: <b>$(& $Enc $R.Status)</b>. Exclusion group: $(& $Enc $R.GroupId). CA snapshots for rollback: table BreakGlassCASnapshots, PartitionKey $(& $Enc $R.RunId).</p>$StepsHtml<h3>Conditional Access</h3>$PoliciesHtml<h3>Credentials (ControlR / Keeper)</h3>$KeeperHtml$Todo"

    foreach ($Channel in 'email', 'psa') {
        try { $null = Send-CIPPAlert -Type $Channel -Title $Title -HTMLContent $Html -TenantFilter $Tenant -APIName $APIName }
        catch { Write-LogMessage -API $APIName -tenant $Tenant -message "Could not send $Channel alert for '$Title': $($_.Exception.Message)" -Sev 'Warning' }
    }
    Write-LogMessage -API $APIName -tenant $Tenant -message "$Title. Run $($R.RunId)." -Sev 'Info'
    return $R
}
