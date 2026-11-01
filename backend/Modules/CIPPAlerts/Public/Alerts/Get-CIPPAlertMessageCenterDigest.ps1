function Get-CIPPAlertMessageCenterDigest {
    <#
    .SYNOPSIS
        Weekly MSP digest of actionable Microsoft 365 Message Center posts, deduplicated across tenants
    .DESCRIPTION
        Uses Get-CIPPMessageCenterDigest (cached MessageCenterMessages) and raises only the alerting categories:
        Action required / deadline, Retirement and Security / compliance. Informational, opt-in and default-change
        posts never alert; they stay visible on Tenant > Reports > Message Center Digest.

        Scope. Run on the partner tenant (the CIPP app's home tenant, customerId = $env:TenantID), it digests EVERY
        managed tenant in one run, so one post reaching 9 tenants is one row listing the 9 tenants, and the week's
        posts arrive in one email. Run on any other tenant it digests only that tenant, unless MCDigestAllTenants is
        on. Do not schedule it on All Tenants with MCDigestAllTenants on: every tenant would send the same digest.

        State mode, one row per post:
          Id 'MC|<MC id>'      the post is new or updated within MCDigestLookbackDays (default 7), or its deadline is
                               still ahead. A post with a deadline therefore stays open, without re-notifying, until
                               the deadline passes.
          Id 'MC|<MC id>|due'  replaces the row above once the deadline is MCDigestDeadlineDays (default 30) or fewer
                               away, so a deadline posted months ahead notifies a second time as it comes due.
        Priority is DUE IN n DAYS / OVERDUE for deadline items. Each row carries the MC id, title, deadline, days left,
        tenants and admin center link: enough to raise a PSA ticket or task later. Nothing is created here.
        Aspendora fork addition (Vikunja CIPP-37).
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
    $DeadlineDays = 30
    $LookbackDays = 7
    $Parsed = 0
    if ($null -ne $InputValue.MCDigestDeadlineDays -and [int]::TryParse([string]$InputValue.MCDigestDeadlineDays, [ref]$Parsed) -and $Parsed -ge 0) { $DeadlineDays = $Parsed }
    if ($null -ne $InputValue.MCDigestLookbackDays -and [int]::TryParse([string]$InputValue.MCDigestLookbackDays, [ref]$Parsed) -and $Parsed -ge 1) { $LookbackDays = $Parsed }
    $ForceAll = ConvertTo-CIPPBoolean $InputValue.MCDigestAllTenants

    $IsPartner = $false
    if (-not [string]::IsNullOrWhiteSpace($env:TenantID)) {
        $Tenant = Get-Tenants -TenantFilter $TenantFilter -IncludeErrors | Select-Object -First 1
        $IsPartner = $TenantFilter -eq $env:TenantID -or ($Tenant -and [string]$Tenant.customerId -eq $env:TenantID)
    }
    $Scope = if ($IsPartner -or $ForceAll) { 'AllTenants' } else { [string]$TenantFilter }

    try {
        $Digest = Get-CIPPMessageCenterDigest -TenantFilter $Scope -Days $LookbackDays -DeadlineDays $DeadlineDays -IncludeOpenDeadlines
    } catch {
        # Could not read = not checked. Returning without Write-AlertTrace keeps every open row open.
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Message Center digest: could not read posts: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
        return
    }

    $Rows = foreach ($Item in @($Digest.Items | Where-Object { $_.Notify })) {
        $Priority = if ($Item.DeadlineStatus -eq 'Overdue') { 'OVERDUE' }
        elseif ($Item.DueSoon) { if ($Item.DaysLeft -eq 0) { 'DUE TODAY' } else { "DUE IN $($Item.DaysLeft) DAYS" } }
        else { '' }
        $Due = if ($Item.Deadline) { " Act by $($Item.Deadline) (US Central)." } else { '' }
        $Lead = if ($Priority) { "[$Priority] " } else { '' }
        [pscustomobject]@{
            Id          = if ($Item.DueSoon) { "MC|$($Item.MessageId)|due" } else { "MC|$($Item.MessageId)" }
            Priority    = $Priority
            Category    = $Item.CategoryLabel
            MessageId   = $Item.MessageId
            Title       = $Item.Title
            Deadline    = $Item.Deadline
            DaysLeft    = $Item.DaysLeft
            TenantCount = $Item.TenantCount
            Tenants     = $Item.TenantsText
            Services    = $Item.Services
            Status      = $Item.WindowReason
            Reasons     = $Item.Reasons
            Link        = $Item.Link
            Message     = "$Lead$($Item.MessageId) $($Item.Title).$Due $($Item.CategoryLabel); $($Item.TenantCount) tenant(s): $($Item.TenantsText). $($Item.Link)"
        }
    }
    # Deadline items first: the email is read top-down.
    $Rows = @($Rows | Where-Object { $_ } | Sort-Object -Property @(
            @{ Expression = { if ($_.Priority) { 0 } else { 1 } } }
            @{ Expression = { if ($null -eq $_.DaysLeft) { [int]::MaxValue } else { [int]$_.DaysLeft } } }
        ))
    Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
}
