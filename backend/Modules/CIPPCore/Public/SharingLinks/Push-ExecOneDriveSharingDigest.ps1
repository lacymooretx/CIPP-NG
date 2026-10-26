function Push-ExecOneDriveSharingDigest {
    <#
    .SYNOPSIS
        Emails each user in a tenant the sharing links in their OneDrive (the weekly OneDrive sharing digest).
    .DESCRIPTION
        Schedulable command. Builds the digest from the sharing-links cache (Get-CIPPOneDriveSharingDigest),
        renders each user's email (New-CIPPOneDriveSharingDigestHtml) and sends it as the configured sender
        mailbox (default help@aspendora.com in aspendora.com) with app-only Graph, so replies reach the
        help desk.

        Preview first: a tenant only mails its own users once it has been approved
        (ExecOneDriveSharingDigest Action=Approve). Until then every
        user's digest goes to the preview recipient instead, with the real recipient in the subject.

        Live sends are refused when the last completed sharing-links scan is older than MaxScanAgeDays, so
        nobody is told about links they removed weeks ago. Schedule the SharePointSharingLinks cache refresh
        to run before this.

        Schedule via POST /api/AddScheduledItem, command 'Push-ExecOneDriveSharingDigest',
        parameters { TenantFilter }.

        Aspendora fork addition.
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        # Send every digest to this address instead of the users, whatever the tenant's approval.
        [string]$PreviewRecipient,
        # Only send for these users (UPN or mail). Empty means everyone with shared items.
        [string[]]$OnlyUsers,
        # Stop after this many emails. 0 means no limit.
        [int]$MaxEmails = 0,
        [int]$MaxScanAgeDays = 8,
        # Render and report, send nothing.
        [bool]$DryRun = $false
    )

    $Settings = Get-CIPPOneDriveSharingDigestSettings -TenantFilter $TenantFilter
    $Live = $Settings.Live -and [string]::IsNullOrWhiteSpace($PreviewRecipient)
    $PreviewTo = if ($PreviewRecipient) { $PreviewRecipient } else { $Settings.PreviewRecipient }

    $Digest = Get-CIPPOneDriveSharingDigest -TenantFilter $TenantFilter
    $Tenant = @(Get-Tenants -TenantFilter $TenantFilter -IncludeErrors)[0]
    $CompanyName = if ($Tenant.displayName) { [string]$Tenant.displayName } else { $TenantFilter }

    $ScanAge = if ($Digest.LastScanUtc) { [DateTimeOffset]::UtcNow - $Digest.LastScanUtc } else { $null }
    if ($Live -and (-not $ScanAge -or $ScanAge.TotalDays -gt $MaxScanAgeDays)) {
        $Message = "OneDrive sharing digest not sent for $TenantFilter`: the last sharing-links scan $(if ($ScanAge) { "finished $([int]$ScanAge.TotalDays) days ago" } else { 'never completed' }) (limit $MaxScanAgeDays days). Refresh the SharePointSharingLinks cache first."
        Write-LogMessage -API 'OneDriveSharingDigest' -tenant $TenantFilter -message $Message -sev Warning
        return [PSCustomObject]@{ Results = $Message; Sent = 0; Skipped = @(); Failed = @() }
    }

    $Users = @($Digest.Users)
    if ($OnlyUsers) {
        $Users = @($Users | Where-Object { $_.UPN -in $OnlyUsers -or $_.Mail -in $OnlyUsers })
    }

    $Sent = [System.Collections.Generic.List[string]]::new()
    $Skipped = [System.Collections.Generic.List[string]]::new()
    $Failed = [System.Collections.Generic.List[string]]::new()
    $Rendered = [System.Collections.Generic.List[object]]::new()

    foreach ($User in $Users) {
        if ($MaxEmails -gt 0 -and $Sent.Count -ge $MaxEmails) { $Skipped.Add("$($User.UPN): MaxEmails reached"); continue }
        if (-not $User.AccountEnabled) { $Skipped.Add("$($User.UPN): account disabled"); continue }
        if ([string]::IsNullOrWhiteSpace($User.Mail)) { $Skipped.Add("$($User.UPN): no mailbox"); continue }

        $Email = New-CIPPOneDriveSharingDigestHtml -User $User -CompanyName $CompanyName -SupportEmail $Settings.SenderMailbox
        $To = if ($Live) { $User.Mail } else { $PreviewTo }
        $Subject = if ($Live) { $Email.Subject } else { "[Preview for $($User.Mail)] $($Email.Subject)" }
        $Rendered.Add([PSCustomObject]@{ User = $User.UPN; To = $To; Subject = $Subject; Outside = @($User.Outside).Count; Inside = @($User.Inside).Count; Html = $Email.Html })

        if ($DryRun -or -not $PSCmdlet.ShouldProcess($To, "Send OneDrive sharing digest for $($User.UPN)")) { continue }
        try {
            Send-CIPPOneDriveSharingDigestMail -Settings $Settings -To $To -Subject $Subject -Html $Email.Html
            $Sent.Add("$($User.UPN) -> $To")
            # Exchange Online allows 30 messages a minute from one mailbox.
            Start-Sleep -Milliseconds 2100
        } catch {
            $ErrorMessage = Get-CippException -Exception $_
            $Failed.Add("$($User.UPN): $($ErrorMessage.NormalizedError)")
        }
    }

    $Mode = if ($DryRun) { 'dry run' } elseif ($Live) { 'live' } else { "preview to $PreviewTo" }
    $Summary = "OneDrive sharing digest ($Mode) for $TenantFilter`: $($Sent.Count) sent, $($Skipped.Count) skipped, $($Failed.Count) failed, $(@($Digest.Unresolved).Count) OneDrive(s) with no resolvable owner."
    $Severity = if ($Failed.Count -gt 0) { 'Warning' } else { 'Info' }
    Write-LogMessage -API 'OneDriveSharingDigest' -tenant $TenantFilter -message $Summary -sev $Severity -LogData @{ Sent = @($Sent); Skipped = @($Skipped); Failed = @($Failed) }

    return [PSCustomObject]@{
        Results     = $Summary
        Mode        = $Mode
        LastScanUtc = $Digest.LastScanUtc
        Sent        = @($Sent)
        Skipped     = @($Skipped)
        Failed      = @($Failed)
        Unresolved  = @($Digest.Unresolved)
        # Rendered bodies only on a dry run: scheduler results are stored in a table row.
        Emails      = if ($DryRun) { @($Rendered) } else { @($Rendered | Select-Object -Property User, To, Subject, Outside, Inside) }
    }
}
