function New-PwPushSecret {
    <#
    .SYNOPSIS
    Creates a Password Pusher push and optionally dispatches the link to the recipient.

    .DESCRIPTION
    Creates the push through the raw API (POST /p.json) so the inline `dispatch` object
    can ride along, which makes creation and delivery a single call. Password Pusher
    itself sends the email (SMTP2GO) and SMS (Clerk Chat) server-side.

    Returns an object describing the push and every delivery that was queued. Never
    throws for a dispatch problem: a failure to text somebody must not fail the
    password reset that produced the secret.

    Aspendora fork addition.

    .PARAMETER Payload
    The secret to push.

    .PARAMETER Name
    Optional label shown in the Password Pusher dashboard and audit log.

    .PARAMETER Emails
    Recipient email address(es).

    .PARAMETER Phones
    Recipient mobile number(s). Human formats are normalised to E.164 by the server.

    .PARAMETER SupervisorEmail
    Optional manager email. Receives the SAME secret link, and their view counts.

    .PARAMETER SupervisorPhone
    Optional manager mobile. Receives the SAME secret link, and their view counts.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Payload,

        [string]$Name,

        [string[]]$Emails,

        [string[]]$Phones,

        [string]$SupervisorEmail,

        [string]$SupervisorPhone
    )

    $Configuration = Get-PwPushConfiguration
    if (-not $Configuration) {
        return [PSCustomObject]@{
            Success    = $false
            Link       = $null
            UrlToken   = $null
            Dispatched = $false
            Queued     = 0
            Errors     = @('PwPush is not enabled or configured.')
            Deliveries = @()
        }
    }

    # Anything we hand an address or number to is a potential viewer, and every view
    # counts against expire_after_views. Size the budget for all of them plus one, so a
    # recipient who fumbles the first open is not locked out by the supervisor's copy.
    $Destinations = @()
    $Destinations += @($Emails | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
    $Destinations += @($Phones | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
    if (![string]::IsNullOrWhiteSpace($SupervisorEmail)) { $Destinations += $SupervisorEmail }
    if (![string]::IsNullOrWhiteSpace($SupervisorPhone)) { $Destinations += $SupervisorPhone }
    $Dispatching = $Destinations.Count -gt 0

    $PushBody = @{ payload = $Payload }
    if (![string]::IsNullOrWhiteSpace($Name)) { $PushBody['name'] = $Name }
    if ($Configuration.ExpireAfterDays) { $PushBody['expire_after_days'] = [int]$Configuration.ExpireAfterDays }
    if ($Configuration.DeletableByViewer -eq $true) { $PushBody['deletable_by_viewer'] = $true }
    if (![string]::IsNullOrEmpty($Configuration.DefaultPassphrase)) { $PushBody['passphrase'] = $Configuration.DefaultPassphrase }
    if ($Configuration.AccountId.value) { $PushBody['account_id'] = $Configuration.AccountId.value }

    $ConfiguredViews = if ($Configuration.ExpireAfterViews) { [int]$Configuration.ExpireAfterViews } else { 0 }
    if ($Dispatching) {
        $RequiredViews = $Destinations.Count + 1
        $PushBody['expire_after_views'] = [Math]::Max($ConfiguredViews, $RequiredViews)
        # Link scanners in Outlook and Teams follow URLs in transit. Without the
        # retrieval step they burn the view before the human ever clicks.
        $PushBody['retrieval_step'] = $true
    } else {
        if ($ConfiguredViews -gt 0) { $PushBody['expire_after_views'] = $ConfiguredViews }
        if ($Configuration.RetrievalStep -eq $true) { $PushBody['retrieval_step'] = $true }
    }

    $Body = @{ password = $PushBody }

    if ($Dispatching) {
        $Dispatch = @{}
        $CleanEmails = @($Emails | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
        $CleanPhones = @($Phones | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
        if ($CleanEmails.Count -gt 0) { $Dispatch['emails'] = $CleanEmails }
        if ($CleanPhones.Count -gt 0) { $Dispatch['phones'] = $CleanPhones }
        if (![string]::IsNullOrWhiteSpace($SupervisorEmail)) { $Dispatch['supervisor_email'] = $SupervisorEmail }
        if (![string]::IsNullOrWhiteSpace($SupervisorPhone)) { $Dispatch['supervisor_phone'] = $SupervisorPhone }
        $Body['dispatch'] = $Dispatch
    }

    try {
        if ($PSCmdlet.ShouldProcess('Create a new PwPush secret')) {
            $Response = Invoke-PwPushRequest -Path '/p.json' -Method POST -Body $Body -Configuration $Configuration
        } else {
            return $null
        }
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogMessage -API 'PwPush' -message "Failed to create a PwPush secret: $ErrorMessage" -Sev 'Error'
        return [PSCustomObject]@{
            Success    = $false
            Link       = $null
            UrlToken   = $null
            Dispatched = $false
            Queued     = 0
            Errors     = @("Failed to create the PwPush link: $ErrorMessage")
            Deliveries = @()
        }
    }

    $DispatchErrors = @()
    $Deliveries = @()
    $Queued = 0
    if ($Response.dispatch) {
        $Queued = [int]$Response.dispatch.queued
        if ($Response.dispatch.errors) { $DispatchErrors = @($Response.dispatch.errors) }
        if ($Response.dispatch.dispatches) { $Deliveries = @($Response.dispatch.dispatches) }
    } elseif ($Dispatching) {
        $DispatchErrors = @('PwPush accepted the push but returned no dispatch result. Check that dispatch is enabled on the instance and that the API user owns the push.')
    }

    foreach ($DispatchError in $DispatchErrors) {
        Write-LogMessage -API 'PwPush' -message "PwPush refused a delivery: $DispatchError" -Sev 'Warning'
    }

    return [PSCustomObject]@{
        Success    = $true
        Link       = $Response.html_url
        UrlToken   = $Response.url_token
        Dispatched = ($Queued -gt 0)
        Queued     = $Queued
        Errors     = $DispatchErrors
        Deliveries = $Deliveries
    }
}
