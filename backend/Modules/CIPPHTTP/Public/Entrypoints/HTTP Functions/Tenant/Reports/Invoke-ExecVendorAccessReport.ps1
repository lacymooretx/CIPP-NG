function Invoke-ExecVendorAccessReport {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Application.ReadWrite
    .SYNOPSIS
        Vendor Access weekly email: preview, send now, and settings
    .DESCRIPTION
        Action Preview returns the email HTML for the saved snapshot. Action Send rebuilds the snapshot for all tenants
        and emails it now (to Recipient, or the saved recipient). Action Settings saves Recipient and Enabled for the
        weekly Monday 07:00 US Central email. Action GetSettings returns them with the last weekly sends. Action Reset
        clears the saved snapshot (not the settings or send history), so the next build is a fresh baseline with
        nothing reported as new or removed: use it after a change to what the report lists.
        Aspendora fork addition (Vendor Access).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # Preview, Send, Settings, GetSettings or Reset.
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action)
    # Email address for Send or Settings.
    $Recipient = [string]($Request.Body.Recipient ?? $Request.Query.Recipient)
    # Settings only: whether the weekly email is sent.
    $Enabled = $Request.Body.Enabled
    # Settings only: drop the saved recipient so the email follows CIPP's notification address.
    $ClearRecipient = $Request.Body.ClearRecipient -eq $true
    # Send only: mail the saved snapshot instead of rebuilding it first.
    $SkipRefresh = $Request.Body.SkipRefresh -eq $true
    $Table = Get-CIPPTable -TableName 'CippVendorAccess'

    try {
        switch ($Action) {
            'Preview' {
                $Snapshot = Get-CIPPVendorAccessSnapshot -TenantFilter 'AllTenants'
                $Body = @{ Results = 'Preview'; Html = (New-CIPPVendorAccessHtml -Snapshot $Snapshot); Summary = $Snapshot.Summary }
            }
            'Send' {
                if ($Recipient -and $Recipient -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw 'Recipient must be an email address' }
                $Result = Send-CIPPVendorAccessReport -Recipient $Recipient -SkipRefresh:$SkipRefresh
                Write-LogMessage -headers $Headers -API $APIName -tenant 'Global' -message "Vendor access report sent to $($Result.Recipient)" -Sev 'Info'
                $Body = @{ Results = "Sent '$($Result.Subject)' to $($Result.Recipient)"; Summary = $Result.Summary }
            }
            'Settings' {
                if ($Recipient -and $Recipient -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw 'Recipient must be an email address' }
                $Current = try { Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Settings' and RowKey eq 'Weekly'" } catch { $null }
                $Entity = @{
                    PartitionKey = 'Settings'
                    RowKey       = 'Weekly'
                    # ClearRecipient goes back to CIPP's notification address (no saved recipient).
                    Recipient    = if ($ClearRecipient) { '' } elseif ($Recipient) { $Recipient } elseif ($Current.Recipient) { [string]$Current.Recipient } else { '' }
                    Enabled      = if ($null -ne $Enabled) { [bool]($Enabled -eq $true) } elseif ($null -ne $Current.Enabled) { [bool]$Current.Enabled } else { $true }
                }
                Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force | Out-Null
                Write-LogMessage -headers $Headers -API $APIName -tenant 'Global' -message "Vendor access weekly email: recipient $($Entity.Recipient), enabled $($Entity.Enabled)" -Sev 'Info'
                $To = if ($Entity.Recipient) { $Entity.Recipient } else { "CIPP's notification address ($(Get-CIPPDefaultReportRecipient))" }
                $Body = @{ Results = "Saved: weekly email to $To is $(if ($Entity.Enabled) { 'on' } else { 'off' })" }
            }
            'Reset' {
                $Rows = @(Get-CIPPAzDataTableEntity @Table | Where-Object { $_.PartitionKey -notin @('Settings', 'Weekly') })
                foreach ($Row in $Rows) { Remove-CIPPAzDataTableEntity @Table -Entity ($Row | Select-Object PartitionKey, RowKey, ETag) -Force | Out-Null }
                Write-LogMessage -headers $Headers -API $APIName -tenant 'Global' -message "Vendor access snapshot reset ($($Rows.Count) rows)" -Sev 'Info'
                $Body = @{ Results = "Cleared $($Rows.Count) snapshot rows. The next build is a new baseline." }
            }
            'GetSettings' {
                $Current = try { Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Settings' and RowKey eq 'Weekly'" } catch { $null }
                $Sends = @(try { Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Weekly'" } catch { @() }) | Sort-Object RowKey -Descending | Select-Object -First 8 | ForEach-Object {
                    [pscustomobject]@{ Day = $_.RowKey; Status = $_.Status; SentAt = $_.SentAt; Recipient = $_.Recipient; Error = $_.Error }
                }
                $Default = Get-CIPPDefaultReportRecipient
                $Body = @{
                    # Recipient is what the email actually goes to; SavedRecipient is '' when it follows the default.
                    Recipient        = if ($Current.Recipient -like '*@*') { [string]$Current.Recipient } else { $Default }
                    SavedRecipient   = if ($Current.Recipient -like '*@*') { [string]$Current.Recipient } else { '' }
                    DefaultRecipient = $Default
                    Enabled   = if ($null -ne $Current.Enabled) { [bool]$Current.Enabled } else { $true }
                    Schedule  = 'Mondays 07:00 US Central'
                    Sends     = @($Sends)
                }
            }
            default { throw "Unknown Action '$Action'. Use Preview, Send, Settings, GetSettings or Reset." }
        }
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant 'Global' -message "Vendor access report action $Action failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::BadRequest
        $Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
