function Get-PwPushDispatchStatus {
    <#
    .SYNOPSIS
    Reads the delivery log for a push, optionally waiting for the queue to drain.

    .DESCRIPTION
    Dispatch is asynchronous: the create call returns every row as `pending` and a
    background job does the sending. This polls GET /p/<token>/dispatches.json so the
    tech is told whether the text actually left the building, rather than only that it
    was queued.

    Deliberately short-lived. If the queue has not drained within the timeout the rows
    are returned as they stand -- a slow provider must not hold up an HTTP response.

    Aspendora fork addition.

    .PARAMETER UrlToken
    The push's url_token.

    .PARAMETER TimeoutSeconds
    How long to wait for every row to leave `pending`. 0 returns immediately.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UrlToken,

        [int]$TimeoutSeconds = 6
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $Deliveries = @()

    do {
        try {
            $Response = Invoke-PwPushRequest -Path "/p/$UrlToken/dispatches.json" -Method GET
            $Deliveries = @($Response.dispatches)
        } catch {
            Write-LogMessage -API 'PwPush' -message "Could not read the PwPush delivery log for $($UrlToken): $($_.Exception.Message)" -Sev 'Warning'
            return $Deliveries
        }

        $Pending = @($Deliveries | Where-Object { $_.status -eq 'pending' })
        if ($Pending.Count -eq 0) { break }

        if ((Get-Date) -lt $Deadline) { Start-Sleep -Seconds 2 }
    } while ((Get-Date) -lt $Deadline)

    return $Deliveries
}
