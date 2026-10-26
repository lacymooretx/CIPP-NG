function Send-CIPPOneDriveSharingDigestMail {
    <#
    .SYNOPSIS
        Sends one OneDrive sharing digest email as the configured sender mailbox.
    .DESCRIPTION
        App-only Graph users/{sender}/sendMail in the sender's tenant (default help@aspendora.com in
        aspendora.com, a shared mailbox, so replies open a help desk ticket). Send-CIPPAlert could not be
        reused: it posts to /me/sendMail on the partner tenant, which can only send as the partner user,
        not as a mailbox in another tenant. Needs the Graph Mail.Send application permission in the
        sender's tenant.

        Not saved to Sent Items, so the help desk mailbox only holds the replies.

        Aspendora fork addition.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Settings,
        [Parameter(Mandatory = $true)][string]$To,
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$Html
    )

    $Body = @{
        message         = @{
            subject      = $Subject
            body         = @{ contentType = 'HTML'; content = $Html }
            toRecipients = @(@{ emailAddress = @{ address = $To } })
            replyTo      = @(@{ emailAddress = @{ address = $Settings.SenderMailbox } })
        }
        saveToSentItems = $false
    }
    $Json = ConvertTo-Json -InputObject $Body -Depth 10 -Compress
    $null = New-GraphPostRequest -uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($Settings.SenderMailbox))/sendMail" -tenantid $Settings.SenderTenant -AsApp $true -type POST -body $Json
}
