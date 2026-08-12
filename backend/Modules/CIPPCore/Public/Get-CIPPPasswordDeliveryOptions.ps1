function Get-CIPPPasswordDeliveryOptions {
    <#
    .SYNOPSIS
    Resolves the effective password delivery options for a request.

    .DESCRIPTION
    Merges what the caller asked for over the defaults configured on the PwPush
    extension, so the reset dialog can pre-check boxes from configuration while any
    individual run can still override them. Returns an object with every switch
    resolved to a concrete boolean.

    When the PwPush extension is disabled, everything is off: without a push there is
    nothing to deliver.

    Aspendora fork addition.

    .PARAMETER Delivery
    Caller-supplied options. Any property that is absent or null falls back to config.
    #>
    [CmdletBinding()]
    param(
        $Delivery
    )

    $Config = Get-PwPushConfiguration

    $Resolved = [PSCustomObject]@{
        Enabled          = $false
        EmailUser        = $false
        TextUser         = $false
        NotifySupervisor = $false
        DocumentInITGlue = $false
        RecipientEmail   = $null
        RecipientPhone   = $null
        SupervisorEmail  = $null
        SupervisorPhone  = $null
    }

    if (-not $Config) { return $Resolved }

    $Resolved.Enabled = $true
    $Resolved.EmailUser = $Config.DispatchEmailUser -eq $true
    $Resolved.TextUser = $Config.DispatchTextUser -eq $true
    $Resolved.NotifySupervisor = $Config.DispatchSupervisor -eq $true
    $Resolved.DocumentInITGlue = $Config.DocumentInITGlue -eq $true

    if ($Delivery) {
        foreach ($Property in @('EmailUser', 'TextUser', 'NotifySupervisor', 'DocumentInITGlue')) {
            $Value = $Delivery.$Property
            # Cast to string before the empty check. PowerShell coerces the right
            # operand to the left operand's type, so a literal $false compared with
            # '' becomes $false -ne $false -> False, and an explicitly disabled
            # switch was silently discarded in favour of the configured default.
            # That made it impossible to turn a config-enabled channel off per run.
            if ($null -ne $Value -and "$Value" -ne '') { $Resolved.$Property = [bool]$Value }
        }
        # RecipientEmail may arrive as a single override from the dialog or as a list from
        # the API, so normalise to an array either way.
        $OverrideEmails = @($Delivery.RecipientEmail | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
        if ($OverrideEmails.Count -gt 0) { $Resolved.RecipientEmail = $OverrideEmails }

        foreach ($Property in @('RecipientPhone', 'SupervisorEmail', 'SupervisorPhone')) {
            $Value = $Delivery.$Property
            if (![string]::IsNullOrWhiteSpace($Value)) { $Resolved.$Property = $Value }
        }
    }

    return $Resolved
}
