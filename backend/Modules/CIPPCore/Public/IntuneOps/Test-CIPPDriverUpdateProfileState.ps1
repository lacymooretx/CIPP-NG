function Test-CIPPDriverUpdateProfileState {
    <#
    .SYNOPSIS
        Decides whether a tenant's Windows driver update profiles match the DriverUpdateProfile standard, and what
        remediation would do.
    .DESCRIPTION
        Pure function, used by Invoke-CIPPStandardDriverUpdateProfile for report, alert and remediate alike.
          - A profile whose displayName equals ProfileName (case-insensitive) is the managed one.
              approvalType differs     -> Action ApprovalTypeMismatch (not compliant). Intune does not allow the
                                          approval method of an existing profile to change, so remediation only
                                          logs it; recreate the profile by hand.
              automatic, deferral off  -> Action UpdateDeferral (not compliant; remediation PATCHes the deferral).
              otherwise                -> Action None (compliant).
          - No such profile:
              AcceptAutopatch and the tenant has a Windows Autopatch driver profile (description "created by
              Windows Autopatch")      -> Action AutopatchManaged (compliant). Autopatch owns driver approval
                                          there; a second, competing profile would only confuse it.
              otherwise                -> Action Create (not compliant; remediation creates it, unassigned).
        Aspendora fork addition (Vikunja CIPP-24).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [object[]]$Profiles = @(),
        [Parameter(Mandatory)][string]$ProfileName,
        [ValidateSet('automatic', 'manual')][string]$ApprovalType = 'automatic',
        [int]$DeferralDays = 7,
        [bool]$AcceptAutopatch = $true
    )

    $Profiles = @($Profiles | Where-Object { $_ -and $_.id })
    $Autopatch = @($Profiles | Where-Object { [string]$_.description -match 'created by Windows Autopatch' })
    $Match = $Profiles | Where-Object { ([string]$_.displayName).Trim() -ieq $ProfileName.Trim() } | Select-Object -First 1
    $ExpectedDeferral = if ($ApprovalType -eq 'automatic') { $DeferralDays } else { $null }

    $Action = 'None'
    if ($Match) {
        $CurrentType = ([string]$Match.approvalType).ToLowerInvariant()
        if ($CurrentType -ne $ApprovalType) {
            $Action = 'ApprovalTypeMismatch'
        } elseif ($ApprovalType -eq 'automatic' -and [int]$Match.deploymentDeferralInDays -ne $DeferralDays) {
            $Action = 'UpdateDeferral'
        }
    } elseif ($AcceptAutopatch -and $Autopatch.Count -gt 0) {
        $Action = 'AutopatchManaged'
    } else {
        $Action = 'Create'
    }

    [pscustomobject]@{
        Compliant         = $Action -in @('None', 'AutopatchManaged')
        Action            = $Action
        ProfileId         = if ($Match) { [string]$Match.id } else { '' }
        CurrentType       = if ($Match) { [string]$Match.approvalType } else { '' }
        CurrentDeferral   = if ($Match) { $Match.deploymentDeferralInDays } else { $null }
        ExpectedType      = $ApprovalType
        ExpectedDeferral  = $ExpectedDeferral
        AutopatchProfiles = @($Autopatch | ForEach-Object { [string]$_.displayName })
        OtherProfiles     = @($Profiles | Where-Object { $_ -ne $Match } | ForEach-Object { [string]$_.displayName })
    }
}
