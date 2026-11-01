function Test-CIPPEnrollmentDiscovery {
    <#
    .SYNOPSIS
        Rules for "is this tenant still relying on CNAME-based Intune enrollment discovery?"
    .DESCRIPTION
        Pure function. Inputs are what Get-CIPPEnrollmentDiscovery read; output is a list of findings, each with a
        stable Id (Category|domain, or Category for tenant-wide findings) so the alert lifecycle ignores wording.

        Background. Windows finds the Intune enrollment service two ways:
          - Entra join / automatic enrollment: the MDM user scope (policies/mobileDeviceManagementPolicies/
            0000000a-...) decides. Scope All enrolls everyone, Selected only members of the included groups,
            None nobody. GPO auto-enrollment of hybrid-joined devices uses the same scope.
          - Manual "Enroll only in device management" / Company Portal sign-in: Windows looks up
            enterpriseenrollment.<UPN suffix> (CNAME to enterpriseenrollment-s.manage.microsoft.com, or the legacy
            enterpriseenrollment.manage.microsoft.com) and enterpriseregistration.<suffix> (CNAME to
            enterpriseregistration.windows.net) for device registration.
        A tenant whose scope is None or a narrow group but which publishes the CNAME is enrolling (some) Windows
        devices through DNS discovery; a tenant using Windows enrollment with a custom domain and no CNAME makes
        manual enrollment fail for users on that suffix.

        Categories (Severity):
          CnameWithScopeNone      (Warning) CNAME published, MDM scope None: DNS is the only Windows enrollment path.
          CnameWithNarrowScope    (Warning) CNAME published, scope Selected: users outside the groups enroll via DNS.
          NoEnrollmentPath        (Warning) Windows devices exist, scope None, no domain has the CNAME.
          CnameMissing            (Warning when scope is not All, else Info) Windows enrollment is in use and a
                                  custom verified domain has no enterpriseenrollment CNAME.
          CnameUnexpectedTarget   (Warning) enterpriseenrollment CNAME points somewhere other than Intune.
          CnameLegacyTarget       (Info) enterpriseenrollment CNAME points at the legacy Intune host (still works).
          RegistrationMissing     (Info) custom domain with the enrollment CNAME but no enterpriseregistration CNAME.
          RegistrationUnexpected  (Warning) enterpriseregistration CNAME points somewhere other than Entra.
          HybridDependsOnScope    (Warning when scope is not All, else Info) hybrid-joined devices enrolled by GPO /
                                  co-management. They re-enroll through the MDM user scope, so taking a user out of
                                  scope (or switching scope to None and relying on the CNAME) breaks them.
          DnsLookupFailed         (Info) a lookup errored; that domain's CNAME state is unknown, not "missing".
        Aspendora fork addition (Vikunja CIPP-22).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # @{ Domain; EnrollmentTarget; RegistrationTarget; LookupError } - targets are '' when no CNAME exists.
        [object[]]$Domains = @(),
        # @{ AppliesTo = 'none'|'all'|'selected'; Groups = @('name', ...) } or $null when it could not be read.
        $MdmScope,
        [int]$WindowsDeviceCount = 0,
        # Hybrid-joined Windows devices: @{ DeviceName; EnrollmentType }
        [object[]]$HybridDevices = @()
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Add = {
        param($Category, $Severity, $Message, $Domain)
        $Findings.Add([pscustomobject]@{
                Id       = if ($Domain) { "$Category|$Domain" } else { $Category }
                Category = $Category
                Severity = $Severity
                Domain   = [string]$Domain
                Message  = $Message
            })
    }

    $Scope = if ($MdmScope) { ([string]$MdmScope.AppliesTo).ToLowerInvariant() } else { '' }
    $ScopeKnown = $Scope -in @('none', 'all', 'selected')
    $Groups = @($MdmScope.Groups | Where-Object { $_ })
    $GroupText = if ($Groups.Count -gt 0) { $Groups -join ', ' } else { 'no groups' }
    $Current = 'enterpriseenrollment-s.manage.microsoft.com'
    $Legacy = 'enterpriseenrollment.manage.microsoft.com'
    $Registration = 'enterpriseregistration.windows.net'

    $Clean = { param($Value) ([string]$Value).Trim().TrimEnd('.').ToLowerInvariant() }
    $Checked = @($Domains | Where-Object { $_ -and -not ($_.LookupError -eq $true) })
    $WithCname = @($Checked | Where-Object { & $Clean $_.EnrollmentTarget })

    foreach ($D in @($Domains | Where-Object { $_.LookupError -eq $true })) {
        & $Add 'DnsLookupFailed' 'Info' "Could not resolve the enrollment CNAMEs for $($D.Domain); its state is unknown this run." $D.Domain
    }

    foreach ($D in $Checked) {
        $Enroll = & $Clean $D.EnrollmentTarget
        $Reg = & $Clean $D.RegistrationTarget
        if ($Enroll) {
            if ($Enroll -eq $Legacy) {
                & $Add 'CnameLegacyTarget' 'Info' "enterpriseenrollment.$($D.Domain) points at the legacy host $Legacy. It still works; Microsoft's current target is $Current." $D.Domain
            } elseif ($Enroll -ne $Current) {
                & $Add 'CnameUnexpectedTarget' 'Warning' "enterpriseenrollment.$($D.Domain) points at $Enroll, not Intune ($Current). Manual Windows enrollment for $($D.Domain) users will fail or go somewhere else." $D.Domain
            }
            if (-not $Reg) {
                & $Add 'RegistrationMissing' 'Info' "$($D.Domain) has the enrollment CNAME but no enterpriseregistration CNAME ($Registration). Device registration discovery for that suffix is incomplete." $D.Domain
            }
        } elseif ($WindowsDeviceCount -gt 0) {
            $Severity = if ($Scope -eq 'all') { 'Info' } else { 'Warning' }
            $Why = if ($Scope -eq 'all') { 'Automatic enrollment covers Entra-joined devices, but manual enrollment (Settings > Access work or school, Company Portal) for users on this suffix needs the record.' } else { 'With the MDM user scope not set to All, manual enrollment is the only path for out-of-scope users, and it needs this record.' }
            & $Add 'CnameMissing' $Severity "$($D.Domain) has no enterpriseenrollment CNAME ($Current). $Why" $D.Domain
        }
        if ($Reg -and $Reg -ne $Registration) {
            & $Add 'RegistrationUnexpected' 'Warning' "enterpriseregistration.$($D.Domain) points at $Reg, not $Registration." $D.Domain
        }
    }

    if ($ScopeKnown -and $WithCname.Count -gt 0) {
        $Names = @($WithCname | ForEach-Object { $_.Domain }) -join ', '
        if ($Scope -eq 'none') {
            & $Add 'CnameWithScopeNone' 'Warning' "MDM user scope is None but the enrollment CNAME is published for $Names. Windows devices can only enroll through DNS discovery (manual enrollment); Entra join and GPO auto-enrollment do not enroll anything. Set the scope to All or a group before removing the CNAME." $null
        } elseif ($Scope -eq 'selected') {
            & $Add 'CnameWithNarrowScope' 'Warning' "MDM user scope is limited to $GroupText while the enrollment CNAME is published for $Names. Users outside those groups can still enroll Windows devices through DNS discovery; check that is intended." $null
        }
    }

    if ($Scope -eq 'none' -and $WindowsDeviceCount -gt 0 -and $WithCname.Count -eq 0 -and $Checked.Count -gt 0) {
        & $Add 'NoEnrollmentPath' 'Warning' "MDM user scope is None and no custom domain publishes the enrollment CNAME, yet $WindowsDeviceCount Windows device(s) are enrolled. New Windows devices have no automatic enrollment path." $null
    }

    $Hybrid = @($HybridDevices | Where-Object { $_ })
    if ($Hybrid.Count -gt 0) {
        $Severity = if ($Scope -eq 'all') { 'Info' } else { 'Warning' }
        $Sample = @($Hybrid | Select-Object -First 5 | ForEach-Object { $_.DeviceName }) -join ', '
        $ScopeText = if ($ScopeKnown) { "Scope is currently $Scope$(if ($Scope -eq 'selected') { " ($GroupText)" })." } else { 'The MDM user scope could not be read.' }
        & $Add 'HybridDependsOnScope' $Severity "$($Hybrid.Count) hybrid-joined Windows device(s) were enrolled by GPO / co-management (e.g. $Sample). They enroll through the MDM user scope, not DNS: keep their users in scope before narrowing it. $ScopeText" $null
    }

    return $Findings.ToArray()
}
