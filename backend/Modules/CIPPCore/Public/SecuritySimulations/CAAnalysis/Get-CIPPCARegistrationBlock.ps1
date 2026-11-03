function Get-CIPPCARegistrationBlock {
    <#
    .SYNOPSIS
        Finds the Conditional Access policies that would stop a user registering a passkey in Microsoft Authenticator.
    .DESCRIPTION
        Pure rules, no Graph or table calls. Takes raw Graph or normalized policies.

        Microsoft Learn (how-to-enable-authenticator-passkey, read 2026-11-03) documents two blocking patterns on an
        All resources policy:
          1. an authentication strength requiring phishing-resistant auth. Every allowed combination has to be
             phishing-resistant: a strength that also allows a Temporary Access Pass or other MFA can be met, which is
             Learn's split-policy workaround.
          2. Require approved client app or Require app protection policy. Authenticator supports neither.

        Not a match:
          - a policy that excludes the Authenticator Credential Registration app (returned as AlreadyExcluded);
          - an OR grant with a control the user can meet: mfa, a compliant device (Learn's workaround for MDM-managed
            phones) or a weaker strength (returned as Mitigated). Hybrid join is not counted, a phone cannot have it;
          - block policies, specific-app policies and disabled policies, which are not these patterns;
          - policies that cannot apply to Authenticator on a phone: platforms without Android or iOS, legacy clients
            only, or users set to None.
        Device filters, locations and risk conditions are not evaluated, so a match means the policy can block, not
        that it blocks every sign-in.

        A strength with no combinations available that is not named phishing-resistant cannot be judged and is
        returned as Unverified, never treated as clear.

        Returns Enforced, ReportOnly, AlreadyExcluded, Mitigated, Unverified (rows of Id, DisplayName, State, Pattern,
        UserScope, ExcludeUsers), RegisterSecurityInfoPolicy (Enforced, ReportOnly or Missing),
        RegisterSecurityInfoPolicies (names) and CaWouldBlock:
          Yes        an enforced policy matches
          ReportOnly only report-only policies match, so it starts when one is enforced
          Unknown    nothing matches but a policy could not be judged
          No         nothing matches
        Report only. Aspendora fork addition (Vikunja CIPP-53).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Policies = @(),
        # Strength id -> strength with allowedCombinations, for policies whose grant carries only the id.
        $AuthStrengths,
        [string]$AppId = '6aa00308-ea33-4caa-90d6-ae905d8cb51b'
    )

    $BuiltInPhishingResistant = '00000000-0000-0000-0000-000000000004'
    $PhishingResistantMethods = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor', 'x509CertificateSingleFactor', 'deviceBoundPasskey')
    $RegisterSecurityInfo = 'urn:user:registersecurityinfo'

    $Enforced = [System.Collections.Generic.List[object]]::new()
    $ReportOnly = [System.Collections.Generic.List[object]]::new()
    $AlreadyExcluded = [System.Collections.Generic.List[object]]::new()
    $Mitigated = [System.Collections.Generic.List[object]]::new()
    $Unverified = [System.Collections.Generic.List[object]]::new()
    $RegisterEnforced = [System.Collections.Generic.List[string]]::new()
    $RegisterReportOnly = [System.Collections.Generic.List[string]]::new()

    foreach ($Policy in @($Policies)) {
        if ($null -eq $Policy -or "$($Policy.state)" -notin @('enabled', 'enabledForReportingButNotEnforced')) { continue }
        $IsEnforced = "$($Policy.state)" -eq 'enabled'
        $Apps = $Policy.conditions.applications

        if (@($Apps.includeUserActions) -contains $RegisterSecurityInfo) {
            if ($IsEnforced) { $RegisterEnforced.Add("$($Policy.displayName)") } else { $RegisterReportOnly.Add("$($Policy.displayName)") }
            continue
        }
        if (@($Apps.includeApplications) -notcontains 'All') { continue }

        $Grant = $Policy.grantControls
        $Controls = @($Grant.builtInControls)
        if ($Controls -contains 'block') { continue }

        $Platforms = $Policy.conditions.platforms
        if ($null -ne $Platforms -and @($Platforms.includePlatforms | Where-Object { $_ }).Count -gt 0) {
            $Excluded = @($Platforms.excludePlatforms)
            $Included = @($Platforms.includePlatforms)
            $Reachable = $false
            foreach ($Phone in @('android', 'iOS')) {
                if (($Included -contains 'all' -or $Included -contains $Phone) -and -not ($Excluded -contains $Phone -or $Excluded -contains 'all')) { $Reachable = $true }
            }
            if (-not $Reachable) { continue }
        }

        $ClientTypes = @($Policy.conditions.clientAppTypes | Where-Object { $_ })
        if ($ClientTypes.Count -gt 0 -and -not ($ClientTypes -contains 'all' -or $ClientTypes -contains 'mobileAppsAndDesktopClients' -or $ClientTypes -contains 'browser')) { continue }

        $Users = $Policy.conditions.users
        $IncludeUsers = @($Users.includeUsers | Where-Object { $_ })
        $IncludeGroups = @($Users.includeGroups | Where-Object { $_ })
        $IncludeRoles = @($Users.includeRoles | Where-Object { $_ })
        $IncludesGuests = $null -ne $Users.includeGuestsOrExternalUsers
        if ($IncludeUsers.Count -eq 1 -and $IncludeUsers[0] -eq 'None' -and $IncludeGroups.Count -eq 0 -and $IncludeRoles.Count -eq 0 -and -not $IncludesGuests) { continue }
        $UserScope = if ($IncludeUsers -contains 'All') { 'AllUsers' }
        elseif ($IncludeRoles.Count -gt 0 -and $IncludeUsers.Count -eq 0 -and $IncludeGroups.Count -eq 0 -and -not $IncludesGuests) { 'AdminRoles' }
        else { 'Targeted' }

        # Authentication strength: None, PhishingResistant, Other (can be met) or Unresolved.
        $Strength = $Grant.authenticationStrength
        $StrengthKind = 'None'
        if ($null -ne $Strength) {
            $Combinations = @($Strength.allowedCombinations | Where-Object { $_ })
            if ($Combinations.Count -eq 0 -and $AuthStrengths -and $Strength.id -and $AuthStrengths.ContainsKey("$($Strength.id)")) {
                $Combinations = @($AuthStrengths["$($Strength.id)"].allowedCombinations | Where-Object { $_ })
            }
            if ("$($Strength.id)" -eq $BuiltInPhishingResistant) {
                $StrengthKind = 'PhishingResistant'
            } elseif ($Combinations.Count -gt 0) {
                $StrengthKind = 'PhishingResistant'
                foreach ($Combination in $Combinations) {
                    foreach ($Method in @("$Combination" -split '\s*,\s*')) {
                        if ($PhishingResistantMethods -notcontains $Method) { $StrengthKind = 'Other' }
                    }
                }
            } elseif ("$($Strength.displayName)" -match 'phishing.?resistant') {
                $StrengthKind = 'PhishingResistant'
            } else {
                $StrengthKind = 'Unresolved'
            }
        }

        $Patterns = [System.Collections.Generic.List[string]]::new()
        if ($StrengthKind -eq 'PhishingResistant') { $Patterns.Add('Phishing-resistant authentication strength') }
        if ($Controls -contains 'approvedApplication') { $Patterns.Add('Require approved client app') }
        if ($Controls -contains 'compliantApplication') { $Patterns.Add('Require app protection policy') }

        $Row = [pscustomobject]@{
            Id           = "$($Policy.id)"
            DisplayName  = "$($Policy.displayName)"
            State        = "$($Policy.state)"
            Pattern      = ($Patterns -join ', ')
            UserScope    = $UserScope
            ExcludeUsers = [string[]]@($Users.excludeUsers | Where-Object { $_ })
        }

        $IsAnd = "$($Grant.operator)" -eq 'AND'
        $IsExcluded = @($Apps.excludeApplications) -contains $AppId
        if ($Patterns.Count -eq 0) {
            if ($StrengthKind -eq 'Unresolved' -and -not $IsExcluded) { $Unverified.Add($Row) }
            continue
        }
        if (-not $IsAnd) {
            $CanMeet = $Controls -contains 'mfa' -or $Controls -contains 'compliantDevice' -or $StrengthKind -eq 'Other' -or @($Grant.customAuthenticationFactors | Where-Object { $_ }).Count -gt 0
            if ($CanMeet) { $Mitigated.Add($Row); continue }
        }
        if ($IsExcluded) {
            $AlreadyExcluded.Add($Row)
        } elseif (-not $IsAnd -and $StrengthKind -eq 'Unresolved') {
            $Unverified.Add($Row)
        } elseif ($IsEnforced) {
            $Enforced.Add($Row)
        } else {
            $ReportOnly.Add($Row)
        }
    }

    $Verdict = if ($Enforced.Count -gt 0) { 'Yes' } elseif ($ReportOnly.Count -gt 0) { 'ReportOnly' } elseif ($Unverified.Count -gt 0) { 'Unknown' } else { 'No' }
    $RegisterState = if ($RegisterEnforced.Count -gt 0) { 'Enforced' } elseif ($RegisterReportOnly.Count -gt 0) { 'ReportOnly' } else { 'Missing' }

    [pscustomobject]@{
        CaWouldBlock                 = $Verdict
        Enforced                     = @($Enforced)
        ReportOnly                   = @($ReportOnly)
        AlreadyExcluded              = @($AlreadyExcluded)
        Mitigated                    = @($Mitigated)
        Unverified                   = @($Unverified)
        RegisterSecurityInfoPolicy   = $RegisterState
        RegisterSecurityInfoPolicies = @(@($RegisterEnforced) + @($RegisterReportOnly))
    }
}
