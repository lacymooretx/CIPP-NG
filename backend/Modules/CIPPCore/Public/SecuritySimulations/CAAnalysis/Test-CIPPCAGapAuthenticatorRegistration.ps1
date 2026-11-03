function Test-CIPPCAGapAuthenticatorRegistration {
    <#
    .SYNOPSIS
        Finds policies that stop people registering a passkey in Microsoft Authenticator, enforced and report-only
        separately, and flags a missing Register security info policy.
    .DESCRIPTION
        Get-CIPPCARegistrationBlock decides which policies match Microsoft Learn's two patterns. An enforced match
        is High unless every match is scoped to admin roles (Medium). A report-only match is Medium.

        A missing Register security info policy is Medium when a matching policy exists or the exclusion is already
        in place, because the exclusion then leaves nothing controlling that step. Otherwise it is Low, which the
        gap analysis does not show. Aspendora fork addition (Vikunja CIPP-53).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Context
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $AppId = '6aa00308-ea33-4caa-90d6-ae905d8cb51b'
    $Category = 'Sign-in method registration'
    $LearnUrl = 'https://learn.microsoft.com/entra/identity/authentication/how-to-enable-authenticator-passkey'
    $RegisterUrl = 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-security-info-registration'
    $Fix = 'Provision the Authenticator Credential Registration app (standard AuthenticatorCredentialRegistration), then exclude it from these policies only, never from multifactor, risk or block policies. Microsoft also documents two alternatives: split desktop and mobile into separate policies with a strength that allows a Temporary Access Pass, or add Require compliant device as an alternative for managed phones.'

    $Block = Get-CIPPCARegistrationBlock -Policies @($Context.Policies) -AuthStrengths $Context.AuthStrengths -AppId $AppId

    $Describe = {
        param($Rows)
        @(foreach ($Row in $Rows) {
                $Scope = switch ($Row.UserScope) {
                    'AllUsers' { 'all users' }
                    'AdminRoles' { 'admin roles only' }
                    default { 'selected users or groups' }
                }
                "- $($Row.DisplayName): $($Row.Pattern), $Scope"
            }) -join "`n"
    }

    if ($Block.Enforced.Count -gt 0) {
        $AdminOnly = @($Block.Enforced | Where-Object { $_.UserScope -ne 'AdminRoles' }).Count -eq 0
        $Params = @{
            Severity         = if ($AdminOnly) { 'Medium' } else { 'High' }
            Category         = $Category
            Title            = "$($Block.Enforced.Count) enforced policy(ies) block passkey registration in Microsoft Authenticator"
            Description      = "Microsoft documents that the Authenticator app cannot meet these requirements while registering a passkey, so people in scope cannot finish:`n$(& $Describe $Block.Enforced)`n`nThe built-in phishing-resistant strength does not include a Temporary Access Pass, so a pass does not get them through. From the SMS and voice retirement dates, a person whose only method is SMS or voice has to register a passkey at sign-in, so this can become a lockout."
            Remediation      = $Fix
            AffectedPolicies = @($Block.Enforced.DisplayName)
            DocumentationUrl = $LearnUrl
            RelatedIds       = @($AppId)
        }
        $Findings.Add((New-CIPPCAGapFinding @Params))
    }

    if ($Block.ReportOnly.Count -gt 0) {
        $Params = @{
            Severity         = 'Medium'
            Category         = $Category
            Title            = "$($Block.ReportOnly.Count) report-only policy(ies) would block passkey registration in Microsoft Authenticator once enforced"
            Description      = "These policies change nothing today, but enforcing one as it stands would stop people in scope registering a passkey in the Authenticator app:`n$(& $Describe $Block.ReportOnly)"
            Remediation      = "Before enforcing: $Fix"
            AffectedPolicies = @($Block.ReportOnly.DisplayName)
            DocumentationUrl = $LearnUrl
            RelatedIds       = @($AppId)
        }
        $Findings.Add((New-CIPPCAGapFinding @Params))
    }

    if ($Block.Unverified.Count -gt 0) {
        $Params = @{
            Severity         = 'Medium'
            Category         = $Category
            Title            = 'Could not tell whether these policies block passkey registration in Microsoft Authenticator'
            Description      = "These tenant-wide policies use an authentication strength whose allowed methods were not available, so it could not be judged:`n$(@($Block.Unverified | ForEach-Object { "- $($_.DisplayName)" }) -join "`n")"
            Remediation      = 'Check whether the strength allows anything other than phishing-resistant methods. If it does not, treat the policy as blocking registration.'
            AffectedPolicies = @($Block.Unverified.DisplayName)
            DocumentationUrl = $LearnUrl
            RelatedIds       = @($AppId)
        }
        $Findings.Add((New-CIPPCAGapFinding @Params))
    }

    if ($Block.RegisterSecurityInfoPolicy -ne 'Enforced') {
        $Relevant = ($Block.Enforced.Count + $Block.ReportOnly.Count + $Block.AlreadyExcluded.Count) -gt 0
        $Current = if ($Block.RegisterSecurityInfoPolicy -eq 'ReportOnly') { 'The only policy covering it is report-only, so nothing enforces it.' } else { 'No policy covers it.' }
        $Params = @{
            Severity         = if ($Relevant) { 'Medium' } else { 'Low' }
            Category         = $Category
            Title            = 'Nothing enforces a policy on registering security info'
            Description      = "$Current Excluding the Authenticator registration app from a phishing-resistant policy lets someone reach registration without phishing-resistant sign-in, so someone who phishes a weaker method could register their own passkey. A policy on the Register security info action is what controls that step."
            Remediation      = 'Add a policy for the Register security info user action that people can meet while registering, for example multifactor authentication or a Temporary Access Pass, and try it in report-only first.'
            DocumentationUrl = $RegisterUrl
            RelatedIds       = @($AppId)
        }
        $Findings.Add((New-CIPPCAGapFinding @Params))
    }

    @($Findings)
}
