function Get-CIPPAlertSmsMfaReliance {
    <#
    .SYNOPSIS
        Weekly check of reliance on SMS/voice MFA, and of Authenticator/passkey coverage regressing
    .DESCRIPTION
        Runs Get-CIPPSmsMfaReadiness and raises its Error and Warning findings, one row per admin and one
        consolidated row per tenant-wide problem: admins whose only MFA is SMS/voice or who have none (Error), admins
        defaulting to SMS/voice, users relying only on SMS/voice, licensed users with no MFA, SMS already disabled
        while users still depend on it (Warning).

        Coverage regression: the share of enabled users with Microsoft Authenticator, a passkey/FIDO2 key, Windows
        Hello or a Platform Credential is compared with the best value seen (table SmsMfaReadiness, PartitionKey
        'Coverage'). A drop of more than SmsCoverageDropPercent points (default 5) raises CoverageRegressed. The first
        run only records the baseline. The baseline ratchets up as coverage improves; a drop that persists for 28
        days becomes the new baseline, so a permanent change (e.g. staff leaving) stops being reported.

        SMS/voice retirement (CIPP-46): every row carries RetirementDate and DaysRemaining (US Central) where one
        applies, and one row 'SmsRetirementDeadline|<date>' (Error for 2027-02-01, Warning for 2027-07-01) is raised
        while the nearest retirement date that still has phone-only accounts is within SmsRetirementWarnDays
        (default 90) - or has passed with accounts still on SMS/voice.

        Each row has a stable Id, so the lifecycle notifies once per problem and resolves it when fixed; counts in
        the message do not re-notify. A run with collection errors does not report, because "could not check" is
        not "clear". Report only: nothing in the tenant is changed. Aspendora fork addition (Vikunja CIPP-6).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )
    try {
        $Report = Get-CIPPSmsMfaReadiness -TenantFilter $TenantFilter
        if (@($Report.Errors).Count -gt 0 -or -not $Report.Summary) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "SMS/voice MFA reliance: skipped reporting, could not read everything: $(@($Report.Errors) -join '; ')" -sev Warning
            return
        }
        Save-CIPPSmsMfaReadinessSummary -TenantFilter $TenantFilter -Report $Report

        # Retirement date per user (CIPP-46), to date the per-admin and per-tenant rows below.
        $UserDates = @{}
        foreach ($U in @($Report.Users)) {
            if ($U.Id -and $U.RetirementDate) { $UserDates[[string]$U.Id] = $U }
        }
        $PhoneOnlyDates = @($Report.Users | Where-Object { $_.Category -eq 'PhoneOnly' -and -not $_.IsAdmin -and $_.RetirementDate } | Sort-Object RetirementDate)

        $Rows = [System.Collections.Generic.List[object]]::new()
        foreach ($F in @($Report.Findings | Where-Object { $_.Severity -in @('Error', 'Warning') })) {
            # The SmsRetirement* findings are covered by the single deadline row below, which only fires inside the
            # warning window; raising them here as well would notify every tenant with phone-only users on the day
            # this shipped, duplicating PhoneOnlyUsers.
            if ([string]$F.Key -like 'SmsRetirement*') { continue }
            $Dated = $null
            $Key = [string]$F.Key
            if ($Key.Contains('|')) { $Dated = $UserDates[$Key.Substring($Key.IndexOf('|') + 1)] }
            elseif ($Key -in @('PhoneOnlyUsers', 'SmsOffUsersDependent') -and $PhoneOnlyDates.Count -gt 0) { $Dated = $PhoneOnlyDates[0] }
            # Account, not UserPrincipalName: the lifecycle hashes UserPrincipalName before Id, which would merge
            # two findings about the same admin. RetirementDate/DaysRemaining are extra columns only: the lifecycle
            # hashes Id, so the weekly countdown does not re-notify existing rows.
            $Rows.Add([pscustomobject]@{
                    Id             = $F.Key
                    Severity       = $F.Severity
                    Check          = $F.Check
                    Account        = $F.Account
                    Message        = $F.Message
                    Fix            = $F.Fix
                    RetirementDate = if ($Dated) { [string]$Dated.RetirementDate } else { '' }
                    DaysRemaining  = if ($Dated) { $Dated.DaysRemaining } else { $null }
                })
        }

        # --- Retirement deadline (CIPP-46) ---
        # One row per tenant while the nearest retirement date that still has phone-only accounts is within
        # SmsRetirementWarnDays (default 90). Id = 'SmsRetirementDeadline|<date>': stable for the whole run-up to
        # one date (count and days change weekly without re-notifying), resolves when those accounts are fixed,
        # and gives the July date its own notification once February is clear.
        $WarnDays = 90
        $RawDays = $InputValue.SmsRetirementWarnDays
        if ($null -ne $RawDays -and [string]$RawDays -ne '') {
            $ParsedDays = 0
            if ([int]::TryParse([string]$RawDays, [System.Globalization.NumberStyles]::Integer, [cultureinfo]::InvariantCulture, [ref]$ParsedDays) -and $ParsedDays -gt 0) { $WarnDays = $ParsedDays }
        }
        $S = $Report.Summary
        if ($S.NearestDeadline -and $null -ne $S.NearestDeadlineDaysRemaining -and [int]$S.NearestDeadlineDaysRemaining -le $WarnDays) {
            $DaysLeft = [int]$S.NearestDeadlineDaysRemaining
            $IsFeb = [string]$S.NearestDeadline -eq '2027-02-01'
            $Who = if ($IsFeb) { 'account(s)' } else { 'Global Administrator or external account(s)' }
            $When = if ($DaysLeft -gt 0) { "in $DaysLeft day(s), on $($S.NearestDeadline)" } elseif ($DaysLeft -eq 0) { "today, $($S.NearestDeadline)" } else { "since $($S.NearestDeadline) ($(-$DaysLeft) day(s) ago)" }
            $Context = @(
                "opt-out $($S.PasskeyDynamicMigrationOptOut)"
                "registration campaign $($S.RegistrationCampaignState)$(if ($S.RegistrationCampaignMethods) { " ($($S.RegistrationCampaignMethods))" })"
                "passkeys $($S.PasskeyState)"
            ) -join ', '
            $Rows.Add([pscustomobject]@{
                    Id             = "SmsRetirementDeadline|$($S.NearestDeadline)"
                    Severity       = if ($IsFeb) { 'Error' } else { 'Warning' }
                    Check          = 'SMS/voice retirement deadline'
                    Account        = ''
                    Message        = "$($S.NearestDeadlineUsers) $Who whose only MFA method is SMS/voice get a blocking passkey registration at sign-in $When. Tenant: $Context."
                    Fix            = 'Open Identity > Reports > SMS/Voice MFA Readiness for the list, and get each user onto a passkey or Windows Hello before the date.'
                    RetirementDate = [string]$S.NearestDeadline
                    DaysRemaining  = $DaysLeft
                })
        }

        # --- Coverage regression ---
        $Drop = 5
        $Raw = $InputValue.SmsCoverageDropPercent
        if ($null -ne $Raw -and [string]$Raw -ne '') {
            $Parsed = 0.0
            if ([double]::TryParse([string]$Raw, [System.Globalization.NumberStyles]::Float, [cultureinfo]::InvariantCulture, [ref]$Parsed) -and $Parsed -gt 0) { $Drop = $Parsed }
        }
        $Coverage = $Report.Summary.CoveragePercent
        if ($null -ne $Coverage) {
            $Coverage = [double]$Coverage
            $Table = Get-CIPPTable -tablename 'SmsMfaReadiness'
            $SafeTenant = ConvertTo-CIPPODataFilterValue -Value ([string]$TenantFilter) -Type String
            $Baseline = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Coverage' and RowKey eq '$SafeTenant'" | Select-Object -First 1
            $Now = [datetime]::UtcNow
            $Best = if ($Baseline -and [string]$Baseline.BestPercent -ne '') { [double]$Baseline.BestPercent } else { $null }
            $BestAt = if ($Baseline) { [string]$Baseline.BestUtc } else { '' }
            $Since = if ($Baseline) { [string]$Baseline.RegressedSinceUtc } else { '' }

            if ($null -eq $Best -or $Coverage -ge $Best) {
                $Best = $Coverage; $BestAt = $Now.ToString('o'); $Since = ''
            } elseif ($Best - $Coverage -gt $Drop) {
                if (-not $Since) { $Since = $Now.ToString('o') }
                $Persisted = try { ([datetimeoffset]$Since).UtcDateTime -lt $Now.AddDays(-28) } catch { $false }
                if ($Persisted) {
                    Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "SMS/voice MFA reliance: Authenticator/passkey coverage has been $Coverage% (best $Best%) for 28 days; taking $Coverage% as the new baseline." -sev Info
                    $Best = $Coverage; $BestAt = $Now.ToString('o'); $Since = ''
                } else {
                    $Rows.Add([pscustomobject]@{
                            Id       = 'CoverageRegressed'
                            Severity = 'Warning'
                            Check    = 'Authenticator/passkey coverage'
                            Account  = ''
                            Message  = "Authenticator/passkey coverage dropped to $Coverage% of $($Report.Summary.UsersEnabled) enabled users, from a best of $Best% (more than $Drop points). New users may be enrolling with SMS/voice only, or people removed their Authenticator."
                            Fix      = 'Check recent registrations in Entra > Authentication methods > User registration details and re-run the registration campaign.'
                        })
                }
            } else {
                $Since = ''
            }
            Add-CIPPAzDataTableEntity @Table -Force -Entity @{
                PartitionKey      = 'Coverage'
                RowKey            = [string]$TenantFilter
                BestPercent       = [string]$Best
                BestUtc           = $BestAt
                LastPercent       = [string]$Coverage
                LastUtc           = $Now.ToString('o')
                RegressedSinceUtc = $Since
            } | Out-Null
        }

        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "SMS/voice MFA reliance check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$((Get-CippException -Exception $_).NormalizedError) $_") -LogData (Get-CippException -Exception $_)
    }
}
