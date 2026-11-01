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

        $Rows = [System.Collections.Generic.List[object]]::new()
        foreach ($F in @($Report.Findings | Where-Object { $_.Severity -in @('Error', 'Warning') })) {
            # Account, not UserPrincipalName: the lifecycle hashes UserPrincipalName before Id, which would merge
            # two findings about the same admin.
            $Rows.Add([pscustomobject]@{ Id = $F.Key; Severity = $F.Severity; Check = $F.Check; Account = $F.Account; Message = $F.Message; Fix = $F.Fix })
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
