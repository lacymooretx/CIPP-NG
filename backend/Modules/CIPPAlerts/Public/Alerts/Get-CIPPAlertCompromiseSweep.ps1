function Get-CIPPAlertCompromiseSweep {
    <#
    .SYNOPSIS
        Tenant-wide sweep for account-compromise patterns that single audit events cannot express
    .DESCRIPTION
        Complements the per-user BEC check and the audit-log alert rules with four detections that
        need aggregation across the sign-in and directory logs:

          DeviceCode  - a SUCCESSFUL sign-in using the OAuth device-code flow. Device-code phishing
                        ("enter this code at microsoft.com/devicelogin") hands the attacker a token
                        that survives a password reset and needs no MFA prompt of its own. Legitimate
                        use (Teams Rooms, az CLI) is excluded through the allow-list input.
          Spray       - one IP failing against many accounts (classic password spray).
          BruteForce  - one account failing from many IPs (distributed guessing / credential
                        stuffing - the pattern seen against bryan@aspendora.com on 2026-10-01).
          DormantMfa  - an MFA method registered on an account with no interactive sign-in in the
                        preceding N days: the "take over an unused account and register my own
                        authenticator" step.

        Spray and BruteForce rows are escalated when the same IP / account also has a SUCCESSFUL
        sign-in in the window - that is the difference between noise and a compromise.

        Sign-in data needs Entra ID P1. A tenant without it skips the sign-in detections with a
        logged warning instead of failing the whole alert.

        Dedup is the AlertLifecycle in -Append (event stream) mode keyed on a stable Id per
        detection, so an ongoing spray from one IP notifies once, not every run.

        Thresholds and windows come from the alert inputs; see alerts.json. Written for the fork
        (M365-Investigation-Toolkit gap review, 2026-10-01).
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

    $LookbackHours = if ($InputValue.CompromiseSweepLookbackHours) { [int]$InputValue.CompromiseSweepLookbackHours } else { 24 }
    $SprayUsersPerIp = if ($InputValue.CompromiseSweepSprayUsersPerIp) { [int]$InputValue.CompromiseSweepSprayUsersPerIp } else { 5 }
    $BruteIpsPerUser = if ($InputValue.CompromiseSweepBruteForceIpsPerUser) { [int]$InputValue.CompromiseSweepBruteForceIpsPerUser } else { 3 }
    $DormantDays = if ($InputValue.CompromiseSweepDormantDays) { [int]$InputValue.CompromiseSweepDormantDays } else { 30 }
    $MaxSurfacedPerCycle = if ($InputValue.CompromiseSweepMaxPerCycle) { [int]$InputValue.CompromiseSweepMaxPerCycle } else { 10 }
    # 'High' surfaces only detections with a confirmed success (or device-code / dormant-MFA, which
    # are always High); 'Medium' also surfaces blocked spray and brute-force campaigns.
    $MinSeverity = if ($InputValue.CompromiseSweepMinSeverity -in @('High', 'Medium')) { [string]$InputValue.CompromiseSweepMinSeverity } else { 'Medium' }
    $AllowList = @(([string]$InputValue.CompromiseSweepDeviceCodeAllowList) -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLower() })

    $Now = (Get-Date).ToUniversalTime()
    $Cutoff = $Now.AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Beta = 'https://graph.microsoft.com/beta'
    $Rows = [System.Collections.Generic.List[object]]::new()

    try {
        $SignInsAvailable = $true

        # ---- DeviceCode ---------------------------------------------------------------------
        # The authenticationProtocol filter is not indexed: it timed out over 30 days in testing
        # but returns quickly over 24 hours, which is why the lookback is short.
        try {
            $Uri = "$Beta/auditLogs/signIns?`$filter=createdDateTime ge $Cutoff and authenticationProtocol eq 'deviceCode'&`$select=createdDateTime,userPrincipalName,userId,appDisplayName,appId,ipAddress,location,status&`$top=200"
            $DeviceCode = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -noPagination $true -ErrorAction Stop |
                    Where-Object { [int]$_.status.errorCode -eq 0 })
            foreach ($Group in ($DeviceCode | Group-Object { "$($_.userPrincipalName)|$($_.appId)" })) {
                $First = $Group.Group | Sort-Object createdDateTime | Select-Object -First 1
                $Upn = [string]$First.userPrincipalName
                if ($AllowList -contains $Upn.ToLower() -or $AllowList -contains ([string]$First.appId).ToLower()) { continue }
                $Rows.Add([PSCustomObject]@{
                        'Id'        = "DeviceCode|$($Upn.ToLower())|$($First.appId)"
                        'Detection' = 'Device-code sign-in'
                        'Severity'  = 'High'
                        'Account'   = $Upn
                        'Detail'    = "$($Group.Count) successful device-code sign-in(s) to $($First.appDisplayName)"
                        'IPs'       = (@($Group.Group.ipAddress | Sort-Object -Unique) -join ', ')
                        'Locations' = (@($Group.Group | ForEach-Object { "$($_.location.city), $($_.location.countryOrRegion)" } | Sort-Object -Unique) -join '; ')
                        'First Seen' = ([datetime]$First.createdDateTime).ToString('u')
                        'Next step' = 'If the user did not knowingly enter a code at microsoft.com/devicelogin: revoke sessions, reset the password, run the CIPP compromise check. Consider a Conditional Access policy blocking the device code flow.'
                        'Tenant'    = $TenantFilter
                    })
            }
        } catch {
            $Message = $_.Exception.Message
            if ($Message -match 'premium|license|Authentication_RequestFromNonPremiumTenantOrB2CTenant') { $SignInsAvailable = $false }
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Compromise sweep: device-code check skipped: $Message" -sev Warning
        }

        # ---- Spray / BruteForce ---------------------------------------------------------------
        if ($SignInsAvailable) {
            try {
                # 50126 = bad username/password, 50053 = locked (smart lockout or malicious IP).
                $Uri = "$Beta/auditLogs/signIns?`$filter=createdDateTime ge $Cutoff and (status/errorCode eq 50126 or status/errorCode eq 50053)&`$select=createdDateTime,userPrincipalName,ipAddress,location,appDisplayName,status&`$top=999"
                $Failures = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -noPagination $true -ErrorAction Stop)
                if ($Failures.Count -ge 999) {
                    Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Compromise sweep: 999+ failed sign-ins in $LookbackHours h; only the first page was analysed." -sev Warning
                }

                # CIPP's trusted-IP list (the same one the audit-log alerts honour) is never an attacker.
                $IPListEntries = @(try { Get-CIPPIPAllowBlockList -TenantFilter $TenantFilter } catch { @() })
                $IsTrusted = {
                    param($Ip)
                    $IPListEntries.Count -gt 0 -and (Resolve-CIPPIPAllowBlockList -IPAddress $Ip -Entries $IPListEntries).State -eq 'Trusted'
                }

                foreach ($Group in ($Failures | Where-Object { $_.ipAddress } | Group-Object ipAddress)) {
                    $Users = @($Group.Group.userPrincipalName | Where-Object { $_ } | Sort-Object -Unique)
                    if ($Users.Count -lt $SprayUsersPerIp) { continue }
                    $Ip = [string]$Group.Name
                    if (& $IsTrusted $Ip) { continue }
                    $Success = @(Get-CIPPCompromiseSweepSuccess -TenantFilter $TenantFilter -Cutoff $Cutoff -Filter "ipAddress eq '$Ip'")
                    # Several different people signing in successfully from the IP makes it shared
                    # egress (an office, a VPN) where typos add up - not a spray source.
                    if (@($Success.userPrincipalName | Sort-Object -Unique).Count -ge 3) { continue }
                    $Loc = $Group.Group[0].location
                    $Rows.Add([PSCustomObject]@{
                            'Id'         = "Spray|$Ip"
                            'Detection'  = 'Password spray'
                            'Severity'   = $(if ($Success.Count) { 'High' } else { 'Medium' })
                            'Account'    = "$($Users.Count) accounts"
                            'Detail'     = "$($Group.Count) failed sign-ins against $($Users.Count) accounts from one IP" + $(if ($Success.Count) { ". SUCCESSFUL sign-in from this IP: $((@($Success.userPrincipalName | Sort-Object -Unique)) -join ', ')" } else { '; no successful sign-in from it' })
                            'IPs'        = $Ip
                            'Locations'  = "$($Loc.city), $($Loc.countryOrRegion)"
                            'First Seen' = ([datetime]($Group.Group | Sort-Object createdDateTime | Select-Object -First 1).createdDateTime).ToString('u')
                            'Next step'  = $(if ($Success.Count) { 'Treat the accounts that signed in successfully as compromised: revoke sessions, reset passwords, run the CIPP compromise check.' } else { 'Smart lockout is absorbing it. Block the IP in a Conditional Access named location if it continues; confirm the targeted accounts have MFA.' })
                            'Tenant'     = $TenantFilter
                        })
                }

                $SharedEgress = @{}
                $BaselineFrom = $Now.AddHours(-$LookbackHours).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
                foreach ($Group in ($Failures | Where-Object { $_.userPrincipalName } | Group-Object userPrincipalName)) {
                    $Ips = @($Group.Group.ipAddress | Where-Object { $_ -and -not (& $IsTrusted $_) } | Sort-Object -Unique)
                    if ($Ips.Count -lt $BruteIpsPerUser) { continue }
                    $Upn = [string]$Group.Name
                    $UpnFilter = "userPrincipalName eq '$($Upn -replace "'", "''")'"
                    # The user's own normal IPs (successful sign-ins in the 7 days before the window):
                    # a typo at home or the office is not an attack, so those IPs neither count towards
                    # the threshold nor escalate the detection.
                    $KnownIps = @(Get-CIPPCompromiseSweepSuccess -TenantFilter $TenantFilter -Cutoff $BaselineFrom -Before $Cutoff -Filter $UpnFilter -Top 200 |
                            ForEach-Object { $_.ipAddress } | Sort-Object -Unique)
                    $Ips = @($Ips | Where-Object { $KnownIps -notcontains $_ })
                    if ($Ips.Count -lt $BruteIpsPerUser) { continue }
                    $Success = @(Get-CIPPCompromiseSweepSuccess -TenantFilter $TenantFilter -Cutoff $Cutoff -Filter $UpnFilter |
                            Where-Object { $Ips -contains $_.ipAddress })
                    # A success from shared egress (3+ different people signed in from it today) is the
                    # user at the office after a typo, not the attacker getting in.
                    $Success = @($Success | Where-Object {
                            $SuccessIp = $_.ipAddress
                            if (-not $SharedEgress.ContainsKey($SuccessIp)) {
                                $SharedEgress[$SuccessIp] = @(Get-CIPPCompromiseSweepSuccess -TenantFilter $TenantFilter -Cutoff $Cutoff -Filter "ipAddress eq '$SuccessIp'" |
                                        ForEach-Object { $_.userPrincipalName } | Sort-Object -Unique).Count -ge 3
                            }
                            -not $SharedEgress[$SuccessIp]
                        })
                    $Rows.Add([PSCustomObject]@{
                            'Id'         = "BruteForce|$($Upn.ToLower())"
                            'Detection'  = 'Distributed brute force'
                            'Severity'   = $(if ($Success.Count) { 'High' } else { 'Medium' })
                            'Account'    = $Upn
                            'Detail'     = "$(@($Group.Group | Where-Object { $Ips -contains $_.ipAddress }).Count) failed sign-ins from $($Ips.Count) IPs the user does not normally sign in from" + $(if ($Success.Count) { ". SUCCESSFUL sign-in from one of those IPs: $((@($Success.ipAddress | Sort-Object -Unique)) -join ', ')" } else { '; none of those IPs signed in successfully' })
                            'IPs'        = ($Ips -join ', ')
                            'Locations'  = (@($Group.Group | ForEach-Object { "$($_.location.city), $($_.location.countryOrRegion)" } | Sort-Object -Unique) -join '; ')
                            'First Seen' = ([datetime]($Group.Group | Sort-Object createdDateTime | Select-Object -First 1).createdDateTime).ToString('u')
                            'Next step'  = $(if ($Success.Count) { 'Account likely compromised: revoke sessions, reset the password, run the CIPP compromise check.' } else { 'Guessing is being blocked and nothing got in. Do NOT force a password change (NIST SP 800-63B: no evidence of compromise; forced changes lead to weaker passwords). Confirm MFA is enforced for the account; if the campaign continues, block the source IPs or countries with Conditional Access.' })
                            'Tenant'     = $TenantFilter
                        })
                }
            } catch {
                Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Compromise sweep: spray/brute-force check skipped: $($_.Exception.Message)" -sev Warning
            }
        }

        # ---- DormantMfa ------------------------------------------------------------------------
        try {
            $Uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $Cutoff and (activityDisplayName eq 'User registered security info' or activityDisplayName eq 'Admin registered security info')&`$top=100"
            $Registrations = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -noPagination $true -ErrorAction Stop)
            foreach ($Reg in $Registrations) {
                $Target = @($Reg.targetResources | Where-Object { $_.type -eq 'User' }) | Select-Object -First 1
                if (-not $Target.id) { continue }
                $User = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($Target.id)?`$select=id,userPrincipalName,createdDateTime" -tenantid $TenantFilter -noPagination $true -ErrorAction SilentlyContinue
                # A brand-new account registering MFA is onboarding, not a takeover.
                if ($User.createdDateTime -and ([datetime]$User.createdDateTime) -gt $Now.AddDays(-$DormantDays)) { continue }
                if (-not $SignInsAvailable) { continue }
                $EventTime = ([datetime]$Reg.activityDateTime).ToUniversalTime()
                $From = $Now.AddDays(-$DormantDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
                $Before = $EventTime.AddHours(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
                $Prior = @(New-GraphGetRequest -uri "$Beta/auditLogs/signIns?`$filter=userId eq '$($Target.id)' and createdDateTime ge $From and createdDateTime le $Before and status/errorCode eq 0&`$select=createdDateTime&`$top=1" -tenantid $TenantFilter -noPagination $true -ErrorAction Stop | Where-Object { $_ })
                if ($Prior.Count -gt 0) { continue }
                $Rows.Add([PSCustomObject]@{
                        'Id'         = "DormantMfa|$($Target.id)|$($EventTime.ToString('yyyyMMdd'))"
                        'Detection'  = 'MFA registered on dormant account'
                        'Severity'   = 'High'
                        'Account'    = [string]($User.userPrincipalName ?? $Target.userPrincipalName)
                        'Detail'     = "$($Reg.activityDisplayName) ($($Reg.result)) with no successful sign-in in the previous $DormantDays days. Initiated by: $($Reg.initiatedBy.user.userPrincipalName ?? $Reg.initiatedBy.app.displayName)"
                        'IPs'        = [string]$Reg.initiatedBy.user.ipAddress
                        'Locations'  = ''
                        'First Seen' = $EventTime.ToString('u')
                        'Next step'  = 'Confirm with the user (by phone, not email) that they registered this method. If not: delete the method, revoke sessions, reset the password, run the CIPP compromise check.'
                        'Tenant'     = $TenantFilter
                    })
            }
        } catch {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Compromise sweep: dormant-MFA check skipped: $($_.Exception.Message)" -sev Warning
        }

        if ($MinSeverity -eq 'High') {
            $Rows = [System.Collections.Generic.List[object]]@($Rows | Where-Object { $_.Severity -eq 'High' })
        }
        if ($Rows.Count -eq 0) { return }

        $CmdletName = [string]$MyInvocation.MyCommand
        $New = @(Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data @($Rows) -Append | Where-Object { $_ })
        if ($New.Count -eq 0) { return }
        if ($New.Count -gt $MaxSurfacedPerCycle) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Compromise sweep: $($New.Count) new detections exceeded the per-cycle cap of $MaxSurfacedPerCycle; surfaced the $MaxSurfacedPerCycle most severe. The remainder are recorded and will not re-surface." -sev Warning
        }
        $New | Sort-Object { if ($_.Severity -eq 'High') { 0 } else { 1 } } | Select-Object -First $MaxSurfacedPerCycle
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Compromise sweep failed for $($TenantFilter): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
    }
}
