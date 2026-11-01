function Get-CIPPAlertExoProvisioning {
    <#
    .SYNOPSIS
        Daily check that Exchange Online provisioned correctly (organisation, RBAC, accepted domains, mailboxes)
    .DESCRIPTION
        Runs Get-CIPPExoProvisioningHealth and raises every Warn and Fail finding: Get-OrganizationConfig not
        answering for a tenant licensed for Exchange, built-in role groups or core management roles missing,
        Organization Management missing roles, mailbox service plans stuck provisioning, verified email domains that
        are not accepted domains, and users licensed for a mailbox for longer than ExoProvisioningGraceHours
        (default 24) with no Exchange recipient. Tenants without an Exchange licence produce nothing.
        State mode, Ids: ExoProvisioning|<Check>, ExoProvisioning|Domain|<domain>, ExoProvisioning|NoMailbox|<user id>,
        so each problem notifies once and resolves when fixed. A check that could not run is logged rather than
        raised (except Exchange not answering, which is the failure itself), and that run raises new findings
        without resolving open ones, because "could not check" is not "clear". When no licensed user has a
        mailbox, one tenant-level finding is raised instead of one per user.
        Report only: the Fix text points to the Exchange role repair (ExecExchangeRoleRepair), which is never
        called from here. Aspendora fork addition (Vikunja CIPP-36).
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
    $GraceHours = 24
    $Parsed = 0
    if ($null -ne $InputValue.ExoProvisioningGraceHours -and [int]::TryParse([string]$InputValue.ExoProvisioningGraceHours, [ref]$Parsed) -and $Parsed -ge 1) { $GraceHours = $Parsed }
    try {
        $Report = Get-CIPPExoProvisioningHealth -TenantFilter $TenantFilter -GraceHours $GraceHours
        # A check that could not run is logged, not alerted, unless it is itself the failure (Exchange not answering).
        $Raise = @($Report.Checks | Where-Object { $_.Status -eq 'Fail' -or ($_.Status -eq 'Warn' -and $_.Errored -ne $true) })
        $Rows = foreach ($Check in $Raise) {
            if ($Check.Check -eq 'AcceptedDomains' -and -not $Check.Errored -and $Check.Status -eq 'Warn') {
                foreach ($Domain in @($Report.MissingDomains)) {
                    [pscustomobject]@{
                        Id       = "ExoProvisioning|Domain|$Domain"
                        Severity = 'Warn'
                        Check    = 'AcceptedDomains'
                        Domain   = $Domain
                        Message  = "$Domain is verified for email in Entra but is not an accepted domain in Exchange Online, so mail to it is rejected."
                        Fix      = $Check.Fix
                    }
                }
            } elseif ($Check.Check -eq 'LicensedUserMailboxes' -and -not $Check.Errored -and $Check.Status -eq 'Warn') {
                foreach ($User in @($Report.UsersWithoutMailbox)) {
                    # 'User', not 'UserPrincipalName': the content hash prefers UserPrincipalName over Id, and a
                    # renamed user must not re-notify.
                    [pscustomobject]@{
                        Id            = "ExoProvisioning|NoMailbox|$($User.id)"
                        Severity      = 'Warn'
                        Check         = 'LicensedUserMailboxes'
                        User          = $User.userPrincipalName
                        LicensedSince = $User.licensedSince
                        Message       = "$($User.userPrincipalName) has been licensed for an Exchange mailbox for more than $GraceHours hours but has no mailbox."
                        Fix           = $Check.Fix
                    }
                }
            } else {
                [pscustomobject]@{
                    Id       = "ExoProvisioning|$($Check.Check)"
                    Severity = $Check.Status
                    Check    = $Check.Check
                    Message  = $Check.Detail
                    Fix      = $Check.Fix
                }
            }
        }
        $Rows = @($Rows | Where-Object { $_ })
        if (@($Report.Checks | Where-Object { $_.Errored -eq $true }).Count -gt 0) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Exchange provisioning: some checks could not run; raising new findings without resolving existing ones this run. $(@($Report.Errors) -join '; ')" -sev Warning
            return @(Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows -Append | Where-Object { $_ })
        }
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        $Err = (Get-CippException -Exception $_).NormalizedError
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Exchange provisioning check failed: $Err" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$Err $_") -LogData (Get-CippException -Exception $_)
    }
}
