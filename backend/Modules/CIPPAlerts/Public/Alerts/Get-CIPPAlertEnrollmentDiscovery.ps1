function Get-CIPPAlertEnrollmentDiscovery {
    <#
    .SYNOPSIS
        Weekly check for tenants still relying on CNAME-based Intune enrollment discovery
    .DESCRIPTION
        Runs Get-CIPPEnrollmentDiscovery (enterpriseenrollment / enterpriseregistration CNAMEs on every custom verified
        domain, the Intune MDM user scope, Windows and hybrid-joined devices) and raises its Warning findings:
        CNAME published while the MDM scope is None or a narrow group, Windows enrollment in use with the CNAME
        missing while the scope is not All, CNAMEs pointing somewhere unexpected, no enrollment path at all, and
        GPO / co-management enrolled hybrid devices that depend on a scope that is not All. With "Include
        informational findings" on, Info findings (legacy target, missing registration CNAME...) are raised too.
        State mode: rows carry the finding Id (Category|domain), so a finding notifies once and resolves when fixed.
        If the MDM scope or the device list could not be read the run does not report, because "could not
        check" is not "clear". Report only. Aspendora fork addition (Vikunja CIPP-22).
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
        $IncludeInfo = ConvertTo-CIPPBoolean $InputValue.EnrollmentDiscoveryIncludeInfo
        $Report = Get-CIPPEnrollmentDiscovery -TenantFilter $TenantFilter
        $Blocking = @($Report.Errors | Where-Object { $_ -match '^(MDM user scope|Windows managed devices|Verified domains):' })
        if ($Blocking.Count -gt 0) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Enrollment discovery: skipped reporting, could not read everything: $($Blocking -join '; ')" -sev Warning
            return
        }
        $Rows = @($Report.Findings | Where-Object { $_.Severity -eq 'Warning' -or ($IncludeInfo -eq $true -and $_.Severity -eq 'Info' -and $_.Category -ne 'DnsLookupFailed') } | ForEach-Object {
                [pscustomobject]@{
                    Id        = $_.Id
                    Severity  = $_.Severity
                    Category  = $_.Category
                    Domain    = $_.Domain
                    MdmScope  = $Report.MdmScope
                    Message   = $_.Message
                }
            })
        # A failed DNS lookup is unknown, not clear: keep that domain's open findings by not reconciling this run.
        if (@($Report.Domains | Where-Object { $_.LookupError -eq $true }).Count -gt 0) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message 'Enrollment discovery: a DNS lookup failed; raising new findings without resolving existing ones this run.' -sev Warning
            return @(Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows -Append | Where-Object { $_ })
        }
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Enrollment discovery check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$((Get-CippException -Exception $_).NormalizedError) $_") -LogData (Get-CippException -Exception $_)
    }
}
