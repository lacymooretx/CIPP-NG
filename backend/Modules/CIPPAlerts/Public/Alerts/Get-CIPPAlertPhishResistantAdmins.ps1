function Get-CIPPAlertPhishResistantAdmins {
    <#
    .SYNOPSIS
        Weekly phishing-resistant MFA check for admins
    .DESCRIPTION
        Runs Get-CIPPPhishResistantPosture and raises its Error and Warning findings: privileged role holders
        (active or PIM-eligible) without a passkey, FIDO2 key, Windows Hello for Business, Platform Credential or
        certificate; admin accounts that also have a licence or mailbox; a Global Admin count outside 2-4; passkeys
        disabled or not self-service; AAGUID restrictions that block Microsoft Authenticator passkeys.
        State mode: a finding notifies once and resolves when it is fixed. A run with collection errors does not
        report, because "could not check" is not "clear". Aspendora fork addition (Vikunja CIPP-7).
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
        $Report = Get-CIPPPhishResistantPosture -TenantFilter $TenantFilter
        if (@($Report.Errors).Count -gt 0) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Phishing-resistant admin MFA: skipped reporting, could not read everything: $(@($Report.Errors) -join '; ')" -sev Warning
            return
        }
        $Rows = @($Report.Findings | Where-Object { $_.Severity -in @('Error', 'Warning') } | ForEach-Object {
                [pscustomobject]@{ Severity = $_.Severity; Check = $_.Check; Account = $_.Account; Message = $_.Message; Fix = $_.Fix; Key = $_.Key }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Phishing-resistant admin MFA check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev Error -LogData (Get-CippException -Exception $_)
    }
}
