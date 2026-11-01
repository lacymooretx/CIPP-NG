function Resolve-CIPPCAPreflightGate {
    <#
    .SYNOPSIS
        Turns a CA pre-flight result into a go / no-go for a write, and logs overrides and warnings.
    .DESCRIPTION
        Mode Enforce (interactive HTTP writes): a failed pre-flight blocks unless Override is true; an
        override is logged at Warning naming the actor.
        Mode Warn (standards / drift, which deploy at scale on a timer): never blocks; a failed pre-flight
        is logged at Warning only, so a new check cannot silently stop standards.
        Returns @{ Allowed; Overridden; Message; Preflight }. Aspendora fork addition (Vikunja CIPP-5).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [ValidateSet('Enforce', 'Warn')][string]$Mode = 'Enforce',
        [bool]$Override = $false,
        $Headers,
        [string]$APIName = 'CA Preflight',
        [string]$TenantFilter
    )

    $Name = $Result.PolicyName
    $Failed = @($Result.Checks | Where-Object Status -EQ 'Fail')
    $Summary = ($Failed | ForEach-Object { "$($_.Check): $($_.Message)" }) -join ' | '
    if ($Result.Passed) {
        return [pscustomobject]@{ Allowed = $true; Overridden = $false; Message = "Pre-flight passed for '$Name'."; Preflight = $Result }
    }

    $LogData = [pscustomobject]@{ Checks = $Result.Checks; WhatIf = $Result.WhatIf; ReportOnly = $Result.ReportOnly; Errors = $Result.Errors }
    if ($Mode -eq 'Warn') {
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "CA pre-flight (warning only, not blocking this scheduled deploy) failed for '$Name' being set to On: $Summary" -Sev 'Warning' -LogData $LogData
        return [pscustomobject]@{ Allowed = $true; Overridden = $false; Message = "Pre-flight failed for '$Name' (warning only)."; Preflight = $Result }
    }
    if ($Override) {
        $Actor = try { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json).userDetails } catch { $null }
        $Actor = $Actor ?? $Headers.'x-ms-client-principal-name' ?? 'an API client'
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "CA pre-flight OVERRIDDEN by ${Actor}: '$Name' set to On despite failed checks: $Summary" -Sev 'Warning' -LogData $LogData
        return [pscustomobject]@{ Allowed = $true; Overridden = $true; Message = "Pre-flight failed for '$Name' and was overridden by $Actor."; Preflight = $Result }
    }
    [pscustomobject]@{
        Allowed    = $false
        Overridden = $false
        Message    = "Blocked by the CA pre-flight check: turning '$Name' On in $TenantFilter could lock admins out. $Summary Fix these, or re-submit with the pre-flight override ticked (PreflightOverride=true); the override is logged."
        Preflight  = $Result
    }
}
