function Confirm-CIPPServicePrincipal {
    <#
    .SYNOPSIS
        Reads whether a tenant has a service principal for an appId and, with -Provision, creates it when absent.
    .DESCRIPTION
        GET, then POST only when the read succeeded and found nothing. Safe to run repeatedly.

        Token order follows what worked live on 2026-11-03 (Vikunja CIPP-53). The read is app-only first, then
        delegated. The create is delegated first, then app-only: delegated worked in 8 of 9 tenants and the partner
        tenant needed the app. The fallback does not test for the partner tenant, it reacts to the failure, so this
        does not depend on $env:TenantID.

        Directory reads can lag a few seconds after a create, so the read-back is retried. A create Graph accepted
        (or refused with "already exists") whose read-back is still empty returns CreatedPendingReadBack with
        Present = $true, not a failure; the next run reads it normally.

        A failed read returns State Unknown and never creates anything: "could not check" is not "absent". An empty
        POST result is not proof either (New-GraphPOSTRequest only writes a non-terminating error when the tenant is
        refused), so success is decided by the POST object or the read-back.

        Returns @{ AppId; State; Present; Created; AccountEnabled; Id; DisplayName; Method; Error }, where State is
        Present, Absent, Created, CreatedPendingReadBack, Failed or Unknown. Method is the token that created it.
        It does not enable a disabled service principal: disabling one is a deliberate act, so callers report it.
        Aspendora fork addition (Vikunja CIPP-53).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)][string]$AppId,
        [switch]$Provision,
        [ValidateRange(1, 10)][int]$ReadBackAttempts = 4,
        [ValidateRange(0, 30)][int]$ReadBackDelaySeconds = 3
    )

    $Uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,accountEnabled"

    $Read = {
        $ReadFailures = [System.Collections.Generic.List[string]]::new()
        foreach ($UseApp in @($true, $false)) {
            try {
                $GetParams = @{ uri = $Uri; tenantid = $TenantFilter; ErrorAction = 'Stop' }
                if ($UseApp) { $GetParams.AsApp = $true }
                $Found = $null
                # Checked here as well as in $filter: an ignored filter must not make another app look like this one.
                foreach ($Row in @(New-GraphGetRequest @GetParams)) {
                    if ("$($Row.appId)" -eq $AppId) { $Found = $Row; break }
                }
                return [pscustomobject]@{ Ok = $true; ServicePrincipal = $Found; Error = $null }
            } catch {
                $ReadFailures.Add("$(if ($UseApp) { 'app' } else { 'delegated' }): $($_.Exception.Message)")
            }
        }
        [pscustomobject]@{ Ok = $false; ServicePrincipal = $null; Error = ($ReadFailures -join '; ') }
    }

    $Result = {
        param($State, $Present, $Created, $Sp, $Method, $ErrorText)
        [pscustomobject]@{
            AppId          = $AppId
            State          = $State
            Present        = [bool]$Present
            Created        = [bool]$Created
            AccountEnabled = $Sp.accountEnabled
            Id             = $Sp.id
            DisplayName    = $Sp.displayName
            Method         = $Method
            Error          = $ErrorText
        }
    }

    $Current = & $Read
    if (-not $Current.Ok) { return (& $Result 'Unknown' $false $false $null $null $Current.Error) }
    if ($Current.ServicePrincipal) { return (& $Result 'Present' $true $false $Current.ServicePrincipal $null $null) }
    if (-not $Provision) { return (& $Result 'Absent' $false $false $null $null $null) }

    $Body = @{ appId = $AppId } | ConvertTo-Json -Compress
    $Failures = [System.Collections.Generic.List[string]]::new()
    $Posted = $null
    $Conflict = $false
    $Method = $null
    foreach ($UseApp in @($false, $true)) {
        $Label = if ($UseApp) { 'AsApp' } else { 'Delegated' }
        try {
            $PostParams = @{ uri = 'https://graph.microsoft.com/v1.0/servicePrincipals'; type = 'POST'; tenantid = $TenantFilter; body = $Body }
            if ($UseApp) { $PostParams.AsApp = $true }
            $Response = New-GraphPOSTRequest @PostParams
            if ("$($Response.appId)" -eq $AppId) {
                $Posted = $Response
                $Method = $Label
                break
            }
            $Failures.Add("$($Label): no service principal returned")
        } catch {
            $Message = "$($_.Exception.Message)"
            # An earlier read that lagged, or another run getting there first. Either way it exists.
            if ($Message -match 'already exists|ObjectConflict') {
                $Conflict = $true
                break
            }
            $Failures.Add("$($Label): $Message")
        }
    }

    $Claimed = $null -ne $Posted -or $Conflict
    $Attempts = if ($Claimed) { $ReadBackAttempts } else { 1 }
    for ($Attempt = 1; $Attempt -le $Attempts; $Attempt++) {
        if ($Attempt -gt 1) { Start-Sleep -Seconds $ReadBackDelaySeconds }
        $Back = & $Read
        if ($Back.ServicePrincipal) {
            $State = if ($Posted) { 'Created' } else { 'Present' }
            return (& $Result $State $true ($null -ne $Posted) $Back.ServicePrincipal $Method $null)
        }
    }

    if ($Claimed) { return (& $Result 'CreatedPendingReadBack' $true ($null -ne $Posted) $Posted $Method $null) }
    & $Result 'Failed' $false $false $null $null ($Failures -join '; ')
}
