function Get-CIPPEwsStatus {
    <#
    .SYNOPSIS
        Collects a tenant's EWS state (EwsEnabled, apps with EWS permissions, optional audit usage) and evaluates it.
    .DESCRIPTION
        EWS consumers are apps holding the Exchange Online application role full_access_as_app or the delegated
        EWS.AccessAsUser.All scope. -IncludeUsage also searches 7 days of MailItemsAccessed for Client=WebServices,
        which shows what actually used EWS (mailbox reads only; calendar-only EWS use is not logged there).
        Aspendora fork addition (Vikunja CIPP-29).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter, [switch]$IncludeUsage)

    $FullAccessAsApp = 'dc890d15-9560-4a4c-9b7f-a736ec74ec40'
    $Org = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-OrganizationConfig' -ErrorAction Stop
    $Exo = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000002-0000-0ff1-ce00-000000000000'&`$select=id" -tenantid $TenantFilter -ErrorAction Stop)[0]
    $AppOnly = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($Exo.id)/appRoleAssignedTo?`$top=999" -tenantid $TenantFilter -ErrorAction Stop |
            Where-Object { $_.appRoleId -eq $FullAccessAsApp } | ForEach-Object principalDisplayName)
    $Grants = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=resourceId eq '$($Exo.id)'&`$top=999" -tenantid $TenantFilter -ErrorAction Stop |
            Where-Object { $_.scope -match 'EWS\.AccessAsUser\.All' })
    $Delegated = foreach ($ClientId in @($Grants.clientId | Sort-Object -Unique)) {
        try { (New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ClientId)?`$select=displayName" -tenantid $TenantFilter -ErrorAction Stop).displayName } catch { $ClientId }
    }

    $Usage = $null
    if ($IncludeUsage) {
        $Usage = @{}
        $End = (Get-Date).ToUniversalTime()
        $Records = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Search-UnifiedAuditLog' -cmdParams @{ StartDate = $End.AddDays(-7).ToString('o'); EndDate = $End.ToString('o'); Operations = @('MailItemsAccessed'); FreeText = 'WebServices'; ResultSize = 5000 } -ErrorAction Stop)
        foreach ($R in $Records) {
            $A = try { $R.AuditData | ConvertFrom-Json } catch { $null }
            if (-not $A -or [string]$A.ClientInfoString -notmatch 'WebServices') { continue }
            $Key = "$(([string]$A.ClientInfoString).Substring(0, [math]::Min(60, ([string]$A.ClientInfoString).Length))) | app $($A.ClientAppId ?? $A.AppId)"
            $Usage[$Key] = ($Usage[$Key] ?? 0) + [int]($A.OperationCount ?? 1)
        }
    }

    $Eval = Test-CIPPEwsStatus -EwsEnabled $Org.EwsEnabled -AppOnlyConsumers $AppOnly -DelegatedConsumers @($Delegated) -RecentUsage $Usage
    [pscustomobject]@{ Tenant = $TenantFilter; EwsEnabled = $Eval.EwsEnabled; AppOnlyConsumers = @($AppOnly | Sort-Object -Unique); DelegatedConsumers = @($Delegated | Sort-Object -Unique); RecentUsage = $Usage; Findings = $Eval.Findings }
}
