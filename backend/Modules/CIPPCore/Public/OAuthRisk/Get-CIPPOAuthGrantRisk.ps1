function Get-CIPPOAuthGrantRisk {
    <#
    .SYNOPSIS
        Collects a tenant's OAuth grants live from Graph and risk-scores them per client app.
    .DESCRIPTION
        Live Graph (not the reporting cache), so the result is current: application permissions from appRoleAssignedTo
        on Microsoft Graph, Office 365 Exchange Online and Office 365 SharePoint Online (appRole ids resolved to names
        from the resource's appRoles), delegated grants from oauth2PermissionGrants, every service principal for the
        publisher and enabled state, and the beta servicePrincipalSignInActivities report for last use (needs Entra ID
        P1; without it last sign-in is unknown, not "never"). Measure-CIPPOAuthGrantRisk does the scoring; AI connectors
        are matched against Config/ShadowAI.json. A failure to read the grants themselves throws, so a caller never
        mistakes "could not check" for "clean". Read-only. Aspendora fork addition (Vikunja CIPP-11).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $ResourceAppIds = @('00000003-0000-0000-c000-000000000000', '00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000')
    $AppIdFilter = ($ResourceAppIds | ForEach-Object { "'$_'" }) -join ','
    $Resources = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId in ($AppIdFilter)&`$select=id,appId,displayName,appRoles" -tenantid $TenantFilter -ErrorAction Stop)
    $Assignments = foreach ($R in $Resources) {
        New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($R.id)/appRoleAssignedTo?`$top=999" -tenantid $TenantFilter -ErrorAction Stop
    }
    $Grants = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' -tenantid $TenantFilter -ErrorAction Stop)
    $Sps = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/servicePrincipals?$top=999&$select=id,appId,displayName,appOwnerOrganizationId,publisherName,verifiedPublisher,accountEnabled,createdDateTime,servicePrincipalType' -tenantid $TenantFilter -ErrorAction Stop)

    $HomeTenantId = try { [string](@(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/organization?$select=id' -tenantid $TenantFilter -ErrorAction Stop)[0].id) } catch { '' }
    $SignInNote = $null
    # $null = unknown (no P1 or no access); an empty array = known, nothing signed in.
    $SignIns = $null
    try {
        $SignIns = [object[]]@(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999' -tenantid $TenantFilter -ErrorAction Stop)
    } catch {
        $SignInNote = "Last sign-in unknown: servicePrincipalSignInActivities could not be read (needs Entra ID P1). $($_.Exception.Message)"
    }

    $ConfigRoot = Join-Path $env:CIPPRootPath 'Config'
    $AiCatalog = try { @(Get-Content -Raw (Join-Path $ConfigRoot 'ShadowAI.json') -ErrorAction Stop | ConvertFrom-Json) } catch { @() }
    $Risky = try { @(Get-Content -Raw (Join-Path $ConfigRoot 'RiskyPermissions.json') -ErrorAction Stop | ConvertFrom-Json) } catch { @() }

    $Apps = @(Measure-CIPPOAuthGrantRisk -ServicePrincipals $Sps -ResourceServicePrincipals $Resources -AppRoleAssignments @($Assignments) -Grants $Grants -SignInActivities $SignIns -AiCatalog $AiCatalog -RiskyPermissions $Risky -HomeTenantId $HomeTenantId)

    [pscustomobject]@{
        Tenant                  = $TenantFilter
        GeneratedAt             = (Get-Date).ToUniversalTime().ToString('o')
        SignInActivityAvailable = $null -ne $SignIns
        Notes                   = @($SignInNote | Where-Object { $_ })
        Summary                 = [pscustomobject]@{
            Apps          = $Apps.Count
            Critical      = @($Apps | Where-Object Risk -EQ 'Critical').Count
            High          = @($Apps | Where-Object Risk -EQ 'High').Count
            Medium        = @($Apps | Where-Object Risk -EQ 'Medium').Count
            Low           = @($Apps | Where-Object Risk -EQ 'Low').Count
            AiConnectors  = @($Apps | Where-Object IsAiConnector).Count
            AppOnlyHigh   = @($Apps | Where-Object { -not $_.IsMicrosoft -and @($_.Permissions | Where-Object { $_.Type -eq 'Application' -and $_.Risk -eq 'High' }).Count }).Count
            TenantWideDel = @($Apps | Where-Object { -not $_.IsMicrosoft -and @($_.Permissions | Where-Object { $_.Type -eq 'Delegated' -and $_.Consent -eq 'Tenant-wide' -and $_.Risk -eq 'High' }).Count }).Count
        }
        Apps                    = $Apps
    }
}
