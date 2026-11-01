function Get-CIPPAlertOAuthHighRiskGrant {
    <#
    .SYNOPSIS
        Daily alert on high-risk OAuth grants: app-only mailbox/file/directory access, tenant-wide risky consent, AI connectors
    .DESCRIPTION
        Runs Get-CIPPOAuthGrantRisk and raises every app scored Critical or High, plus any AI connector
        (Config/ShadowAI.json) holding mail, files or sites scopes at any level, unless the app is on the allow-list.
        Each row carries the blast radius and a suggested action.

        Allow-lists. Each entry is an appId or a display name; names may use * wildcards (e.g. "Backup Application *").
          OAuthRiskAllowList       - fleet-wide: applies to every tenant the alert runs on (vetted vendors).
          OAuthRiskTenantAllowList - tenant-specific: entries written "tenant|appId-or-name", where tenant is the default
                                     domain or tenant id (e.g. "aspendora.com|e0476654-..."). Only that tenant is affected,
                                     so an app vetted in one tenant (an AI connector, our own automation) still alerts
                                     everywhere else. A "tenant|..." entry in the fleet-wide list is scoped the same way.
          Entries are separated by commas or new lines; custom variables such as %oauthallowlist% are expanded.

        State mode: the hash key (Id) is appId plus the alerting scope set, so each app notifies once, notifies again if
        it gains a new high-risk scope, and resolves when the grant is removed or the app is allow-listed. A run that
        could not read the grants does not report, because "could not check" is not "clear".
        Aspendora fork addition (Vikunja CIPP-11).
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
        $AllowRaw = Get-CIPPTextReplacement -TenantFilter $TenantFilter -Text ([string]$InputValue.OAuthRiskAllowList)
        $TenantAllowRaw = Get-CIPPTextReplacement -TenantFilter $TenantFilter -Text ([string]$InputValue.OAuthRiskTenantAllowList)
        $TenantIds = @([string]$TenantFilter)
        $Allow = [System.Collections.Generic.List[string]]::new()
        foreach ($Entry in @("$AllowRaw`n$TenantAllowRaw" -split '[,\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            if ($Entry -notlike '*|*') { $Allow.Add($Entry); continue }
            # Tenant-scoped entry: "tenant|appId-or-name". Split once; never rely on $Matches here.
            $Parts = $Entry -split '\|', 2
            $Scope = $Parts[0].Trim()
            $Pattern = $Parts[1].Trim()
            if (-not $Scope -or -not $Pattern) { continue }
            if ($Scope -match '^[0-9a-fA-F-]{36}$' -and $TenantIds.Count -eq 1) {
                $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
                if ($Tenant.customerId) { $TenantIds += [string]$Tenant.customerId }
            }
            if ($TenantIds -contains $Scope) { $Allow.Add($Pattern) }
        }

        $Report = Get-CIPPOAuthGrantRisk -TenantFilter $TenantFilter
        $Rows = foreach ($App in @($Report.Apps)) {
            if ($App.IsMicrosoft) { continue }
            $AiData = $App.IsAiConnector -and @($App.DataPermissions).Count -gt 0
            if ($App.Risk -notin @('Critical', 'High') -and -not $AiData) { continue }
            $Allowed = $false
            foreach ($Entry in $Allow) {
                if ($App.AppId -and $Entry -eq $App.AppId) { $Allowed = $true; break }
                if ($App.DisplayName -like $Entry) { $Allowed = $true; break }
            }
            if ($Allowed) { continue }

            $Scopes = @(@($App.HighRiskPermissions) + @(if ($AiData) { $App.DataPermissions }) | Sort-Object -Unique)
            $LastUse = if (-not $App.SignInKnown) { 'unknown (no Entra ID P1)' } elseif ($App.LastSignIn) { ([datetime]$App.LastSignIn).ToString('yyyy-MM-dd') } else { 'none recorded' }
            [pscustomobject]@{
                Id              = "$($App.AppId)|$($Scopes -join ',')"
                Severity        = $App.Risk
                App             = $App.DisplayName
                AppId           = $App.AppId
                Publisher       = "$($App.Publisher)$(if (-not $App.PublisherVerified) { ' (unverified)' })"
                AiTool          = $App.AiTool
                Score           = $App.Score
                Consent         = $App.ConsentScope
                HighRiskScopes  = $Scopes -join ', '
                BlastRadius     = $App.BlastRadius
                Reasons         = @($App.Reasons) -join ' '
                LastSignIn      = $LastUse
                SuggestedAction = $App.SuggestedAction
            }
        }
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "OAuth high-risk grant check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev Error
    }
}
