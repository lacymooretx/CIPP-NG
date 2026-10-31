function Get-CIPPAlertOAuthHighRiskGrant {
    <#
    .SYNOPSIS
        Daily alert on high-risk OAuth grants: app-only mailbox/file/directory access, tenant-wide risky consent, AI connectors
    .DESCRIPTION
        Runs Get-CIPPOAuthGrantRisk and raises every app scored Critical or High, plus any AI connector
        (Config/ShadowAI.json) holding mail, files or sites scopes at any level, unless the app is on the allow-list.
        Each row carries the blast radius and a suggested action.

        Allow-list (input OAuthRiskAllowList): comma-separated appIds or display names; names may use * wildcards
        (e.g. "Backup Application *"); custom variables such as %oauthallowlist% are expanded.

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
        $Allow = @($AllowRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

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
