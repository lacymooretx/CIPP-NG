function Set-CIPPDBCacheAzureResourceConfig {
    <#
    .SYNOPSIS
        Caches per-resource settings that Resource Graph doesn't expose
    .DESCRIPTION
        Reads the resource list from the AzureResources cache (so it must run after that collector)
        and makes targeted ARM GETs:
          - storage accounts: blob service soft-delete / versioning
          - key vaults: diagnostic settings
          - SQL servers: firewall rules, auditing, Defender for SQL (security alert policy)
          - web apps: site config (TLS, FTP, remote debugging, HTTP/2)
        One item per resource, keyed by the resource id, with the sub-call results under `config`.
        A sub-call that fails is recorded in `errors` so a test can skip instead of falsely failing.
        Each resource type is capped at $MaxPerType resources to bound the run on large estates.
    .PARAMETER TenantFilter
        The tenant to cache Azure resource configuration for
    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    $MaxPerType = 250
    $Calls = @{
        'microsoft.storage/storageaccounts' = [ordered]@{ blobService = 'blobServices/default?api-version=2023-05-01' }
        'microsoft.keyvault/vaults'         = [ordered]@{ diagnosticSettings = 'providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview' }
        'microsoft.sql/servers'             = [ordered]@{
            firewallRules        = 'firewallRules?api-version=2021-11-01'
            auditingSettings     = 'auditingSettings/default?api-version=2021-11-01'
            securityAlertPolicy  = 'securityAlertPolicies/Default?api-version=2021-11-01'
        }
        'microsoft.web/sites'               = [ordered]@{ siteConfig = 'config/web?api-version=2023-12-01' }
    }

    try {
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzureResourceConfig' -ScriptBlock {
            param($SubscriptionIds)
            $Resources = @(New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'AzureResources' -Fields 'id', 'type')
            foreach ($ResourceType in $Calls.Keys) {
                $OfType = @($Resources | Where-Object { $_.type -eq $ResourceType })
                if ($OfType.Count -gt $MaxPerType) {
                    Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "AzureResourceConfig: $($OfType.Count) $ResourceType resources, only the first $MaxPerType inspected" -sev Warning
                    $OfType = $OfType[0..($MaxPerType - 1)]
                }
                foreach ($Resource in $OfType) {
                    $Entry = [ordered]@{ id = $Resource.id; type = $ResourceType; config = [ordered]@{}; errors = @{} }
                    foreach ($Name in $Calls[$ResourceType].Keys) {
                        try {
                            $Entry.config[$Name] = New-CIPPAzureRequest -TenantFilter $TenantFilter -Uri "$($Resource.id)/$($Calls[$ResourceType][$Name])"
                        } catch {
                            $Entry.config[$Name] = $null
                            $Entry.errors[$Name] = $_.Exception.Message
                        }
                    }
                    [pscustomobject]$Entry
                }
            }
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure resource configuration: $($_.Exception.Message)" -sev Error
        throw
    }
}
