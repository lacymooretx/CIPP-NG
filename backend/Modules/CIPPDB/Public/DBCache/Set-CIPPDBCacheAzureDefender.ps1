function Set-CIPPDBCacheAzureDefender {
    <#
    .SYNOPSIS
        Caches Microsoft Defender for Cloud configuration per subscription
    .DESCRIPTION
        One item per subscription: plan pricings, security contacts and integration settings
        (WDATP = Defender for Endpoint, MCAS = Defender for Cloud Apps). These are ARM-only
        settings, not exposed by Resource Graph. A part that fails is recorded in `errors` so a
        test can skip instead of reporting a false failure.
    .PARAMETER TenantFilter
        The tenant to cache Defender for Cloud configuration for
    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    $Parts = [ordered]@{
        pricings         = 'providers/Microsoft.Security/pricings?api-version=2024-01-01'
        securityContacts = 'providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview'
        settings         = 'providers/Microsoft.Security/settings?api-version=2022-05-01'
    }

    try {
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzureDefender' -ScriptBlock {
            param($SubscriptionIds)
            foreach ($SubscriptionId in $SubscriptionIds) {
                $Entry = [ordered]@{ id = $SubscriptionId; subscriptionId = $SubscriptionId; errors = @{} }
                foreach ($Part in $Parts.Keys) {
                    try {
                        $Entry[$Part] = @(New-CIPPAzureRequest -TenantFilter $TenantFilter -Uri "/subscriptions/$SubscriptionId/$($Parts[$Part])" | ForEach-Object {
                                [pscustomobject]@{ name = $_.name; properties = $_.properties; kind = $_.kind }
                            })
                    } catch {
                        $Entry[$Part] = $null
                        $Entry.errors[$Part] = $_.Exception.Message
                    }
                }
                # A subscription that never registered the Microsoft.Security provider has never had
                # Defender for Cloud turned on at all — a finding in itself, not a collection error.
                $Entry.securityProviderRegistered = -not (@($Entry.errors.Values) -match 'Subscription Not Registered')
                [pscustomobject]$Entry
            }
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure Defender for Cloud configuration: $($_.Exception.Message)" -sev Error
        throw
    }
}
