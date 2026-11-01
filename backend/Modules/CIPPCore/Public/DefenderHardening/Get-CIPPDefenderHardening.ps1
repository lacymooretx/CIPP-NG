function Get-CIPPDefenderHardening {
    <#
    .SYNOPSIS
        Defender for Endpoint hardening posture for one tenant: Network Protection, Device Control, and a marker
        for the portal-only web content filtering settings.
    .DESCRIPTION
        Read-only. Network Protection and Device Control come from the tenant's assigned Settings Catalog /
        endpoint security policies (Resolve-CIPPDefenderHardeningState).
        Web content filtering policies and the Advanced features toggle that enables them live only in the
        Defender portal (Settings > Endpoints > Advanced features / Web content filtering). Neither Microsoft Graph
        nor the Defender for Endpoint API documents an endpoint for them (as of 2026-10-31; the portal uses an
        undocumented internal API, not built on here), so the row is reported as Manual with
        no state rather than guessed. What CIPP can check is the prerequisite: Network Protection in Block.
        Returns @{ Tenant; Controls; Errors; Notes }. Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)
    $Inventory = Get-CIPPDefenderPolicyInventory -TenantFilter $TenantFilter
    $Controls = @(Resolve-CIPPDefenderHardeningState -Policies @($Inventory.Policies))
    $Controls += [pscustomobject]@{
        Control  = 'WebContentFiltering'
        State    = 'NotApiReachable'
        Status   = 'Manual'
        Policies = ''
        Detail   = 'Configured only in the Defender portal (Settings > Endpoints > Advanced features > Web content filtering, then Settings > Endpoints > Web content filtering). No Graph or MDE API exposes it; check by hand. Needs Network Protection in Block to enforce outside Edge.'
    }
    [pscustomobject]@{
        Tenant   = $TenantFilter
        Controls = $Controls
        Errors   = @($Inventory.Errors)
        Notes    = @($Inventory.Notes)
    }
}
