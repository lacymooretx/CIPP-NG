function Get-CIPPDriverUpdateQueue {
    <#
    .SYNOPSIS
        Lists a tenant's Windows driver update profiles and the drivers in them, by default only those awaiting review.
    .DESCRIPTION
        GET beta deviceManagement/windowsDriverUpdateProfiles, then one driverInventories read per profile (batched),
        filtered server-side on approvalStatus (default needsReview; 'all' reads everything). Verified live
        2026-10-31: the approvalStatus $filter is honoured, and an unfiltered inventory pages at 200 rows.

        Driver update management needs Windows Enterprise E3/E5 (or Microsoft 365 Business Premium / A3 / A5)
        rights and the tenant's devices onboarded to Windows Update for Business deployment service / Autopatch;
        a tenant without them answers 400/403 on the profile list, which is returned in Errors with Available =
        $false rather than as "no drivers to review".

        Returns @{ Tenant; Available; Profiles = @(@{ Id; Name; ApprovalType; DeferralDays; Autopatch; NeedsReview });
        Drivers = @(row per driver); Errors }. Each driver row carries Tenant, ProfileId and DriverId so the
        frontend can post it straight to ExecDriverUpdateAction. Read only. Aspendora fork addition (Vikunja CIPP-24).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [ValidateSet('needsReview', 'approved', 'declined', 'suspended', 'all')]
        [string]$Status = 'needsReview'
    )

    $Errors = [System.Collections.Generic.List[string]]::new()
    try {
        $Profiles = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles' -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
    } catch {
        $Err = (Get-CippException -Exception $_).NormalizedError
        return [pscustomobject]@{ Tenant = $TenantFilter; Available = $false; Profiles = @(); Drivers = @(); Errors = @("Driver update profiles could not be read (needs Windows E3/E5 or Business Premium rights and WUfB deployment service onboarding): $Err") }
    }

    $ProfileRows = [System.Collections.Generic.List[object]]::new()
    $Drivers = [System.Collections.Generic.List[object]]::new()
    if ($Profiles.Count -gt 0) {
        $Query = if ($Status -eq 'all') { '' } else { "?`$filter=approvalStatus%20eq%20'$Status'" }
        $Requests = @($Profiles | ForEach-Object { [pscustomobject]@{ id = [string]$_.id; method = 'GET'; url = "/deviceManagement/windowsDriverUpdateProfiles/$($_.id)/driverInventories$Query" } })
        $Results = @(New-GraphBulkRequest -Requests $Requests -tenantid $TenantFilter)
        foreach ($P in $Profiles) {
            $R = $Results | Where-Object { [string]$_.id -eq [string]$P.id } | Select-Object -First 1
            $Autopatch = [string]$P.description -match 'created by Windows Autopatch'
            $Ok = $R -and ($null -eq $R.status -or ($R.status -ge 200 -and $R.status -lt 300))
            if (-not $Ok) {
                $Errors.Add("Driver inventory for '$($P.displayName)': $(if ($R) { "HTTP $($R.status) $([string]$R.body.error.message)" } else { 'no response' })")
            }
            $Items = if ($Ok) { @($R.body.value | Where-Object { $_.id }) } else { @() }
            $ProfileRows.Add([pscustomobject]@{
                    Id           = [string]$P.id
                    Name         = [string]$P.displayName
                    ApprovalType = [string]$P.approvalType
                    DeferralDays = $P.deploymentDeferralInDays
                    Autopatch    = $Autopatch
                    Inventory    = if ($Ok) { 'Read' } else { 'Unavailable' }
                    NeedsReview  = @($Items | Where-Object { $_.approvalStatus -eq 'needsReview' }).Count
                })
            foreach ($I in $Items) {
                $Drivers.Add([pscustomobject]@{
                        Tenant                = $TenantFilter
                        ProfileId             = [string]$P.id
                        ProfileName           = [string]$P.displayName
                        ApprovalType          = [string]$P.approvalType
                        Autopatch             = $Autopatch
                        DriverId              = [string]$I.id
                        Name                  = [string]$I.name
                        Version               = [string]$I.version
                        Manufacturer          = [string]$I.manufacturer
                        DriverClass           = [string]$I.driverClass
                        Category              = [string]$I.category
                        ApprovalStatus        = [string]$I.approvalStatus
                        ApplicableDeviceCount = [int]$I.applicableDeviceCount
                        ReleaseDate           = [string]$I.releaseDateTime
                        DeployDate            = if ([string]$I.deployDateTime -match '^0001-') { '' } else { [string]$I.deployDateTime }
                    })
            }
        }
    }

    [pscustomobject]@{
        Tenant    = $TenantFilter
        Available = $true
        Profiles  = @($ProfileRows)
        Drivers   = @($Drivers | Sort-Object -Property @{ Expression = 'ApplicableDeviceCount'; Descending = $true }, Name)
        Errors    = @($Errors)
    }
}
