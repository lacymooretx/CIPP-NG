function Invoke-ListDriverUpdateQueue {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Windows driver and firmware updates awaiting review, for one tenant or across all tenants
    .DESCRIPTION
        Lists the drivers in each Windows driver update profile (deviceManagement/windowsDriverUpdateProfiles/{id}/
        driverInventories), by default only those with approvalStatus needsReview. Status=approved|declined|suspended|all
        widens it. tenantFilter=AllTenants sweeps every tenant the caller may see (time-boxed; unreached tenants are
        listed in Skipped). Tenants without driver update management (no Windows E3/E5 / Business Premium rights or
        no WUfB deployment service onboarding) are listed in Tenants with Available = false, never as "nothing to
        review". Body: @{ Results = @(driver rows, each with Tenant, ProfileId, DriverId); Tenants = @(per-tenant
        summary); Failed; Skipped }. Read only; approve / decline / suspend is ExecDriverUpdateAction.
        Aspendora fork addition (Vikunja CIPP-24).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $Status = [string]($Request.Query.Status ?? $Request.Body.Status)
    if (-not $Status) { $Status = 'needsReview' }
    $Status = @('needsReview', 'approved', 'declined', 'suspended', 'all') | Where-Object { $_ -ieq $Status } | Select-Object -First 1
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'tenantFilter is required (a tenant or AllTenants).' } })
    }
    if (-not $Status) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Status must be needsReview, approved, declined, suspended or all.' } })
    }
    try {
        $Sweep = Invoke-CIPPTenantSweep -Request $Request -TenantFilter $TenantFilter -ScriptBlock ({ param($T) Get-CIPPDriverUpdateQueue -TenantFilter $T -Status $Status }.GetNewClosure())
        $Tenants = @($Sweep.Results | ForEach-Object {
                [pscustomobject]@{
                    Tenant    = $_.Tenant
                    Available = $_.Available
                    Profiles  = @($_.Profiles).Count
                    Drivers   = @($_.Drivers).Count
                    DevicesAffected = (@($_.Drivers | ForEach-Object { [int]$_.ApplicableDeviceCount }) | Measure-Object -Sum).Sum
                    Errors    = @($_.Errors)
                    ProfileList = @($_.Profiles)
                }
            })
        $Body = [pscustomobject]@{
            Results = @($Sweep.Results | ForEach-Object { $_.Drivers })
            Tenants = $Tenants
            Failed  = @($Sweep.Failed)
            Skipped = @($Sweep.Skipped)
            Status  = $Status
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Body })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Driver update queue failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
