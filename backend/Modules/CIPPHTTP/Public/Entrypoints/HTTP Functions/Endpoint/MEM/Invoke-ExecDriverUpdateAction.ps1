function Invoke-ExecDriverUpdateAction {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .SYNOPSIS
        Approve, decline or suspend Windows drivers in a driver update profile
    .DESCRIPTION
        POST deviceManagement/windowsDriverUpdateProfiles/{ProfileId}/executeAction with
        @{ actionName = approve|decline|suspend; driverIds; deploymentDate }. Body/query: tenantFilter (one tenant,
        not AllTenants), ProfileId, DriverIds (one id or a list), Action (Approve | Decline | Suspend) and, for
        Approve, an optional DeploymentDate (ISO 8601, default now). Intune answers with a bulkDriverActionResult
        (successfulDriverIds / failedDriverIds / notFoundDriverIds); the drivers are then read back from the
        inventory so the response states the approvalStatus Intune actually holds, not just what was asked.
        This CHANGES tenant configuration: approved drivers start installing on devices in the profile's groups.
        If Multi Admin Approval protects driver updates, Intune refuses the call. Aspendora fork addition
        (Vikunja CIPP-24).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $ProfileId = [string]($Request.Body.ProfileId ?? $Request.Query.ProfileId)
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action)
    $DriverIds = @($Request.Body.DriverIds ?? $Request.Query.DriverIds | ForEach-Object { if ($_ -is [string]) { $_ -split ',' } else { $_ } } | ForEach-Object { ([string]($_.value ?? $_)).Trim() } | Where-Object { $_ })
    $DeploymentDate = [string]($Request.Body.DeploymentDate ?? $Request.Query.DeploymentDate)

    $Bad = { param($Text) [HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = $Text } } }
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') { return (& $Bad 'Pick a single tenant.') }
    $Guid = [guid]::Empty
    if (-not [guid]::TryParse($ProfileId, [ref]$Guid)) { return (& $Bad 'ProfileId must be the driver update profile id.') }
    $ActionName = @('approve', 'decline', 'suspend') | Where-Object { $_ -ieq $Action } | Select-Object -First 1
    if (-not $ActionName) { return (& $Bad 'Action must be Approve, Decline or Suspend.') }
    if ($DriverIds.Count -eq 0) { return (& $Bad 'DriverIds is required.') }
    # Driver ids are <64 hex>_<guid>; anything else would be pasted into the request URL filter below.
    $Invalid = @($DriverIds | Where-Object { $_ -notmatch '^[A-Za-z0-9_\-]{1,200}$' })
    if ($Invalid.Count -gt 0) { return (& $Bad "Invalid driver id(s): $($Invalid -join ', ')") }

    $Body = [ordered]@{ actionName = $ActionName; driverIds = @($DriverIds) }
    if ($ActionName -eq 'approve') {
        $When = [datetimeoffset]::UtcNow
        if ($DeploymentDate) {
            $Parsed = [datetimeoffset]::MinValue
            if (-not [datetimeoffset]::TryParse($DeploymentDate, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Parsed)) { return (& $Bad 'DeploymentDate must be an ISO 8601 date/time.') }
            $When = $Parsed
        }
        $Body.deploymentDate = $When.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    try {
        $Result = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles/$ProfileId/executeAction" -tenantid $TenantFilter -type POST -body ($Body | ConvertTo-Json -Compress -Depth 5) -ContentType 'application/json'

        # Read back what Intune now holds for these drivers.
        $Inventory = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles/$ProfileId/driverInventories?`$select=id,name,approvalStatus,deployDateTime" -tenantid $TenantFilter)
        $Now = @($Inventory | Where-Object { [string]$_.id -in $DriverIds } | ForEach-Object { [pscustomobject]@{ DriverId = [string]$_.id; Name = [string]$_.name; ApprovalStatus = [string]$_.approvalStatus; DeployDate = [string]$_.deployDateTime } })
        $Expected = @{ approve = 'approved'; decline = 'declined'; suspend = 'suspended' }[$ActionName]
        $Applied = @($Now | Where-Object { $_.ApprovalStatus -eq $Expected })
        $Names = @($Now | ForEach-Object { $_.Name }) -join ', '
        $Message = "$((Get-Culture).TextInfo.ToTitleCase($ActionName)) requested for $($DriverIds.Count) driver(s)$(if ($Names) { " ($Names)" }); $($Applied.Count) now read back as $Expected."
        if (@($Result.failedDriverIds).Count -gt 0) { $Message += " Failed: $(@($Result.failedDriverIds) -join ', ')." }
        if (@($Result.notFoundDriverIds).Count -gt 0) { $Message += " Not found: $(@($Result.notFoundDriverIds) -join ', ')." }
        $Sev = if ($Applied.Count -eq $DriverIds.Count) { 'Info' } else { 'Warning' }
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Driver update profile $($ProfileId): $Message" -Sev $Sev
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results  = $Message
                    Metadata = @{
                        Successful = @($Result.successfulDriverIds)
                        Failed     = @($Result.failedDriverIds)
                        NotFound   = @($Result.notFoundDriverIds)
                        ReadBack   = $Now
                    }
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Driver $ActionName failed for profile $($ProfileId): $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed to $ActionName driver(s): $($ErrorMessage.NormalizedError)" } })
    }
}
