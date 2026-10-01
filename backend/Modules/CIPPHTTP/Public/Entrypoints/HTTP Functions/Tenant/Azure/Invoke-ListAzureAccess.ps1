function Invoke-ListAzureAccess {
    <#
    .SYNOPSIS
        Azure subscription access per tenant for the Azure compliance suite
    .DESCRIPTION
        Shows, per tenant, which Azure subscriptions the CIPP-SAM app can read (from the
        AzureSubscriptions cache, or live with Live=true for a single tenant) and the commands a
        subscription Owner runs once to grant it Reader. Status is 'Onboarded' (at least one
        subscription readable), 'NotOnboarded' (none readable: no Reader grant, or no Azure),
        'NotCollected' (no Azure collection has run yet) or 'Error' (live check failed).
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Reports.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.TenantFilter ?? $Request.Body.TenantFilter
    $Live = $Request.Query.Live ?? $Request.Body.Live

    try {
        if (-not $TenantFilter) { throw 'TenantFilter is required' }
        if ($Live -eq $true -and $TenantFilter -eq 'AllTenants') { throw 'Live checks run against a single tenant' }

        $Tenants = if ($TenantFilter -eq 'AllTenants') { Get-Tenants } else { Get-Tenants -TenantFilter $TenantFilter -IncludeErrors }
        $AppId = $env:ApplicationID
        $Table = Get-CIPPTable -tablename 'CippReportingDB'

        $Results = foreach ($Tenant in @($Tenants)) {
            $Domain = $Tenant.defaultDomainName
            $Subscriptions = $null
            $LastCollected = $null
            $ErrorText = $null

            if ($Live -eq $true) {
                try {
                    $Subscriptions = @(New-CIPPAzureRequest -TenantFilter $Domain -Uri '/subscriptions?api-version=2022-12-01')
                    $LastCollected = (Get-Date).ToUniversalTime().ToString('o')
                } catch {
                    $ErrorText = $_.Exception.Message
                }
            } else {
                $CountRow = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$Domain' and RowKey eq 'AzureSubscriptions-Count'"
                if ($CountRow) {
                    $LastCollected = $CountRow.Timestamp
                    $Subscriptions = @(New-CIPPDbRequest -TenantFilter $Domain -Type 'AzureSubscriptions')
                }
            }

            $Status = if ($ErrorText) { 'Error' }
            elseif ($null -eq $Subscriptions) { 'NotCollected' }
            elseif (@($Subscriptions).Count -gt 0) { 'Onboarded' }
            else { 'NotOnboarded' }

            $SubIds = @($Subscriptions | ForEach-Object { $_.subscriptionId })
            $Scopes = if ($SubIds.Count -gt 0) { $SubIds | ForEach-Object { "/subscriptions/$_" } } else { @('/subscriptions/<subscription-id>') }

            [pscustomobject]@{
                Tenant            = $Domain
                TenantName        = $Tenant.displayName
                TenantId          = $Tenant.customerId
                Status            = $Status
                SubscriptionCount = $SubIds.Count
                Subscriptions     = @($Subscriptions | ForEach-Object { [pscustomobject]@{ subscriptionId = $_.subscriptionId; displayName = $_.displayName; state = $_.state } })
                LastCollected     = $LastCollected
                Error             = $ErrorText
                GrantAzCli        = (@("az login --tenant $($Tenant.customerId)") + @($Scopes | ForEach-Object { "az role assignment create --assignee $AppId --role Reader --scope $_" })) -join "`n"
                GrantPowerShell   = (@("Connect-AzAccount -Tenant $($Tenant.customerId)") + @($Scopes | ForEach-Object { "New-AzRoleAssignment -ApplicationId $AppId -RoleDefinitionName Reader -Scope $_" })) -join "`n"
            }
        }

        $StatusCode = [HttpStatusCode]::OK
        $Body = @($Results)
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to list Azure access: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::BadRequest
        $Body = @{ Results = "Failed to list Azure access: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
