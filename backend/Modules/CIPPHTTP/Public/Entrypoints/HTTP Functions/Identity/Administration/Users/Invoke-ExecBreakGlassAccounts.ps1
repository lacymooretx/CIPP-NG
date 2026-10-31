function Invoke-ExecBreakGlassAccounts {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.ReadWrite
    .SYNOPSIS
        Register a tenant's break-glass (emergency access) accounts for the break-glass activity alert
    .DESCRIPTION
        Action=List    (default) registered accounts for tenantFilter (AllTenants lists every tenant).
        Action=Add     registers UserPrincipalName (or UserId) in tenantFilter, with an optional Note.
        Action=Remove  unregisters UserId (or UserPrincipalName).
        Action=Suggest proposes likely break-glass accounts: the user CIPP's CA analysis sees excluded most
                       often from All-users policies, plus accounts whose name looks like break-glass/emergency.
        Registered accounts are watched by the BreakGlassActivity alert. Aspendora fork addition (Vikunja CIPP-3).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Headers = $Request.Headers
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action ?? 'List')
    $Upn = [string]($Request.Body.UserPrincipalName ?? $Request.Query.UserPrincipalName)
    $UserId = [string]($Request.Body.UserId ?? $Request.Query.UserId)
    $Note = [string]($Request.Body.Note ?? $Request.Query.Note)
    $Table = Get-CIPPTable -tablename 'BreakGlassAccounts'

    $Respond = { param($Code, $Body) [HttpResponseContext]@{ StatusCode = $Code; Body = $Body } }
    if (-not $TenantFilter) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'tenantFilter is required.' }) }

    try {
        if ($Action -eq 'List') {
            $Rows = if ($TenantFilter -eq 'AllTenants') { Get-CIPPBreakGlassAccounts } else { Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter }
            $Names = @{}
            foreach ($T in @(Get-Tenants -IncludeAll)) { $Names[[string]$T.customerId] = $T.defaultDomainName }
            $Results = @($Rows | ForEach-Object {
                    [pscustomobject]@{ Tenant = $Names[[string]$_.PartitionKey] ?? $_.PartitionKey; TenantId = $_.PartitionKey; UserId = $_.RowKey; UserPrincipalName = $_.UserPrincipalName; DisplayName = $_.DisplayName; Note = $_.Note; AddedBy = $_.AddedBy; AddedUtc = $_.AddedUtc }
                })
            return (& $Respond ([HttpStatusCode]::OK) @{ Results = $Results })
        }

        if ($TenantFilter -eq 'AllTenants') { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = "$Action needs a single tenant." }) }
        $Tenant = Get-Tenants -TenantFilter $TenantFilter
        if (-not $Tenant.customerId) { return (& $Respond ([HttpStatusCode]::NotFound) @{ Results = "Tenant $TenantFilter not found." }) }
        $TenantId = ([string]$Tenant.customerId).ToLower()

        switch ($Action) {
            'Add' {
                $Lookup = if ($UserId) { $UserId } elseif ($Upn) { $Upn } else { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'UserPrincipalName or UserId is required.' }) }
                $User = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($Lookup)?`$select=id,userPrincipalName,displayName" -tenantid $TenantFilter -ErrorAction Stop
                $Actor = try { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json).userDetails } catch { 'API client' }
                Add-CIPPAzDataTableEntity @Table -Entity @{
                    PartitionKey      = $TenantId
                    RowKey            = [string]$User.id
                    UserPrincipalName = [string]$User.userPrincipalName
                    DisplayName       = [string]$User.displayName
                    Note              = $Note
                    AddedBy           = [string]($Actor ?? 'unknown')
                    AddedUtc          = (Get-Date).ToUniversalTime().ToString('o')
                } -Force
                Write-LogMessage -headers $Headers -API 'BreakGlass' -tenant $TenantFilter -message "Registered break-glass account $($User.userPrincipalName) ($($User.id))" -Sev 'Info'
                $Results = "Registered $($User.userPrincipalName) as a break-glass account. Any sign-in or change to it now raises a High alert (when the Break-glass activity alert is scheduled for this tenant)."
            }
            'Remove' {
                $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantId'" | Where-Object { ($UserId -and $_.RowKey -eq $UserId) -or ($Upn -and $_.UserPrincipalName -eq $Upn) })
                if ($Rows.Count -eq 0) { return (& $Respond ([HttpStatusCode]::NotFound) @{ Results = 'That account is not registered for this tenant.' }) }
                Remove-AzDataTableEntity @Table -Entity $Rows -Force
                Write-LogMessage -headers $Headers -API 'BreakGlass' -tenant $TenantFilter -message "Unregistered break-glass account $($Rows[0].UserPrincipalName) ($($Rows[0].RowKey))" -Sev 'Warning'
                $Results = "Unregistered $($Rows[0].UserPrincipalName). It is no longer watched."
            }
            'Suggest' {
                $Registered = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantId'" | ForEach-Object RowKey)
                $Suggestions = [System.Collections.Generic.List[object]]::new()
                $Policies = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -tenantid $TenantFilter -ErrorAction SilentlyContinue)
                $Candidate = if ($Policies) { Get-CIPPCABreakGlassCandidate -Policies $Policies }
                if ($Candidate -and $Candidate.type -eq 'user') {
                    $Suggestions.Add([pscustomobject]@{ UserId = $Candidate.id; Reason = "Excluded from $($Candidate.count) All-users Conditional Access policies" })
                }
                $Named = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,displayName&`$top=999" -tenantid $TenantFilter -ErrorAction SilentlyContinue | Where-Object { "$($_.userPrincipalName) $($_.displayName)" -match 'break\W?glass|breaky|emergency|bglass' })
                foreach ($U in $Named) { if ($U.id -notin $Suggestions.UserId) { $Suggestions.Add([pscustomobject]@{ UserId = $U.id; Reason = 'Name looks like an emergency-access account' }) } }
                $Results = @(foreach ($S in $Suggestions) {
                        $U = $Named | Where-Object id -EQ $S.UserId | Select-Object -First 1
                        if (-not $U) { $U = try { New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($S.UserId)?`$select=id,userPrincipalName,displayName" -tenantid $TenantFilter -ErrorAction Stop } catch { $null } }
                        if ($U) { [pscustomobject]@{ UserId = $U.id; UserPrincipalName = $U.userPrincipalName; DisplayName = $U.displayName; Reason = $S.Reason; Registered = ($U.id -in $Registered) } }
                    })
            }
            default { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = "Unknown Action '$Action'. Use List, Add, Remove or Suggest." }) }
        }
        return (& $Respond ([HttpStatusCode]::OK) @{ Results = $Results })
    } catch {
        return (& $Respond ([HttpStatusCode]::InternalServerError) @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" })
    }
}
