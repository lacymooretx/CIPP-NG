function Get-CIPPAlertAzureElevatedAccess {
    <#
    .SYNOPSIS
        Alert when a Global Admin uses "elevate access" (Access management for Azure resources) in a tenant
    .DESCRIPTION
        "Elevate access" gives a Global Admin User Access Administrator at the root scope "/", over every Azure
        subscription and management group of the tenant. GDAP partner admins cannot do it (Azure returns 403 on
        Microsoft.Authorization/elevateAccess/action), so in a client tenant only a native account can.

        Two signals, each reported through its own lifecycle:
          1. Events (append mode, this cmdlet name): Entra directory audit records in category
             AzureRBACRoleManagementElevateAccess from the last 25 hours. Elevating raises a Warning; removing the
             elevation raises Info. Each audit record notifies once (stable Id = audit id).
          2. Standing access (state mode, cmdlet name + 'RootScope'): role assignments at scope "/" seen through any
             Azure subscription CIPP-SAM can read in the tenant (Reader is enough, inherited assignments are listed).
             Each one raises a Warning once and resolves when it is removed. Tenants where CIPP reads no subscription
             skip this silently.
        Accounts listed in AllowedElevationActors (comma separated UPNs or object ids) are left out of both, for
        elevations the MSP keeps on purpose. A signal whose read fails is not reported, because "could not check" is
        not "clear". Report only: nothing in the tenant or Azure is changed. Aspendora fork addition (Vikunja CIPP-45).
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
    $CmdletName = [string]$MyInvocation.MyCommand
    $AllowedRaw = if ($InputValue -is [string]) { $InputValue } else { [string]$InputValue.AllowedElevationActors }
    $Allowed = @($AllowedRaw -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLowerInvariant() })
    $IsAllowed = {
        param($Id, $Upn)
        ($Id -and $Allowed -contains ([string]$Id).ToLowerInvariant()) -or ($Upn -and $Allowed -contains ([string]$Upn).ToLowerInvariant())
    }
    $Notify = [System.Collections.Generic.List[object]]::new()

    # 1. Elevation events in the Entra audit log.
    try {
        $Since = [datetime]::UtcNow.AddHours(-25).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $Uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=category eq 'AzureRBACRoleManagementElevateAccess' and activityDateTime ge $Since"
        $Events = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -AsApp $true -ErrorAction Stop | Where-Object { $_.id })
        $Rows = foreach ($E in $Events) {
            $User = $E.initiatedBy.user
            $Actor = if ($User.userPrincipalName) { [string]$User.userPrincipalName } elseif ($E.initiatedBy.app.displayName) { [string]$E.initiatedBy.app.displayName } else { [string]$User.id }
            if (& $IsAllowed $User.id $User.userPrincipalName) { continue }
            $Removed = [string]$E.activityDisplayName -match 'remov'
            [pscustomobject]@{
                Id        = "ElevateAccess|$($E.id)"
                Severity  = $(if ($Removed) { 'Info' } else { 'Warning' })
                Signal    = 'Audit'
                Actor     = $Actor
                Activity  = [string]$E.activityDisplayName
                Result    = [string]$E.result
                WhenUtc   = [string]$E.activityDateTime
                IPAddress = [string]$User.ipAddress
                Message   = $(if ($Removed) {
                        "$Actor removed their elevated Azure access ($($E.activityDisplayName), $($E.result))."
                    } else {
                        "$Actor used 'elevate access' ($($E.activityDisplayName), $($E.result)). They now hold User Access Administrator over every Azure subscription and management group in the tenant. Confirm with the client who did it and why, and remove it (Entra admin center > Properties > Access management for Azure resources = No) when it is not needed."
                    })
            }
        }
        $Rows = @($Rows)
        foreach ($N in @(Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data $Rows -Append | Where-Object { $_ })) { $Notify.Add($N) }
    } catch {
        $ErrorData = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Elevated access: audit log check failed: $($ErrorData.NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$($ErrorData.NormalizedError) $_") -LogData $ErrorData
    }

    # 2. Standing root-scope role assignments, through the subscriptions CIPP-SAM can read.
    try {
        $Arm = 'https://management.azure.com/.default'
        $Subs = @(New-GraphGetRequest -uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' -tenantid $TenantFilter -scope $Arm -AsApp $true -ErrorAction Stop | Where-Object { $_.subscriptionId })
        if ($Subs.Count -gt 0) {
            $RootAssignments = @{}
            $SubErrors = 0
            foreach ($Sub in $Subs) {
                try {
                    $Assignments = @(New-GraphGetRequest -uri "https://management.azure.com/subscriptions/$($Sub.subscriptionId)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" -tenantid $TenantFilter -scope $Arm -AsApp $true -ErrorAction Stop)
                    foreach ($A in $Assignments) {
                        if ([string]$A.properties.scope -eq '/') { $RootAssignments[[string]$A.name] = $A }
                    }
                } catch { $SubErrors++ }
            }
            if ($SubErrors -eq $Subs.Count) { throw "could not read role assignments in any of $($Subs.Count) subscription(s)" }
            $RoleNames = @{ '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'; '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner' }
            $Rows = foreach ($A in $RootAssignments.Values) {
                $P = $A.properties
                $PrincipalName = $null
                try {
                    $Obj = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/directoryObjects/$($P.principalId)" -tenantid $TenantFilter -AsApp $true -NoAuthCheck $true -ErrorAction Stop
                    $PrincipalName = if ($Obj.userPrincipalName) { [string]$Obj.userPrincipalName } else { [string]$Obj.displayName }
                } catch { }
                if (& $IsAllowed $P.principalId $PrincipalName) { continue }
                $RoleId = ([string]$P.roleDefinitionId -split '/')[-1]
                $Role = if ($RoleNames.ContainsKey($RoleId)) { $RoleNames[$RoleId] } else { "role $RoleId" }
                $Who = if ($PrincipalName) { $PrincipalName } else { "$($P.principalType) $($P.principalId)" }
                [pscustomobject]@{
                    Id          = "RootScope|$($A.name)"
                    Severity    = 'Warning'
                    Signal      = 'RootScope'
                    Actor       = $Who
                    PrincipalId = [string]$P.principalId
                    Role        = $Role
                    CreatedUtc  = [string]$P.createdOn
                    Message     = "$Who holds $Role at the Azure root scope '/' (since $($P.createdOn)), which covers every subscription and management group in the tenant. This is what 'elevate access' leaves behind. Remove it when it is not needed, or add the account to AllowedElevationActors if it is kept on purpose."
                }
            }
            $Rows = @($Rows)
            foreach ($N in @(Write-AlertTrace -cmdletName "$($CmdletName)RootScope" -tenantFilter $TenantFilter -data $Rows | Where-Object { $_ })) { $Notify.Add($N) }
        }
    } catch {
        $ErrorData = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Elevated access: Azure root-scope check failed: $($ErrorData.NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$($ErrorData.NormalizedError) $_") -LogData $ErrorData
    }

    $Notify.ToArray()
}
