function Invoke-ExecOneDriveSharingDigest {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Admin.ReadWrite
    .SYNOPSIS
        Preview, send, approve or revoke the weekly OneDrive sharing digest for a tenant
    .DESCRIPTION
        Action=Status  (default) the tenant's digest settings, last scan and per-user link counts.
        Action=Preview renders without sending. With UserPrincipalName, returns that user's email HTML.
        Action=Send    runs the digest now: to the users when the tenant is approved, otherwise to the
                       preview recipient. PreviewRecipient forces a preview send to that address.
        Action=Approve switches the tenant to live (its users get their own digest).
        Action=Revoke  puts the tenant back into preview.
        Aspendora fork addition.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $TriggerMetadata.FunctionName
    $Headers = $Request.Headers
    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action ?? 'Status')
    $UserPrincipalName = [string]($Request.Body.UserPrincipalName ?? $Request.Query.UserPrincipalName)
    $PreviewRecipient = [string]($Request.Body.PreviewRecipient ?? $Request.Query.PreviewRecipient)

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'The OneDrive sharing digest runs against a single tenant' } })
    }

    try {
        switch ($Action) {
            'Status' {
                $Settings = Get-CIPPOneDriveSharingDigestSettings -TenantFilter $TenantFilter
                $Digest = Get-CIPPOneDriveSharingDigest -TenantFilter $TenantFilter
                $Body = @{
                    Results  = "$(@($Digest.Users).Count) user(s) with shared OneDrive items; tenant is $(if ($Settings.Live) { 'live' } else { 'in preview' })"
                    Settings = $Settings
                    Digest   = @{
                        LastScanUtc = $Digest.LastScanUtc
                        Users       = @($Digest.Users | ForEach-Object { @{ UPN = $_.UPN; Mail = $_.Mail; DisplayName = $_.DisplayName; AccountEnabled = $_.AccountEnabled; Outside = @($_.Outside).Count; Inside = @($_.Inside).Count } })
                        Unresolved  = @($Digest.Unresolved)
                    }
                }
            }
            'Preview' {
                $Params = @{ TenantFilter = $TenantFilter; DryRun = $true }
                if ($UserPrincipalName) { $Params.OnlyUsers = @($UserPrincipalName) }
                $Run = Push-ExecOneDriveSharingDigest @Params
                $Body = @{ Results = $Run.Results; Emails = @($Run.Emails); Skipped = @($Run.Skipped) }
            }
            'Send' {
                $Params = @{ TenantFilter = $TenantFilter }
                if ($PreviewRecipient) { $Params.PreviewRecipient = $PreviewRecipient }
                if ($UserPrincipalName) { $Params.OnlyUsers = @($UserPrincipalName) }
                $Run = Push-ExecOneDriveSharingDigest @Params
                Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Run.Results -Sev 'Info'
                $Body = @{ Results = $Run.Results; Sent = @($Run.Sent); Skipped = @($Run.Skipped); Failed = @($Run.Failed) }
            }
            { $_ -in @('Approve', 'Revoke') } {
                $Settings = Get-CIPPOneDriveSharingDigestSettings -TenantFilter $TenantFilter
                # API clients have no client principal header.
                $User = try { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json).userDetails } catch { 'API client' }
                $Table = Get-CIPPTable -TableName 'Config'
                $Entity = @{
                    PartitionKey = 'OneDriveSharingDigest'
                    RowKey       = [string]$Settings.Tenant
                    Live         = $Action -eq 'Approve'
                    ApprovedBy   = [string]($User ?? 'unknown')
                    ApprovedUtc  = [string](Get-Date).ToUniversalTime().ToString('o')
                }
                Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force
                $Message = if ($Action -eq 'Approve') { "OneDrive sharing digest is now live for $($Settings.Tenant): users get their own digest" } else { "OneDrive sharing digest is back in preview for $($Settings.Tenant)" }
                Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Message -Sev 'Info'
                $Body = @{ Results = $Message }
            }
            default {
                return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = "Unknown Action '$Action'. Use Status, Preview, Send, Approve or Revoke." } })
            }
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Body })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "OneDrive sharing digest $Action failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "OneDrive sharing digest $Action failed: $($ErrorMessage.NormalizedError)" } })
    }
}
