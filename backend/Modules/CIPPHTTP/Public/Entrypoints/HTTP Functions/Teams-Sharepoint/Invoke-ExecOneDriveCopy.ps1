function Invoke-ExecOneDriveCopy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Site.ReadWrite
    .DESCRIPTION
        Copies a user's OneDrive into a new folder ("From <name> (<date>)" unless FolderName is given)
        in another user's OneDrive using SharePoint server-side copy jobs. Action Preflight checks
        and counts without changing anything; Action Start creates the folder and queues the copy.
        Track progress with ListOneDriveCopies.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Body.tenantFilter.value ?? $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action ?? 'Preflight')
    $SourceUser = $Request.Body.SourceUser.value ?? $Request.Body.SourceUser ?? $Request.Body.userPrincipalName
    $DestinationUser = $Request.Body.DestinationUser.value ?? $Request.Body.DestinationUser
    $FolderName = [string]$Request.Body.FolderName

    try {
        if (-not $TenantFilter) { throw 'tenantFilter is required.' }
        if (-not $SourceUser -or -not $DestinationUser) { throw 'SourceUser and DestinationUser are required.' }
        if ($Action -notin @('Preflight', 'Start')) { throw "Unknown Action '$Action'. Use Preflight or Start." }

        $User = try { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json } catch { $null }
        $StartedBy = $User.userDetails ?? $Headers.'x-ms-client-principal-name' ?? 'CIPP-API'

        $Result = Start-CIPPOneDriveCopy -TenantFilter $TenantFilter -SourceUser $SourceUser -DestinationUser $DestinationUser `
            -Mode $Action -FolderName $FolderName -StartedBy $StartedBy -Headers $Headers -APIName $APIName
        $StatusCode = [HttpStatusCode]::OK
        $Body = @{ Results = $Result }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "OneDrive copy $Action failed: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::BadRequest
        $Body = @{ Results = "OneDrive copy failed: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
