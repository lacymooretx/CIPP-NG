function Invoke-ListTeamsFileResolution {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Site.Read
    .SYNOPSIS
        Resolves a Teams chat or channel file to its real storage location and permissions, and suggests the smallest fix
    .DESCRIPTION
        Read only, single tenant. Give url (a Teams file link, a SharePoint / OneDrive sharing link or a direct file URL),
        or userPrincipalName plus fileName to search that user's OneDrive "Microsoft Teams Chat Files" folder and their
        teams' libraries (bounded: 25 teams, 25 candidates). Returns where the file really lives (the uploader's OneDrive
        for chat files, the team site for standard channels, a separate site for private and shared channels), the
        site and drive URLs, owner and item path, every permission on the item (sharing-link scope, never the link URL),
        and, with affectedUser, whether that user is covered and how, team versus channel membership, the teams a shared
        channel is shared with, external (other-tenant) shared-channel members with the B2B direct connect inbound
        setting for their tenant, and a plain-English most likely cause with the smallest fix and a link to the CIPP
        page that applies it. Changes nothing. Aspendora fork addition (Vikunja CIPP-33).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant the file belongs to. AllTenants is not supported.
    $TenantFilter = [string]$Request.Query.tenantFilter
    # The file link: a Teams file link (teams.microsoft.com/l/file/...), a sharing link, or the file's browser URL.
    $Url = [string]$Request.Query.url
    # Optional. The user who cannot open the file (UPN or object ID); their access is checked and drives the suggested fix.
    $AffectedUser = [string]$Request.Query.affectedUser
    # Search mode, with fileName: the user whose chat files and teams are searched. For a chat file, give the sender.
    $UserPrincipalName = [string]$Request.Query.userPrincipalName
    # Search mode, with userPrincipalName: all or part of the file name.
    $FileName = [string]$Request.Query.fileName

    $Bad = { param($Message) [HttpResponseContext]@{ StatusCode = [System.Net.HttpStatusCode]::BadRequest; Body = @{ Results = $Message } } }
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') { return (& $Bad 'Select a single tenant: the file is resolved live in one tenant.') }
    $Params = @{ TenantFilter = $TenantFilter }
    if ($AffectedUser.Trim()) { $Params.AffectedUser = $AffectedUser.Trim() }
    if ($Url.Trim()) {
        $Params.Url = $Url.Trim()
    } elseif ($UserPrincipalName.Trim() -and $FileName.Trim()) {
        $Params.UserPrincipalName = $UserPrincipalName.Trim()
        $Params.FileName = $FileName.Trim()
    } else {
        return (& $Bad 'Give url, or userPrincipalName and fileName.')
    }

    try {
        $Body = Get-CIPPTeamsFileResolution @Params
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch [System.ArgumentException] {
        # Input the resolver refuses (not a web link, a Teams link without objectUrl): the caller's to fix.
        return (& $Bad $_.Exception.Message)
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to resolve the Teams file: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to resolve the Teams file: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
