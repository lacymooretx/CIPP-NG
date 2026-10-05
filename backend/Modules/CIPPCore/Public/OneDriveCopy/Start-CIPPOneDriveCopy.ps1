function Start-CIPPOneDriveCopy {
    <#
    .SYNOPSIS
        Copies a user's OneDrive into a new folder in another user's OneDrive (preflight or start)
    .DESCRIPTION
        The typical use is an offboarding hand-off: the departed user's files land in
        "From <name> (<date>)" in the manager's OneDrive. The source is never modified.

        Uses SharePoint's server-side copy (CreateCopyJobs, MoveButKeepSource) through the same
        helpers and the same SharePointLibraryCopy operation table as upstream's library copy. That
        keeps version history and metadata, and the work runs inside SharePoint rather than CIPP.
        Upstream's library-copy entry point is deliberately not reused: its eligibility check
        rejects a OneDrive's Documents library (BaseTemplate 700, Graph template
        mySiteDocumentLibrary) and it always copies into the destination library root.

        The destination OneDrive must already exist. SharePoint refuses app-only personal-site
        provisioning in every tenant, so an unprovisioned target fails preflight with the fix
        (the user signs in to OneDrive once).
    .PARAMETER Mode
        Preflight (counts and checks, changes nothing) or Start.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$SourceUser,
        [Parameter(Mandatory = $true)][string]$DestinationUser,
        [ValidateSet('Preflight', 'Start')][string]$Mode = 'Preflight',
        [string]$FolderName,
        [string]$StartedBy = 'CIPP-API',
        $Headers,
        [string]$APIName = 'OneDriveCopy'
    )

    $Graph = 'https://graph.microsoft.com/v1.0'
    if ($SourceUser.Trim().ToLower() -eq $DestinationUser.Trim().ToLower()) {
        throw 'Source and destination must be different users.'
    }

    $GetUser = {
        param($Upn)
        try {
            New-GraphGetRequest -uri "$Graph/users/$([uri]::EscapeDataString($Upn))?`$select=id,displayName,userPrincipalName" -tenantid $TenantFilter -AsApp $true -noPagination $true -ErrorAction Stop
        } catch { throw "User '$Upn' was not found in $TenantFilter." }
    }
    $GetDrive = {
        param($UserId, $Upn, $Role)
        try {
            New-GraphGetRequest -uri "$Graph/users/$UserId/drive?`$select=id,webUrl,quota" -tenantid $TenantFilter -AsApp $true -noPagination $true -ErrorAction Stop
        } catch {
            if ($Role -eq 'destination') {
                throw "$Upn has no OneDrive yet. OneDrive can't be created app-only; ask the user (or sign in as them) to open OneDrive once, then retry."
            }
            throw "$Upn has no OneDrive to copy from."
        }
    }

    $Src = & $GetUser $SourceUser
    $Dst = & $GetUser $DestinationUser
    $SrcDrive = & $GetDrive $Src.id $Src.userPrincipalName 'source'
    $DstDrive = & $GetDrive $Dst.id $Dst.userPrincipalName 'destination'

    # sharepointIds gives the site URL and list id the SharePoint copy API needs.
    $SrcRoot = New-GraphGetRequest -uri "$Graph/drives/$($SrcDrive.id)/root?`$select=sharepointIds,folder,size" -tenantid $TenantFilter -AsApp $true -noPagination $true
    $SrcSiteUrl = [string]$SrcRoot.sharepointIds.siteUrl
    $SrcListId = [string]$SrcRoot.sharepointIds.listId
    if (-not $SrcSiteUrl -or -not $SrcListId) { throw "Could not resolve the SharePoint site of $($Src.userPrincipalName)'s OneDrive." }

    $Enumerate = Get-CIPPSharePointLibraryRootChildUris -TenantFilter $TenantFilter -SiteUrl $SrcSiteUrl -ListId $SrcListId
    $Count = [int]$Enumerate.EligibleRootCount

    $Folder = if ($FolderName) { $FolderName.Trim() } else { "From $($Src.displayName) ($((Get-Date).ToString('yyyy-MM-dd')))" }
    # OneDrive rejects these characters in item names.
    $Folder = ($Folder -replace '["*:<>?/\\|]', '-').Trim().TrimEnd('.')
    if (-not $Folder) { throw 'Folder name is empty after removing characters OneDrive does not allow.' }

    $SizeBytes = [int64]($SrcRoot.size ?? 0)
    $FreeBytes = [int64]($DstDrive.quota.remaining ?? 0)
    $Preflight = [ordered]@{
        SourceUser        = $Src.userPrincipalName
        DestinationUser   = $Dst.userPrincipalName
        DestinationFolder = $Folder
        RootItemCount     = $Count
        SourceSizeGB      = [math]::Round($SizeBytes / 1GB, 2)
        DestinationFreeGB = [math]::Round($FreeBytes / 1GB, 2)
        Warnings          = [System.Collections.Generic.List[string]]::new()
    }
    if ($Count -eq 0) { throw "$($Src.userPrincipalName)'s OneDrive has nothing to copy." }
    if ($Count -gt 1000) { throw "$($Src.userPrincipalName)'s OneDrive has $Count items at its root (the copy API limit is 1,000). Group them into folders first." }
    if ($FreeBytes -gt 0 -and $SizeBytes -gt $FreeBytes) {
        throw "Not enough space: the source is $($Preflight.SourceSizeGB) GB and $($Dst.userPrincipalName) has $($Preflight.DestinationFreeGB) GB free."
    }
    if ($Count -gt 200) { $Preflight.Warnings.Add("$Count root items means $Count SharePoint copy jobs; large copies can take hours.") }

    if ($Mode -eq 'Preflight') {
        $Preflight.Message = "Ready to copy $Count item(s) ($($Preflight.SourceSizeGB) GB) into '$Folder' in $($Dst.userPrincipalName)'s OneDrive."
        return [PSCustomObject]$Preflight
    }

    # A fresh folder per run; 'rename' means a second run never merges into the first.
    $FolderBody = @{ name = $Folder; folder = @{}; '@microsoft.graph.conflictBehavior' = 'rename' } | ConvertTo-Json -Compress
    $NewFolder = New-GraphPOSTRequest -uri "$Graph/drives/$($DstDrive.id)/root/children" -tenantid $TenantFilter -body $FolderBody -AsApp $true
    if (-not $NewFolder.webUrl) { throw "Could not create '$Folder' in $($Dst.userPrincipalName)'s OneDrive." }

    $CopyJobs = Invoke-CIPPSharePointCreateCopyJobs -TenantFilter $TenantFilter -SourceSiteUrl $SrcSiteUrl `
        -ExportObjectUris $Enumerate.ChildUris -DestinationUri ([string]$NewFolder.webUrl) -NameConflictBehavior 1

    $OperationId = (New-Guid).Guid
    $HandleStates = @($CopyJobs | ForEach-Object { [PSCustomObject]@{ Status = 'Queued'; IsComplete = $false } })
    Set-CIPPSharePointLibraryCopyOperation -TenantFilter $TenantFilter -OperationId $OperationId -Entity @{
        Kind              = 'OneDriveCopy'
        SourceUser        = [string]$Src.userPrincipalName
        DestinationUser   = [string]$Dst.userPrincipalName
        DestinationFolder = [string]$NewFolder.name
        DestinationUrl    = [string]$NewFolder.webUrl
        SourceSiteUrl     = $SrcSiteUrl
        SourceSiteName    = "OneDrive - $($Src.displayName)"
        SourceLibraryName = 'Documents'
        DestSiteName      = "OneDrive - $($Dst.displayName)"
        DestLibraryName   = [string]$NewFolder.name
        StartedBy         = $StartedBy
        Status            = 'Processing'
        JobHandleCount    = $CopyJobs.Count
        Expiry            = ([DateTime]::UtcNow.AddDays(7)).ToString('o')
        CopyJobInfos      = @($CopyJobs)
        HandleStates      = (ConvertTo-Json -InputObject @($HandleStates) -Compress -Depth 4)
        SanitizedSnapshot = (ConvertTo-Json -InputObject @{
                OperationId   = $OperationId
                Status        = 'Processing'
                JobsComplete  = 0
                JobsTotal     = $CopyJobs.Count
                TotalErrors   = 0
                TotalWarnings = 0
                Message       = 'Copy queued.'
            } -Compress)
    }

    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -sev Info `
        -message "Started OneDrive copy ${OperationId}: $($Src.userPrincipalName) -> $($Dst.userPrincipalName) '$($NewFolder.name)' ($Count items, $($CopyJobs.Count) jobs)"

    [PSCustomObject]@{
        OperationId       = $OperationId
        SourceUser        = $Src.userPrincipalName
        DestinationUser   = $Dst.userPrincipalName
        DestinationFolder = $NewFolder.name
        DestinationUrl    = $NewFolder.webUrl
        JobCount          = $CopyJobs.Count
        Message           = "Copying $Count item(s) into '$($NewFolder.name)' in $($Dst.userPrincipalName)'s OneDrive. Progress: OneDrive copies list."
    }
}
