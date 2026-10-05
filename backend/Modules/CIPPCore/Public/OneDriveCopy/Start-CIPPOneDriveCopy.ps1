function Start-CIPPOneDriveCopy {
    <#
    .SYNOPSIS
        Copies a user's OneDrive into a new folder in another user's OneDrive (preflight or start)
    .DESCRIPTION
        The typical use is an offboarding hand-off: the departed user's files land in
        "From <name> (<date>)" in the manager's OneDrive. Options:
          -Destination NewFolder (default) | Root   - into a new folder, or straight into their OneDrive root
          -Operation   Copy (default) | Move        - Move removes each source item after it is copied
          -ConflictBehavior Rename (default) | Fail | Replace - when a same-named item already exists

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
        [ValidateSet('NewFolder', 'Root')][string]$Destination = 'NewFolder',
        [ValidateSet('Copy', 'Move')][string]$Operation = 'Copy',
        [ValidateSet('Rename', 'Fail', 'Replace')][string]$ConflictBehavior = 'Rename',
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

    $Folder = $null
    if ($Destination -eq 'NewFolder') {
        $Folder = if ($FolderName) { $FolderName.Trim() } else { "From $($Src.displayName) ($((Get-Date).ToString('yyyy-MM-dd')))" }
        # OneDrive rejects these characters in item names.
        $Folder = ($Folder -replace '["*:<>?/\\|]', '-').Trim().TrimEnd('.')
        if (-not $Folder) { throw 'Folder name is empty after removing characters OneDrive does not allow.' }
    }
    # SharePoint copy job NameConflictBehavior: 0 = fail (skip the item), 1 = replace, 2 = keep both (rename).
    $ConflictCode = switch ($ConflictBehavior) { 'Fail' { 0 } 'Replace' { 1 } default { 2 } }

    $SizeBytes = [int64]($SrcRoot.size ?? 0)
    $FreeBytes = [int64]($DstDrive.quota.remaining ?? 0)
    $Preflight = [ordered]@{
        SourceUser        = $Src.userPrincipalName
        DestinationUser   = $Dst.userPrincipalName
        Destination       = $(if ($Folder) { "New folder '$Folder'" } else { 'OneDrive root' })
        DestinationFolder = $Folder
        Operation         = $Operation
        ConflictBehavior  = $ConflictBehavior
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
    if ($Operation -eq 'Move') { $Preflight.Warnings.Add("MOVE: each item is removed from $($Src.userPrincipalName)'s OneDrive after it is copied.") }
    if ($Destination -eq 'Root' -and $ConflictBehavior -eq 'Replace') { $Preflight.Warnings.Add("Replace into the OneDrive root overwrites $($Dst.userPrincipalName)'s files that have the same name.") }

    if ($Mode -eq 'Preflight') {
        $Verb = $Operation.ToLower()
        $Where = if ($Folder) { "'$Folder' in" } else { 'the root of' }
        $Preflight.Message = "Ready to $Verb $Count item(s) ($($Preflight.SourceSizeGB) GB) into $Where $($Dst.userPrincipalName)'s OneDrive."
        return [PSCustomObject]$Preflight
    }

    if ($Destination -eq 'NewFolder') {
        # A fresh folder per run; 'rename' means a second run never merges into the first.
        $FolderBody = @{ name = $Folder; folder = @{}; '@microsoft.graph.conflictBehavior' = 'rename' } | ConvertTo-Json -Compress
        $Target = New-GraphPOSTRequest -uri "$Graph/drives/$($DstDrive.id)/root/children" -tenantid $TenantFilter -body $FolderBody -AsApp $true
        if (-not $Target.webUrl) { throw "Could not create '$Folder' in $($Dst.userPrincipalName)'s OneDrive." }
    } else {
        $Target = [pscustomobject]@{ name = 'OneDrive root'; webUrl = [string]$DstDrive.webUrl }
    }

    $CopyJobs = Invoke-CIPPSharePointCreateCopyJobs -TenantFilter $TenantFilter -SourceSiteUrl $SrcSiteUrl `
        -ExportObjectUris $Enumerate.ChildUris -DestinationUri ([string]$Target.webUrl) -NameConflictBehavior $ConflictCode `
        -IsMoveMode ($Operation -eq 'Move')

    $OperationId = (New-Guid).Guid
    $HandleStates = @($CopyJobs | ForEach-Object { [PSCustomObject]@{ Status = 'Queued'; IsComplete = $false } })
    Set-CIPPSharePointLibraryCopyOperation -TenantFilter $TenantFilter -OperationId $OperationId -Entity @{
        Kind              = 'OneDriveCopy'
        Operation         = $Operation
        ConflictBehavior  = $ConflictBehavior
        SourceUser        = [string]$Src.userPrincipalName
        DestinationUser   = [string]$Dst.userPrincipalName
        DestinationFolder = [string]$Target.name
        DestinationUrl    = [string]$Target.webUrl
        SourceSiteUrl     = $SrcSiteUrl
        SourceSiteName    = "OneDrive - $($Src.displayName)"
        SourceLibraryName = 'Documents'
        DestSiteName      = "OneDrive - $($Dst.displayName)"
        DestLibraryName   = [string]$Target.name
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
        -message "Started OneDrive $($Operation.ToLower()) ${OperationId}: $($Src.userPrincipalName) -> $($Dst.userPrincipalName) '$($Target.name)' ($Count items, $($CopyJobs.Count) jobs)"

    [PSCustomObject]@{
        OperationId       = $OperationId
        SourceUser        = $Src.userPrincipalName
        DestinationUser   = $Dst.userPrincipalName
        DestinationFolder = $Target.name
        DestinationUrl    = $Target.webUrl
        JobCount          = $CopyJobs.Count
        Operation         = $Operation
        Message           = "$(if ($Operation -eq 'Move') { 'Moving' } else { 'Copying' }) $Count item(s) into $(if ($Folder) { "'$($Target.name)' in" } else { 'the root of' }) $($Dst.userPrincipalName)'s OneDrive. Progress: Teams & SharePoint > OneDrive Copies."
    }
}
