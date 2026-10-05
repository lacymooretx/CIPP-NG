function Start-CIPPMailboxCopy {
    <#
    .SYNOPSIS
        Copies or moves one mailbox's content (and its online archive) into another mailbox (preflight or start)
    .DESCRIPTION
        Full-fidelity copy through the Graph mailbox import/export API (exportItems -> import session):
        mail, calendar, contacts and tasks keep their dates, senders, read state and attachments.

          -Destination NewFolder (default) | Root
              NewFolder: everything lands under "From <name> (<date>)" at the top of the destination
              mailbox, with the source folder tree recreated inside it.
              Root: merged into the destination's own folders - Inbox into Inbox, Calendar into
              Calendar, custom folders matched by name (created when missing).
          -Operation Copy (default) | Move   - Move soft-deletes each source item after it is imported.
          -IncludeDeletedItems / -IncludeJunk - both skipped by default.
          -IncludeArchive (default on)       - also copies the source's online archive, if it has one.
          -ArchiveDestination Archive (default) | Primary
              Archive: into the destination's online archive (same NewFolder/Root layout as above).
              Primary: into an "Online Archive" folder in the destination's main mailbox. Also the
              fallback when the destination has no archive.

        Archive mailboxes are only reachable through the beta admin mailbox API (v1.0 answers
        "Operation on Archive mailbox not allowed"), so every folder row carries its own mailbox ids
        and API version and the planner/copier use those rather than one pair per operation.

        Start creates the destination folders, records the operation, and hands the item work to an
        orchestrator: Push-MailboxCopyPlan lists the items into chunks, then three sequential lanes of
        Push-MailboxCopyChunk do the export/import. Progress: ListMailboxCopies.

        Needs MailboxFolder.ReadWrite.All, MailboxItem.ImportExport.All and MailboxItem.ReadWrite.All
        (application) - declared in AdditionalPermissions.json.
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
        [string]$FolderName,
        [bool]$IncludeDeletedItems = $false,
        [bool]$IncludeJunk = $false,
        [bool]$IncludeArchive = $true,
        [ValidateSet('Archive', 'Primary')][string]$ArchiveDestination = 'Archive',
        [string]$StartedBy = 'CIPP-API',
        $Headers,
        [string]$APIName = 'MailboxCopy'
    )

    $Graph = 'https://graph.microsoft.com/v1.0'
    if ($SourceUser.Trim().ToLower() -eq $DestinationUser.Trim().ToLower()) {
        throw 'Source and destination must be different mailboxes.'
    }

    $Resolve = {
        param($Upn)
        $U = try {
            New-GraphGetRequest -uri "$Graph/users/$([uri]::EscapeDataString($Upn))?`$select=id,displayName,userPrincipalName" -tenantid $TenantFilter -AsApp $true -noPagination $true -ErrorAction Stop
        } catch { throw "User '$Upn' was not found in $TenantFilter." }
        $Ex = try {
            New-GraphGetRequest -uri "$Graph/users/$($U.id)/settings/exchange" -tenantid $TenantFilter -AsApp $true -noPagination $true -ErrorAction Stop
        } catch { $null }
        if (-not $Ex.primaryMailboxId) { throw "$($U.userPrincipalName) has no Exchange Online mailbox." }
        [PSCustomObject]@{
            Id               = $U.id
            Upn              = $U.userPrincipalName
            Name             = $U.displayName
            MailboxId        = [string]$Ex.primaryMailboxId
            ArchiveMailboxId = [string]($Ex.inPlaceArchiveMailboxId ?? '')
        }
    }
    $Src = & $Resolve $SourceUser
    $Dst = & $Resolve $DestinationUser

    $Container = $null
    if ($Destination -eq 'NewFolder') {
        $Container = if ($FolderName) { $FolderName.Trim() } else { "From $($Src.Name) ($((Get-Date).ToString('yyyy-MM-dd')))" }
        $Container = ($Container -replace '[\\/]', '-').Trim()
        if (-not $Container) { throw 'Folder name is empty.' }
    }

    $Warnings = [System.Collections.Generic.List[string]]::new()

    # ── Sections: the primary mailbox, plus the archive when there is one and it is wanted ──
    $Sections = [System.Collections.Generic.List[object]]::new()
    $Sections.Add([PSCustomObject]@{
            Name = 'Mailbox'; SrcMailboxId = $Src.MailboxId; SrcArchive = $false
            DstMailboxId = $Dst.MailboxId; DstArchive = $false; Wrapper = $null
        })
    if ($IncludeArchive -and $Src.ArchiveMailboxId) {
        if ($ArchiveDestination -eq 'Archive' -and $Dst.ArchiveMailboxId) {
            $Sections.Add([PSCustomObject]@{
                    Name = 'Online archive'; SrcMailboxId = $Src.ArchiveMailboxId; SrcArchive = $true
                    DstMailboxId = $Dst.ArchiveMailboxId; DstArchive = $true; Wrapper = $null
                })
        } else {
            if ($ArchiveDestination -eq 'Archive') {
                $Warnings.Add("$($Dst.Upn) has no online archive, so $($Src.Upn)'s archive goes into an 'Online Archive' folder in their main mailbox. Enable their archive first if it should land there instead.")
            }
            $Sections.Add([PSCustomObject]@{
                    Name = 'Online archive'; SrcMailboxId = $Src.ArchiveMailboxId; SrcArchive = $true
                    DstMailboxId = $Dst.MailboxId; DstArchive = $false
                    Wrapper = $(if ($Container) { 'Online Archive' } else { "Online Archive - $($Src.Name)" })
                })
        }
    }

    foreach ($Section in $Sections) {
        $Folders = Get-CIPPMailboxCopyFolders -TenantFilter $TenantFilter -MailboxId $Section.SrcMailboxId -Archive:$Section.SrcArchive `
            -IncludeDeletedItems:$IncludeDeletedItems -IncludeJunk:$IncludeJunk
        $Section | Add-Member -NotePropertyName Folders -NotePropertyValue @($Folders | Where-Object { -not $_.Skip }) -Force
        $Section | Add-Member -NotePropertyName Skipped -NotePropertyValue @($Folders | Where-Object { $_.Skip -and $_.SkipReason -notlike 'inside skipped*' }) -Force
        $Section | Add-Member -NotePropertyName ItemCount -NotePropertyValue ([int](($Section.Folders | Measure-Object -Property ItemCount -Sum).Sum)) -Force
    }
    $Primary = $Sections[0]
    $ArchiveSection = $Sections | Where-Object SrcArchive | Select-Object -First 1
    $TotalItems = [int](($Sections | Measure-Object -Property ItemCount -Sum).Sum)
    $FolderTotal = [int](($Sections | ForEach-Object { $_.Folders.Count } | Measure-Object -Sum).Sum)

    $ArchiveWhere = if (-not $ArchiveSection) { $null }
    elseif ($ArchiveSection.DstArchive) { "$($Dst.Upn)'s online archive$(if ($Container) { " ('$Container')" })" }
    else { "'$(if ($Container) { "$Container/" })$($ArchiveSection.Wrapper)' in $($Dst.Upn)'s mailbox" }

    $Preflight = [ordered]@{
        SourceUser          = $Src.Upn
        DestinationUser     = $Dst.Upn
        Destination         = $(if ($Container) { "New folder '$Container'" } else { 'Merged into the mailbox''s own folders' })
        Operation           = $Operation
        FolderCount         = $FolderTotal
        ItemCount           = $TotalItems
        MailboxItems        = $Primary.ItemCount
        ArchiveItems        = $(if ($ArchiveSection) { $ArchiveSection.ItemCount } else { 0 })
        SourceHasArchive    = [bool]$Src.ArchiveMailboxId
        ArchiveDestination  = $(if ($ArchiveSection) { $ArchiveWhere } elseif ($Src.ArchiveMailboxId) { 'Not included' } else { 'Source has no online archive' })
        SkippedFolders      = @($Sections | ForEach-Object {
                $S = $_
                $S.Skipped | ForEach-Object { "$(if ($S.SrcArchive) { 'Archive: ' })$($_.Path) ($($_.ItemCount) items) - $($_.SkipReason)" }
            })
        Warnings            = $Warnings
    }
    if ($TotalItems -eq 0) { throw "$($Src.Upn)'s mailbox$(if ($ArchiveSection) { ' and archive have' } else { ' has' }) nothing to copy." }
    if ($Operation -eq 'Move') { $Warnings.Add("MOVE: each item is deleted from $($Src.Upn)'s mailbox$(if ($ArchiveSection) { ' and archive' }) after it is imported (soft delete - recoverable from Recoverable Items). Folders are left in place, empty.") }
    if ($Destination -eq 'Root') { $Warnings.Add("Root: items merge into $($Dst.Upn)'s existing folders. Nothing is de-duplicated; running twice copies twice.") }
    if ($TotalItems -gt 50000) { $Warnings.Add("$TotalItems items: expect this to take several hours.") }

    if ($Mode -eq 'Preflight') {
        $Verb = $Operation.ToLower()
        $Preflight.Message = "Ready to $Verb $TotalItems item(s) in $FolderTotal folder(s) from $($Src.Upn) into $(if ($Container) { "'$Container' in " })$($Dst.Upn)'s mailbox$(if ($ArchiveSection) { " ($($ArchiveSection.ItemCount) of them from the online archive, into $ArchiveWhere)" })."
        return [PSCustomObject]$Preflight
    }

    # ── Build the destination tree(s) ──
    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($Section in $Sections) {
        if ($Section.Folders.Count -eq 0) { continue }
        $DstApi = if ($Section.DstArchive) { 'beta' } else { 'v1.0' }
        $DstBase = "https://graph.microsoft.com/$DstApi/admin/exchange/mailboxes/$($Section.DstMailboxId)/folders"
        $NewFolder = {
            param($ParentId, $Name, $Type)
            $Body = @{ displayName = $Name; type = $Type } | ConvertTo-Json -Compress
            $Uri = if ($ParentId) { "$DstBase/$ParentId/childFolders" } else { $DstBase }
            $Created = New-GraphPOSTRequest -uri $Uri -tenantid $TenantFilter -body $Body -AsApp $true
            if (-not $Created.id) { throw "Could not create folder '$Name' in $($Dst.Upn)'s $(if ($Section.DstArchive) { 'archive' } else { 'mailbox' })." }
            [string]$Created.id
        }
        $DstFolders = @(Get-CIPPMailboxCopyFolders -TenantFilter $TenantFilter -MailboxId $Section.DstMailboxId -Archive:$Section.DstArchive -IncludeDeletedItems -IncludeJunk)
        $FindChild = {
            param($ParentId, $Name)
            $DstFolders | Where-Object { $_.ParentId -eq $ParentId -and $_.DisplayName -eq $Name } | Select-Object -First 1
        }

        # A fresh container per run; a same-day rerun gets a time suffix instead of merging into the first.
        $NewContainer = {
            $Name = $Container
            if (& $FindChild $null $Name) { $Name = "$Container $((Get-Date).ToString('HHmm'))" }
            & $NewFolder $null $Name 'IPF.Note'
        }
        # Top of this section's tree in the destination.
        $TopId = $null
        if ($Section.Wrapper) {
            # Archive going into the main mailbox: under the primary section's container (same mailbox),
            # inside an "Online Archive" folder.
            $Parent = $null
            if ($Container) {
                if (-not $Primary.PSObject.Properties['ContainerId']) {
                    $Primary | Add-Member -NotePropertyName ContainerId -NotePropertyValue (& $NewContainer) -Force
                }
                $Parent = $Primary.ContainerId
            }
            $TopId = (& $FindChild $Parent $Section.Wrapper).Id
            if (-not $TopId) { $TopId = & $NewFolder $Parent $Section.Wrapper 'IPF.Note' }
        } elseif ($Container) {
            $TopId = & $NewContainer
            if ($Section.Name -eq 'Mailbox') { $Section | Add-Member -NotePropertyName ContainerId -NotePropertyValue $TopId -Force }
        }
        $MergeIntoOwn = (-not $Container) -and (-not $Section.Wrapper)

        $Map = @{}
        foreach ($F in $Section.Folders) {
            $ParentDst = if ($F.ParentId) { $Map[$F.ParentId] } else { $TopId }
            if ($F.ParentId -and -not $ParentDst) { continue }   # parent was skipped
            $DstId = $null
            if ($MergeIntoOwn -and $F.WellKnownName) {
                $DstId = ($DstFolders | Where-Object { $_.WellKnownName -eq $F.WellKnownName } | Select-Object -First 1).Id
            }
            if (-not $DstId -and $MergeIntoOwn) { $DstId = (& $FindChild $ParentDst $F.DisplayName).Id }
            if (-not $DstId) { $DstId = & $NewFolder $ParentDst $F.DisplayName $F.Type }
            $Map[$F.Id] = $DstId
            $Rows.Add([PSCustomObject]@{
                    SrcFolderId  = $F.Id
                    DstFolderId  = $DstId
                    Path         = $(if ($Section.SrcArchive) { "Archive/$($F.Path)" } else { $F.Path })
                    ItemCount    = $F.ItemCount
                    SrcMailboxId = $Section.SrcMailboxId
                    DstMailboxId = $Section.DstMailboxId
                    SrcApi       = $(if ($Section.SrcArchive) { 'beta' } else { 'v1.0' })
                    DstApi       = $DstApi
                })
        }
    }

    # ── Record the operation and hand off ──
    $OperationId = (New-Guid).Guid
    $Table = Get-CippTable -tablename 'MailboxCopy'
    $i = 0
    foreach ($R in $Rows) {
        $i++
        Add-CIPPAzDataTableEntity @Table -Entity @{
            PartitionKey = $OperationId
            RowKey       = 'f{0:D5}' -f $i
            SrcFolderId  = $R.SrcFolderId
            DstFolderId  = $R.DstFolderId
            Path         = $R.Path
            ItemCount    = [int]$R.ItemCount
            SrcMailboxId = $R.SrcMailboxId
            DstMailboxId = $R.DstMailboxId
            SrcApi       = $R.SrcApi
            DstApi       = $R.DstApi
        } -Force
    }
    Add-CIPPAzDataTableEntity @Table -Entity @{
        PartitionKey       = 'Operation'
        RowKey             = $OperationId
        TenantFilter       = $TenantFilter
        SourceUser         = $Src.Upn
        DestinationUser    = $Dst.Upn
        SrcMailboxId       = $Src.MailboxId
        DstMailboxId       = $Dst.MailboxId
        Operation          = $Operation
        Destination        = $Destination
        DestinationFolder  = [string]($Container ?? '')
        IncludesArchive    = [bool]$ArchiveSection
        ArchiveDestination = [string]($ArchiveWhere ?? '')
        ArchiveItems       = $(if ($ArchiveSection) { $ArchiveSection.ItemCount } else { 0 })
        FolderCount        = $Rows.Count
        PlannedItems       = $TotalItems
        Status             = 'Planning'
        StartedBy          = $StartedBy
        Started            = [DateTime]::UtcNow.ToString('o')
    } -Force

    $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
            OrchestratorName = "MailboxCopyPlan_$($OperationId.Substring(0, 8))"
            Batch            = @([PSCustomObject]@{ FunctionName = 'MailboxCopyPlan'; OperationId = $OperationId; TenantFilter = $TenantFilter })
            SkipLog          = $true
        })

    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -sev Info `
        -message "Started mailbox $($Operation.ToLower()) ${OperationId}: $($Src.Upn) -> $($Dst.Upn) $(if ($Container) { "'$Container'" } else { '(root)' }) ($TotalItems items, $($Rows.Count) folders$(if ($ArchiveSection) { ", archive -> $ArchiveWhere" }))"

    [PSCustomObject]@{
        OperationId        = $OperationId
        SourceUser         = $Src.Upn
        DestinationUser    = $Dst.Upn
        DestinationFolder  = $Container
        Operation          = $Operation
        FolderCount        = $Rows.Count
        ItemCount          = $TotalItems
        ArchiveItems       = $(if ($ArchiveSection) { $ArchiveSection.ItemCount } else { 0 })
        ArchiveDestination = $ArchiveWhere
        Message            = "$(if ($Operation -eq 'Move') { 'Moving' } else { 'Copying' }) $TotalItems item(s) in $($Rows.Count) folder(s) into $(if ($Container) { "'$Container' in " })$($Dst.Upn)'s mailbox$(if ($ArchiveSection) { " (archive: $ArchiveWhere)" }). Progress: Email & Exchange > Mailbox Copies."
    }
}
