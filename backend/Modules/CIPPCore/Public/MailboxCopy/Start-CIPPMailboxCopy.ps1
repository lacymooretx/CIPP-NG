function Start-CIPPMailboxCopy {
    <#
    .SYNOPSIS
        Copies or moves one mailbox's content into another mailbox (preflight or start)
    .DESCRIPTION
        Full-fidelity copy through the Graph mailbox import/export API (exportItems -> import session):
        mail, calendar, contacts and tasks keep their dates, senders, read state and attachments.

          -Destination NewFolder (default) | Root
              NewFolder: everything lands under "From <name> (<date>)" at the top of the destination
              mailbox, with the source folder tree recreated inside it.
              Root: merged into the destination's own folders - Inbox into Inbox, Calendar into
              Calendar, custom folders matched by name (created when missing).
          -Operation Copy (default) | Move   - Move deletes each source item after it is imported.
          -IncludeDeletedItems / -IncludeJunk - both skipped by default.

        Start creates the destination folders, records the operation, and hands the item work to an
        orchestrator: Push-MailboxCopyPlan lists the items into chunks, then three sequential lanes of
        Push-MailboxCopyChunk do the export/import (three keeps under Exchange's per-mailbox
        concurrency limit). Progress: ListMailboxCopies.

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
        [PSCustomObject]@{ Id = $U.id; Upn = $U.userPrincipalName; Name = $U.displayName; MailboxId = [string]$Ex.primaryMailboxId }
    }
    $Src = & $Resolve $SourceUser
    $Dst = & $Resolve $DestinationUser

    $SrcFolders = Get-CIPPMailboxCopyFolders -TenantFilter $TenantFilter -MailboxId $Src.MailboxId -IncludeDeletedItems:$IncludeDeletedItems -IncludeJunk:$IncludeJunk
    $Copy = @($SrcFolders | Where-Object { -not $_.Skip })
    $Skipped = @($SrcFolders | Where-Object { $_.Skip -and $_.SkipReason -notlike 'inside skipped*' })
    $TotalItems = [int](($Copy | Measure-Object -Property ItemCount -Sum).Sum)

    $Container = $null
    if ($Destination -eq 'NewFolder') {
        $Container = if ($FolderName) { $FolderName.Trim() } else { "From $($Src.Name) ($((Get-Date).ToString('yyyy-MM-dd')))" }
        $Container = ($Container -replace '[\\/]', '-').Trim()
        if (-not $Container) { throw 'Folder name is empty.' }
    }

    $Preflight = [ordered]@{
        SourceUser      = $Src.Upn
        DestinationUser = $Dst.Upn
        Destination     = $(if ($Container) { "New folder '$Container'" } else { 'Merged into the mailbox''s own folders' })
        Operation       = $Operation
        FolderCount     = $Copy.Count
        ItemCount       = $TotalItems
        SkippedFolders  = @($Skipped | ForEach-Object { "$($_.Path) ($($_.ItemCount) items) - $($_.SkipReason)" })
        Warnings        = [System.Collections.Generic.List[string]]::new()
    }
    if ($TotalItems -eq 0) { throw "$($Src.Upn)'s mailbox has nothing to copy." }
    if ($Operation -eq 'Move') { $Preflight.Warnings.Add("MOVE: each item is deleted from $($Src.Upn)'s mailbox after it is imported. Folders are left in place (empty).") }
    if ($Destination -eq 'Root') { $Preflight.Warnings.Add("Root: items merge into $($Dst.Upn)'s existing Inbox, Sent Items, Calendar and other folders. Nothing is de-duplicated; running twice copies twice.") }
    if ($TotalItems -gt 50000) { $Preflight.Warnings.Add("$TotalItems items: expect this to take several hours.") }

    if ($Mode -eq 'Preflight') {
        $Verb = $Operation.ToLower()
        $Preflight.Message = "Ready to $Verb $TotalItems item(s) in $($Copy.Count) folder(s) from $($Src.Upn) into $(if ($Container) { "'$Container' in " })$($Dst.Upn)'s mailbox."
        return [PSCustomObject]$Preflight
    }

    # ── Build the destination tree ──
    $DstBase = "$Graph/admin/exchange/mailboxes/$($Dst.MailboxId)/folders"
    $NewFolder = {
        param($ParentId, $Name, $Type)
        $Body = @{ displayName = $Name; type = $Type } | ConvertTo-Json -Compress
        $Uri = if ($ParentId) { "$DstBase/$ParentId/childFolders" } else { $DstBase }
        New-GraphPOSTRequest -uri $Uri -tenantid $TenantFilter -body $Body -AsApp $true
    }
    $DstFolders = @(Get-CIPPMailboxCopyFolders -TenantFilter $TenantFilter -MailboxId $Dst.MailboxId -IncludeDeletedItems -IncludeJunk)
    $FindChild = {
        param($ParentId, $Name)
        $DstFolders | Where-Object { $_.ParentId -eq $ParentId -and $_.DisplayName -eq $Name } | Select-Object -First 1
    }

    $ContainerId = $null
    if ($Container) {
        $Name = $Container
        if (& $FindChild $null $Name) { $Name = "$Container $((Get-Date).ToString('HHmm'))" }
        $Created = & $NewFolder $null $Name 'IPF.Note'
        if (-not $Created.id) { throw "Could not create '$Name' in $($Dst.Upn)'s mailbox." }
        $Container = $Name
        $ContainerId = [string]$Created.id
    }

    $Map = @{}
    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($F in $Copy) {
        $ParentDst = if ($F.ParentId) { $Map[$F.ParentId] } else { $ContainerId }
        if ($F.ParentId -and -not $ParentDst) { continue }   # parent was skipped
        $DstId = $null
        if (-not $Container -and $F.WellKnownName) {
            $DstId = ($DstFolders | Where-Object { $_.WellKnownName -eq $F.WellKnownName } | Select-Object -First 1).Id
        }
        if (-not $DstId -and -not $Container) {
            $DstId = (& $FindChild $ParentDst $F.DisplayName).Id
        }
        if (-not $DstId) {
            $DstId = [string](& $NewFolder $ParentDst $F.DisplayName $F.Type).id
            if (-not $DstId) { throw "Could not create folder '$($F.Path)' in $($Dst.Upn)'s mailbox." }
        }
        $Map[$F.Id] = $DstId
        $Rows.Add([PSCustomObject]@{ SrcFolderId = $F.Id; DstFolderId = $DstId; Path = $F.Path; ItemCount = $F.ItemCount })
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
        } -Force
    }
    Add-CIPPAzDataTableEntity @Table -Entity @{
        PartitionKey      = 'Operation'
        RowKey            = $OperationId
        TenantFilter      = $TenantFilter
        SourceUser        = $Src.Upn
        DestinationUser   = $Dst.Upn
        SrcMailboxId      = $Src.MailboxId
        DstMailboxId      = $Dst.MailboxId
        Operation         = $Operation
        Destination       = $Destination
        DestinationFolder = [string]($Container ?? '')
        FolderCount       = $Rows.Count
        PlannedItems      = $TotalItems
        Status            = 'Planning'
        StartedBy         = $StartedBy
        Started           = [DateTime]::UtcNow.ToString('o')
    } -Force

    $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
            OrchestratorName = "MailboxCopyPlan_$($OperationId.Substring(0, 8))"
            Batch            = @([PSCustomObject]@{ FunctionName = 'MailboxCopyPlan'; OperationId = $OperationId; TenantFilter = $TenantFilter })
            SkipLog          = $true
        })

    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -sev Info `
        -message "Started mailbox $($Operation.ToLower()) ${OperationId}: $($Src.Upn) -> $($Dst.Upn) $(if ($Container) { "'$Container'" } else { '(root)' }) ($TotalItems items, $($Rows.Count) folders)"

    [PSCustomObject]@{
        OperationId       = $OperationId
        SourceUser        = $Src.Upn
        DestinationUser   = $Dst.Upn
        DestinationFolder = $Container
        Operation         = $Operation
        FolderCount       = $Rows.Count
        ItemCount         = $TotalItems
        Message           = "$(if ($Operation -eq 'Move') { 'Moving' } else { 'Copying' }) $TotalItems item(s) in $($Rows.Count) folder(s) into $(if ($Container) { "'$Container' in " })$($Dst.Upn)'s mailbox. Progress: Email & Exchange > Mailbox Copies."
    }
}
