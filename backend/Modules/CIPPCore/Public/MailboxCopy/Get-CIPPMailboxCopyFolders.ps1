function Get-CIPPMailboxCopyFolders {
    <#
    .SYNOPSIS
        Lists a mailbox's folders (admin mailbox API) as a flat tree with paths, minus folders a copy must skip
    .DESCRIPTION
        Walks /admin/exchange/mailboxes/{id}/folders and each folder's childFolders, de-duplicating by id
        (the top-level list can already include descendants). Returns one object per folder:
        Id, ParentId, DisplayName, Path, Depth, Type, WellKnownName, ItemCount, Skip, SkipReason.

        Skipped (the folder and everything under it): search folders, sync-issue folders, Recoverable
        Items, Outbox, hidden system folders (PR_ATTR_HIDDEN), and Deleted Items / Junk Email unless
        asked for. Skipped folders are still returned so preflight can show what was left out.

        -Archive: an online archive (inPlaceArchiveMailboxId). v1.0 refuses archive mailboxes with
        "Operation on Archive mailbox not allowed", so archives are read through beta. Archive folders
        have no well-known names except archivedeleteditems, so system folders there (Outbox, Sync
        Issues, PersonMetadata) are recognised by name.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$MailboxId,
        [switch]$IncludeDeletedItems,
        [switch]$IncludeJunk,
        [switch]$Archive
    )

    $Api = if ($Archive) { 'beta' } else { 'v1.0' }
    $Base = "https://graph.microsoft.com/$Api/admin/exchange/mailboxes/$MailboxId/folders"
    # PR_ATTR_HIDDEN marks the system folders Outlook never shows (PersonMetadata, Yammer Root, ...).
    $Query = "`$top=250&`$expand=singleValueExtendedProperties(`$filter=id eq 'Boolean 0x10F4')"

    $AlwaysSkip = @('searchfolders', 'syncissues', 'conflicts', 'localfailures', 'serverfailures', 'outbox',
        'recoverableitemsroot', 'recoverableitemsdeletions', 'recoverableitemspurges', 'recoverableitemsversions',
        'recoverableitemsdiscoveryholds', 'recoverableitemssubstrateholds', 'conversationhistory_system')
    # Hidden folders that some tenants return without PR_ATTR_HIDDEN set.
    $SkipNames = @('PersonMetadata', 'ExternalContacts', 'Yammer Root', 'Files', 'Conversation Action Settings',
        'Quick Step Settings', 'Social Activity Notifications', 'Recipient Cache', 'Organizational Contacts',
        'GAL Contacts', 'Companies', 'Sync Issues', 'Recoverable Items', 'Search Folders', 'Outbox')

    $ById = [ordered]@{}
    $Pending = [System.Collections.Generic.Queue[object]]::new()
    foreach ($F in @(New-GraphGetRequest -uri "$Base`?$Query" -tenantid $TenantFilter -AsApp $true)) {
        if ($F.id -and -not $ById.Contains($F.id)) { $ById[$F.id] = $F; $Pending.Enqueue($F) }
    }
    while ($Pending.Count -gt 0) {
        $F = $Pending.Dequeue()
        if ([int]($F.childFolderCount ?? 0) -le 0) { continue }
        foreach ($C in @(New-GraphGetRequest -uri "$Base/$($F.id)/childFolders?$Query" -tenantid $TenantFilter -AsApp $true)) {
            if ($C.id -and -not $ById.Contains($C.id)) { $ById[$C.id] = $C; $Pending.Enqueue($C) }
        }
    }

    # Top-level folders are the ones whose parent is not in the set (the IPM subtree root).
    $Result = [System.Collections.Generic.List[object]]::new()
    $Memo = @{}
    $Resolve = $null
    $Resolve = {
        param($Id)
        if ($Memo.ContainsKey($Id)) { return $Memo[$Id] }
        $F = $ById[$Id]
        $Wkn = [string]($F.wellKnownName ?? '')
        $Hidden = [bool](@($F.singleValueExtendedProperties | Where-Object { $_.id -match '0x10F4' -and [string]$_.value -eq 'true' }).Count)
        $Reason = $null
        if ($Wkn.ToLower() -in $AlwaysSkip -or $Wkn -match 'recoverableitems') { $Reason = 'system folder' }
        elseif ($Hidden) { $Reason = 'hidden system folder' }
        elseif ([string]$F.displayName -in $SkipNames -and -not $Wkn) { $Reason = 'hidden system folder' }
        elseif ($Wkn -in @('deleteditems', 'archivedeleteditems') -and -not $IncludeDeletedItems) { $Reason = 'Deleted Items not included' }
        elseif ($Wkn -eq 'junkemail' -and -not $IncludeJunk) { $Reason = 'Junk Email not included' }

        $Parent = if ($F.parentFolderId -and $ById.Contains($F.parentFolderId)) { & $Resolve $F.parentFolderId } else { $null }
        if ($Parent -and $Parent.Skip -and -not $Reason) { $Reason = "inside skipped folder '$($Parent.Path)'" }
        $Node = [PSCustomObject]@{
            Id            = [string]$F.id
            ParentId      = if ($Parent) { $Parent.Id } else { $null }
            DisplayName   = [string]$F.displayName
            Path          = if ($Parent) { "$($Parent.Path)/$($F.displayName)" } else { [string]$F.displayName }
            Depth         = if ($Parent) { $Parent.Depth + 1 } else { 0 }
            Type          = [string]($F.type ?? 'IPF.Note')
            WellKnownName = $Wkn
            ItemCount     = [int]($F.totalItemCount ?? 0)
            Skip          = [bool]$Reason
            SkipReason    = $Reason
        }
        $Memo[$Id] = $Node
        $Node
    }
    foreach ($Id in $ById.Keys) { $Result.Add((& $Resolve $Id)) }
    # Parents before children, so a destination tree can be created in one pass.
    @($Result | Sort-Object Depth, Path)
}
