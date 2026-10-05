BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/MailboxCopy/Get-CIPPMailboxCopyFolders.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/MailboxCopy/Start-CIPPMailboxCopy.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPActivityTriggers/Public/Entrypoints/Activity Triggers/Mailbox Copy/Push-MailboxCopyChunk.ps1')

    function Write-LogMessage { param($headers, $API, $tenant, $message, $sev, $LogData) }
    function Get-NormalizedError { param($message) $message }
    function Get-CippTable { param($tablename) @{ Name = $tablename } }
    function Start-CIPPOrchestrator { param($InputObject) }
    function Add-CIPPAzDataTableEntity { param($Name, $Entity, [switch]$Force) }
    function Get-CIPPAzDataTableEntity { param($Name, $Filter, $Property) }
    function New-GraphPOSTRequest { param($uri, $tenantid, $body, $AsApp, $type) }
    function New-GraphGetRequest { param($uri, $tenantid, $AsApp, $noPagination, $ErrorAction) }

    function New-Folder($id, $name, $parent, $wkn = $null, $count = 5, $children = 0, $hidden = $false) {
        [pscustomobject]@{ id = $id; displayName = $name; parentFolderId = $parent; wellKnownName = $wkn; totalItemCount = $count
            childFolderCount = $children; type = 'IPF.Note'
            singleValueExtendedProperties = @(if ($hidden) { [pscustomobject]@{ id = 'Boolean 0x10F4'; value = 'true' } }) }
    }
}

Describe 'Get-CIPPMailboxCopyFolders' {
    BeforeEach {
        Mock New-GraphGetRequest {
            if ($uri -match '/folders/inbox-id/childFolders') { return @(New-Folder 'sub-id' 'Clients' 'inbox-id') }
            if ($uri -match '/folders/deleted-id/childFolders') { return @(New-Folder 'delsub' 'Old' 'deleted-id') }
            @(
                (New-Folder 'inbox-id' 'Inbox' 'root' 'inbox' 10 1)
                (New-Folder 'deleted-id' 'Deleted Items' 'root' 'deleteditems' 3 1)
                (New-Folder 'junk-id' 'Junk Email' 'root' 'junkemail' 2)
                (New-Folder 'search-id' 'Search Folders' 'root' 'searchfolders' 0)
                (New-Folder 'pm-id' 'PersonMetadata' 'root' $null 40 0 $true)
            )
        }
    }

    It 'builds paths, recurses into child folders and orders parents first' {
        $F = Get-CIPPMailboxCopyFolders -TenantFilter 't' -MailboxId 'MBX:1'
        ($F | Where-Object Id -eq 'sub-id').Path | Should -Be 'Inbox/Clients'
        [array]::IndexOf(@($F.Id), 'inbox-id') | Should -BeLessThan ([array]::IndexOf(@($F.Id), 'sub-id'))
    }

    It 'skips system, hidden, deleted and junk folders (and their children) by default' {
        $F = Get-CIPPMailboxCopyFolders -TenantFilter 't' -MailboxId 'MBX:1'
        @($F | Where-Object { -not $_.Skip }).Id | Should -Be @('inbox-id', 'sub-id')
        ($F | Where-Object Id -eq 'delsub').SkipReason | Should -Match 'inside skipped'
        ($F | Where-Object Id -eq 'pm-id').SkipReason | Should -Be 'hidden system folder'
    }

    It 'includes Deleted Items and Junk when asked' {
        $F = Get-CIPPMailboxCopyFolders -TenantFilter 't' -MailboxId 'MBX:1' -IncludeDeletedItems -IncludeJunk
        @($F | Where-Object { -not $_.Skip }).Id | Should -Contain 'delsub'
        @($F | Where-Object { -not $_.Skip }).Id | Should -Contain 'junk-id'
    }
}

Describe 'Start-CIPPMailboxCopy' {
    BeforeEach {
        Mock New-GraphGetRequest {
            if ($uri -match '/settings/exchange') {
                $uid = $uri -replace '.*/users/([^/]+)/.*', '$1'
                $R = [pscustomobject]@{ primaryMailboxId = "MBX:$uid" }
                if ($script:Archives -contains $uid) { $R | Add-Member -NotePropertyName inPlaceArchiveMailboxId -NotePropertyValue "MBX:arch-$uid" }
                return $R
            }
            if ($uri -match 'MBX:arch-id-src/folders') {
                if ($uri -notmatch '/beta/') { throw 'Operation on Archive mailbox not allowed' }
                return @((New-Folder 'a-old' 'Old Mail' 'aroot' $null 30), (New-Folder 'a-del' 'Deleted Items' 'aroot' 'archivedeleteditems' 9), (New-Folder 'a-out' 'Outbox' 'aroot' $null 0))
            }
            if ($uri -match 'MBX:arch-id-dst/folders') {
                if ($uri -notmatch '/beta/') { throw 'Operation on Archive mailbox not allowed' }
                return @(New-Folder 'da-old' 'Old Mail' 'daroot' $null 1)
            }
            if ($uri -match '/users/([^/?]+)\?') {
                $upn = [uri]::UnescapeDataString($Matches[1])
                if ($upn -eq 'ghost@t.com') { throw 'Request_ResourceNotFound' }
                return [pscustomobject]@{ id = "id-$($upn.Split('@')[0])"; displayName = "Name $($upn.Split('@')[0])"; userPrincipalName = $upn }
            }
            if ($uri -match 'MBX:id-dst/folders') {
                return @((New-Folder 'd-inbox' 'Inbox' 'droot' 'inbox' 1), (New-Folder 'd-clients' 'Clients' 'droot' $null 0))
            }
            if ($uri -match '/folders/s-inbox/childFolders') { return @(New-Folder 's-sub' 'Projects' 's-inbox' $null 4) }
            @((New-Folder 's-inbox' 'Inbox' 'sroot' 'inbox' 10 1), (New-Folder 's-clients' 'Clients' 'sroot' $null 6))
        }
        Mock New-GraphPOSTRequest { [pscustomobject]@{ id = "new-$([guid]::NewGuid().ToString('N').Substring(0,6))" } }
        Mock Add-CIPPAzDataTableEntity { }
        Mock Start-CIPPOrchestrator { }
        $script:Archives = @()
    }

    It 'includes the source archive (via beta) in preflight, skipping archive system and deleted folders' {
        $script:Archives = @('id-src', 'id-dst')
        $R = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com'
        $R.ArchiveItems | Should -Be 30
        $R.ItemCount | Should -Be 50
        $R.ArchiveDestination | Should -Match 'online archive'
        ($R.SkippedFolders -join ' ') | Should -Match 'Archive: Deleted Items'
        ($R.SkippedFolders -join ' ') | Should -Match 'Archive: Outbox'
    }

    It 'leaves the archive out when asked, and says so' {
        $script:Archives = @('id-src')
        $R = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -IncludeArchive $false
        $R.ArchiveItems | Should -Be 0
        $R.ArchiveDestination | Should -Be 'Not included'
    }

    It 'copies archive into the destination archive with beta rows and a container there' {
        $script:Archives = @('id-src', 'id-dst')
        $null = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -Mode Start
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -match '/beta/admin/exchange/mailboxes/MBX:arch-id-dst/folders$' -and $body -match 'From Name src' }
        Should -Invoke Add-CIPPAzDataTableEntity -Times 1 -Exactly -ParameterFilter {
            $Entity.SrcFolderId -eq 'a-old' -and $Entity.SrcMailboxId -eq 'MBX:arch-id-src' -and $Entity.DstMailboxId -eq 'MBX:arch-id-dst' -and $Entity.SrcApi -eq 'beta' -and $Entity.DstApi -eq 'beta' -and $Entity.Path -eq 'Archive/Old Mail'
        }
        Should -Invoke Add-CIPPAzDataTableEntity -ParameterFilter { $Entity.SrcFolderId -eq 's-inbox' -and $Entity.SrcApi -eq 'v1.0' -and $Entity.DstMailboxId -eq 'MBX:id-dst' }
    }

    It 'falls back to an Online Archive folder in the main mailbox when the destination has no archive' {
        $script:Archives = @('id-src')
        $P = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com'
        ($P.Warnings -join ' ') | Should -Match 'has no online archive'
        $null = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -Mode Start
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -match '/v1.0/admin/exchange/mailboxes/MBX:id-dst/folders/new-\w+/childFolders$' -and $body -match '"Online Archive"' }
        Should -Invoke Add-CIPPAzDataTableEntity -ParameterFilter { $Entity.SrcFolderId -eq 'a-old' -and $Entity.SrcApi -eq 'beta' -and $Entity.DstApi -eq 'v1.0' -and $Entity.DstMailboxId -eq 'MBX:id-dst' }
    }

    It 'root mode merges the archive into same-name folders of the destination archive' {
        $script:Archives = @('id-src', 'id-dst')
        $null = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -Mode Start -Destination Root
        Should -Invoke Add-CIPPAzDataTableEntity -ParameterFilter { $Entity.SrcFolderId -eq 'a-old' -and $Entity.DstFolderId -eq 'da-old' }
        Should -Invoke New-GraphPOSTRequest -Times 0 -ParameterFilter { $uri -match 'arch-id-dst' }
    }

    It 'preflight counts items and folders without creating anything' {
        $R = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com'
        $R.ItemCount | Should -Be 20
        $R.FolderCount | Should -Be 3
        $R.Destination | Should -Match "From Name src"
        Should -Invoke New-GraphPOSTRequest -Times 0 -Exactly
        Should -Invoke Start-CIPPOrchestrator -Times 0 -Exactly
    }

    It 'new-folder start creates the container plus the full tree and queues the planner' {
        $R = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -Mode Start
        Should -Invoke New-GraphPOSTRequest -Times 4 -Exactly   # container + Inbox + Clients + Inbox/Projects
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -match '/childFolders$' -and $body -match 'Projects' }
        Should -Invoke Start-CIPPOrchestrator -Times 1 -Exactly -ParameterFilter { $InputObject.Batch[0].FunctionName -eq 'MailboxCopyPlan' }
        Should -Invoke Add-CIPPAzDataTableEntity -Times 1 -Exactly -ParameterFilter { $Entity.PartitionKey -eq 'Operation' -and $Entity.PlannedItems -eq 20 -and $Entity.SrcMailboxId -eq 'MBX:id-src' }
        $R.OperationId | Should -Not -BeNullOrEmpty
    }

    It 'root start maps well-known and same-name folders onto the destination and only creates what is missing' {
        $null = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -Mode Start -Destination Root
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly   # only Inbox/Projects is new
        Should -Invoke Add-CIPPAzDataTableEntity -ParameterFilter { $Entity.SrcFolderId -eq 's-inbox' -and $Entity.DstFolderId -eq 'd-inbox' }
        Should -Invoke Add-CIPPAzDataTableEntity -ParameterFilter { $Entity.SrcFolderId -eq 's-clients' -and $Entity.DstFolderId -eq 'd-clients' }
    }

    It 'warns about Move and refuses self-copy and unknown users' {
        $P = Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -Operation Move
        ($P.Warnings -join ' ') | Should -Match 'MOVE'
        { Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'Src@t.com' -DestinationUser 'src@t.com' } | Should -Throw '*different mailboxes*'
        { Start-CIPPMailboxCopy -TenantFilter 't' -SourceUser 'ghost@t.com' -DestinationUser 'dst@t.com' } | Should -Throw '*was not found*'
    }
}

Describe 'Push-MailboxCopyChunk' {
    BeforeAll {
        function Get-GraphToken { param($tenantid, $AsApp, $SkipCache) @{ Authorization = 'Bearer t' } }
        function Invoke-CIPPMailboxItemExport { param($ExportUri, $Authorization, $ItemId, $FolderId) }
        function Invoke-CIPPMailboxItemImport { param($Export, $ImportUrl) }
        function New-FakeExport([string]$Id, [bool]$HasData = $true, [int]$Status = 200, [string]$Body = '', [double]$RetryAfter = 0, [long]$Length = 100) {
            $X = [pscustomobject]@{ ItemId = $Id; HasData = $HasData; StatusCode = $Status; Body = $Body; RetryAfterSeconds = $RetryAfter; DataLength = $Length; Released = $false }
            $X | Add-Member -MemberType ScriptMethod -Name Release -Value { $this.Released = $true }
            $X
        }
        function Ok { [pscustomobject]@{ Success = $true; StatusCode = 200; Body = ''; RetryAfterSeconds = 0 } }
        $script:Run = { Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' }) }
        $script:Final = { $script:Saved | Where-Object { $_.RowKey -eq 'c00001' } | Select-Object -Last 1 }
    }
    BeforeEach {
        $script:Saved = [System.Collections.Generic.List[object]]::new()
        $script:Op = [pscustomobject]@{ PartitionKey = 'Operation'; RowKey = 'op1'; Operation = 'Copy'; Status = 'Copying'; SrcMailboxId = 'MBX:s'; DstMailboxId = 'MBX:d'; SourceUser = 's'; DestinationUser = 'd' }
        $Ids = 1..12 | ForEach-Object { "item$_|1000" }
        $script:Chunk = [pscustomobject]@{ PartitionKey = 'op1'; RowKey = 'c00001'; SrcFolderId = 'sf'; DstFolderId = 'df'; Ids = (ConvertTo-Json -InputObject @($Ids) -Compress); Done = 0; Copied = 0; Failed = 0; State = 'Pending'; Errors = '[]' }
        Mock Get-CIPPAzDataTableEntity {
            if ($Filter -match "PartitionKey eq 'Operation'") { return $script:Op }
            if ($Filter -match "State ne 'Done'") { return @() }
            if ($Filter -match "RowKey eq 'c00001'") { return $script:Chunk }
            return @($script:Chunk)
        }
        Mock Add-CIPPAzDataTableEntity { $script:Saved.Add(($Entity | Select-Object *)) }
        Mock Start-Sleep { }
        Mock New-GraphPOSTRequest {
            if ($uri -match 'createImportSession') { return [pscustomobject]@{ importUrl = "https://outlook/import/$($uri -replace '.*mailboxes/([^/]+)/.*','$1')"; expirationDateTime = [DateTime]::UtcNow.AddHours(1).ToString('o') } }
        }
        Mock Invoke-CIPPMailboxItemExport {
            if ($ItemId -eq 'item3') { return New-FakeExport $ItemId $false 200 '{"value":[{"itemId":"item3","error":{"code":"ErrorCorruptData","message":"bad item"}}]}' }
            New-FakeExport $ItemId
        }
        Mock Invoke-CIPPMailboxItemImport { Ok }
    }

    It 'copies one item per export, counts a bad item as failed and closes the operation' {
        & $script:Run
        Should -Invoke Invoke-CIPPMailboxItemExport -Times 12 -Exactly -ParameterFilter { $ExportUri -eq 'https://graph.microsoft.com/v1.0/admin/exchange/mailboxes/MBX:s/exportItems' -and $FolderId -eq 'df' -and $Authorization -eq 'Bearer t' }
        Should -Invoke Invoke-CIPPMailboxItemImport -Times 11 -Exactly -ParameterFilter { $ImportUrl -eq 'https://outlook/import/MBX:d' -and $Export.Released }   # released after import
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -match 'createImportSession' }
        $F = & $script:Final
        $F.State | Should -Be 'Done'; $F.Copied | Should -Be 11; $F.Failed | Should -Be 1
        $F.Errors | Should -Match 'ErrorCorruptData'
        ($script:Saved | Where-Object { $_.RowKey -eq 'op1' } | Select-Object -Last 1).Status | Should -Be 'CompletedWithErrors'
    }

    It 'backs off on 429 IncomingBytes (honouring Retry-After) instead of failing the item' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10') -Compress)
        $script:Tries = 0
        Mock Invoke-CIPPMailboxItemImport {
            $script:Tries++
            if ($script:Tries -le 2) { return [pscustomobject]@{ Success = $false; StatusCode = 429; Body = '{"error":{"code":"ApplicationThrottled","message":"Application is over its IncomingBytes limit."}}'; RetryAfterSeconds = 42 } }
            Ok
        }
        & $script:Run
        Should -Invoke Start-Sleep -Times 2 -Exactly -ParameterFilter { $Seconds -eq 42 }
        (& $script:Final).Copied | Should -Be 1
        (& $script:Final).Failed | Should -Be 0
    }

    It 'gives up on an item only after 12 throttled attempts (short waits, no Retry-After), and carries on with the next' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10', 'item2|10') -Compress)
        Mock Invoke-CIPPMailboxItemImport {
            if ($Export.ItemId -eq 'item1') { return [pscustomobject]@{ Success = $false; StatusCode = 429; Body = 'throttled'; RetryAfterSeconds = 0 } }
            Ok
        }
        & $script:Run
        Should -Invoke Invoke-CIPPMailboxItemImport -Times 12 -Exactly -ParameterFilter { $Export.ItemId -eq 'item1' }
        Should -Invoke Start-Sleep -Times 11 -Exactly
        Should -Invoke Start-Sleep -Times 0 -Exactly -ParameterFilter { $Seconds -gt 60 }
        (& $script:Final).Copied | Should -Be 1
        (& $script:Final).Failed | Should -Be 1
    }

    It 'fails only the item that runs out of memory, not the rest of the chunk (3E failure)' {
        Mock Invoke-CIPPMailboxItemExport {
            if ($ItemId -eq 'item5') { throw [System.OutOfMemoryException]::new() }
            New-FakeExport $ItemId
        }
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @(1..8 | ForEach-Object { "item$_|1000" }) -Compress)
        & $script:Run
        $F = & $script:Final
        $F.Copied | Should -Be 7; $F.Failed | Should -Be 1; $F.State | Should -Be 'Done'
        $F.Errors | Should -Match 'ran out of memory'
    }

    It 'reports an empty export (NotReturned) with the reported size, and retries server errors' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|5242880', 'item2|10') -Compress)
        $script:Calls = @{}
        Mock Invoke-CIPPMailboxItemExport {
            $script:Calls[$ItemId] = 1 + ($script:Calls[$ItemId] ?? 0)
            if ($ItemId -eq 'item1') { return New-FakeExport $ItemId $false 200 '{"value":[]}' }
            if ($script:Calls[$ItemId] -eq 1) { return New-FakeExport $ItemId $false 503 'busy' }
            New-FakeExport $ItemId
        }
        & $script:Run
        $F = & $script:Final
        $F.Copied | Should -Be 1; $F.Failed | Should -Be 1
        $F.Errors | Should -Match 'NotReturned.*5 MB'
        $script:Calls['item2'] | Should -Be 2
    }

    It 'treats an item deleted since planning as done, not failed' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10') -Compress)
        Mock Invoke-CIPPMailboxItemExport { New-FakeExport $ItemId $false 200 '{"value":[{"itemId":"item1","error":{"code":"ErrorItemNotFound","message":"gone"}}]}' }
        & $script:Run
        (& $script:Final).Failed | Should -Be 0
        (& $script:Final).Done | Should -Be 1
    }

    It 'follows the archive redirect and deletes moved items from the auxiliary mailbox' {
        $script:Op.Operation = 'Move'
        $script:Chunk | Add-Member -NotePropertyName SrcMailboxId -NotePropertyValue 'MBX:arch' -Force
        $script:Chunk | Add-Member -NotePropertyName SrcApi -NotePropertyValue 'beta' -Force
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10', 'item2|10') -Compress)
        Mock Invoke-CIPPMailboxItemExport {
            if ($ItemId -eq 'item2' -and $ExportUri -notmatch 'MBX:aux') {
                return New-FakeExport $ItemId $false 200 '{"value":[{"itemId":"item2","error":{"code":"ErrorArchiveFolderMovedPermanently","message":"https://graph.microsoft.com/beta/admin/exchange/mailboxes/MBX:aux/exportItems"}}]}'
            }
            New-FakeExport $ItemId
        }
        & $script:Run
        Should -Invoke Invoke-CIPPMailboxItemExport -Times 1 -Exactly -ParameterFilter { $ExportUri -eq 'https://graph.microsoft.com/beta/admin/exchange/mailboxes/MBX:aux/exportItems' }
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $type -eq 'DELETE' -and $uri -eq 'https://graph.microsoft.com/beta/admin/exchange/mailboxes/MBX:arch/folders/sf/items/item1?disposalType=softDelete' }
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $type -eq 'DELETE' -and $uri -match 'MBX:aux/folders/sf/items/item2\?disposalType=softDelete$' }
        (& $script:Final).Copied | Should -Be 2
    }

    It 'opens a new import session in the mailbox a 409 names' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10') -Compress)
        Mock Invoke-CIPPMailboxItemImport {
            if ($ImportUrl -notmatch 'auxdst') { return [pscustomobject]@{ Success = $false; StatusCode = 409; Body = '{"Message":"Invalid import session. The target session is expected in mailbox MBX:auxdst."}'; RetryAfterSeconds = 0 } }
            Ok
        }
        & $script:Run
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -match 'MBX:auxdst/createImportSession' }
        (& $script:Final).Copied | Should -Be 1
    }

    It 'resumes after the saved position, stops on cancel within a few items, and ignores superseded chunks' {
        $script:Chunk.Done = 10; $script:Chunk.Copied = 10
        & $script:Run
        Should -Invoke Invoke-CIPPMailboxItemImport -Times 2 -Exactly

        $script:Chunk.Done = 0; $script:Chunk.Copied = 0; $script:Chunk.State = 'Pending'
        $script:Reads = 0
        Mock Get-CIPPAzDataTableEntity {
            if ($Filter -match "PartitionKey eq 'Operation'") { $script:Reads++; if ($script:Reads -ge 3) { $script:Op.Status = 'Cancelled' }; return $script:Op }
            if ($Filter -match "RowKey eq 'c00001'") { return $script:Chunk }
            @()
        }
        & $script:Run
        Should -Invoke Invoke-CIPPMailboxItemImport -Times 6 -Exactly   # 2 before + item1..item5 minus corrupt item3 = 4 more
        (& $script:Final).State | Should -Be 'Stopped'

        $script:Op.Status = 'Copying'
        $script:Op | Add-Member -NotePropertyName PlanFirstChunk -NotePropertyValue 250 -Force
        & $script:Run
        Should -Invoke Invoke-CIPPMailboxItemImport -Times 6 -Exactly
    }

    It 'stops after a throttle sleep when a Resume has re-planned past it, without importing the item' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10', 'item2|10') -Compress)
        Mock Invoke-CIPPMailboxItemImport { [pscustomobject]@{ Success = $false; StatusCode = 429; Body = 'throttled'; RetryAfterSeconds = 290 } }
        Mock Start-Sleep { $script:Op | Add-Member -NotePropertyName PlanFirstChunk -NotePropertyValue 5 -Force }
        & $script:Run
        Should -Invoke Invoke-CIPPMailboxItemImport -Times 1 -Exactly
        $States = @($script:Saved | Where-Object { $_.RowKey -eq 'c00001' } | ForEach-Object State)
        $States[0] | Should -Be 'Running'   # heartbeat written before the sleep
        $States[-1] | Should -Be 'Stopped'
        (& $script:Final).Copied | Should -Be 0
        (& $script:Final).Failed | Should -Be 0
    }
}

Describe 'Push-MailboxCopyPlan' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'Modules/CIPPActivityTriggers/Public/Entrypoints/Activity Triggers/Mailbox Copy/Push-MailboxCopyPlan.ps1')
        function Key($k) { @([pscustomobject]@{ id = 'Binary 0x300b'; value = $k }) }
    }
    BeforeEach {
        $script:Saved = [System.Collections.Generic.List[object]]::new()
        $script:Op = [pscustomobject]@{ PartitionKey = 'Operation'; RowKey = '11111111-2222-3333-4444-555555555555'; Status = 'Planning'; SrcMailboxId = 'MBX:s'; DstMailboxId = 'MBX:d'; ChunkCount = 250; PlanFirstChunk = 250; Dedupe = $true }
        $script:Folder = [pscustomobject]@{ RowKey = 'f00001'; SrcFolderId = 'sf'; DstFolderId = 'df'; Path = 'Inbox'; ItemCount = 5; SrcMailboxId = 'MBX:s'; DstMailboxId = 'MBX:d'; SrcApi = 'beta'; DstApi = 'beta' }
        Mock Get-CIPPAzDataTableEntity {
            if ($Filter -match "PartitionKey eq 'Operation'") { return $script:Op }
            if ($Filter -match "RowKey gt 'c") { return @($script:Saved | Where-Object { $_.RowKey -like 'c*' }) }
            @($script:Folder)
        }
        Mock Add-CIPPAzDataTableEntity { $script:Saved.Add(($Entity | Select-Object *)) }
        Mock Start-CIPPOrchestrator { }
        Mock New-GraphGetRequest {
            if ($uri -match '/folders/df/items') { return @([pscustomobject]@{ id = 'd1'; singleValueExtendedProperties = (Key 'K1') }, [pscustomobject]@{ id = 'd2'; singleValueExtendedProperties = (Key 'K3') }) }
            @(1..5 | ForEach-Object { [pscustomobject]@{ id = "s$_"; size = 10; singleValueExtendedProperties = $(if ($_ -ne 5) { Key "K$_" }) } })
        }
    }

    It 'resume skips items whose search key is already in the destination and numbers chunks after the old ones' {
        Push-MailboxCopyPlan -Item ([pscustomobject]@{ OperationId = '11111111-2222-3333-4444-555555555555'; TenantFilter = 't' })
        $Chunk = $script:Saved | Where-Object { $_.RowKey -like 'c*' }
        @($Chunk).Count | Should -Be 1
        $Chunk.RowKey | Should -Be 'c00251'
        ($Chunk.Ids | ConvertFrom-Json) | Should -Be @('s2|10', 's4|10', 's5|10')   # s5 has no key: always copied
        $Final = $script:Saved | Where-Object { $_.RowKey -eq '11111111-2222-3333-4444-555555555555' } | Select-Object -Last 1
        $Final.AlreadyPresent | Should -Be 2
        $Final.Status | Should -Be 'Copying'
        Should -Invoke New-GraphGetRequest -ParameterFilter { $uri -match '/beta/admin/exchange/mailboxes/MBX:d/folders/df/items' -and $uri -match '0x300B' }
        Should -Invoke Start-CIPPOrchestrator -Times 1 -Exactly -ParameterFilter { $InputObject.Sequential -and $InputObject.Batch[0].ChunkKey -eq 'c00251' -and $InputObject.OrchestratorName -like '*_p250_lane0' }
    }

    It 'completes without starting lanes when everything is already there' {
        Mock New-GraphGetRequest {
            if ($uri -match '/folders/df/items') { return @(1..5 | ForEach-Object { [pscustomobject]@{ id = "d$_"; singleValueExtendedProperties = (Key "K$_") } }) }
            @(1..5 | ForEach-Object { [pscustomobject]@{ id = "s$_"; size = 10; singleValueExtendedProperties = (Key "K$_") } })
        }
        Push-MailboxCopyPlan -Item ([pscustomobject]@{ OperationId = '11111111-2222-3333-4444-555555555555'; TenantFilter = 't' })
        ($script:Saved | Where-Object { $_.RowKey -eq '11111111-2222-3333-4444-555555555555' } | Select-Object -Last 1).Status | Should -Be 'Completed'
        Should -Invoke Start-CIPPOrchestrator -Times 0 -Exactly
    }

    It 'a first run (no dedupe) does not read the destination' {
        $script:Op.Dedupe = $false; $script:Op.ChunkCount = 0; $script:Op.PlanFirstChunk = 0
        Push-MailboxCopyPlan -Item ([pscustomobject]@{ OperationId = '11111111-2222-3333-4444-555555555555'; TenantFilter = 't' })
        Should -Invoke New-GraphGetRequest -Times 0 -ParameterFilter { $uri -match '/folders/df/items' }
        ($script:Saved | Where-Object { $_.RowKey -eq 'c00001' }).Count | Should -Be 5
    }

    It 'gives each destination mailbox its own two lanes (main mailbox and archive throttle separately)' {
        $script:Op.Dedupe = $false; $script:Op.ChunkCount = 0; $script:Op.PlanFirstChunk = 0
        $Archive = [pscustomobject]@{ RowKey = 'f00002'; SrcFolderId = 'asf'; DstFolderId = 'adf'; Path = 'Archive/Inbox'; ItemCount = 5; SrcMailboxId = 'MBX:sa'; DstMailboxId = 'MBX:da'; SrcApi = 'beta'; DstApi = 'beta' }
        Mock Get-CIPPAzDataTableEntity {
            if ($Filter -match "PartitionKey eq 'Operation'") { return $script:Op }
            if ($Filter -match "RowKey gt 'c") { return @($script:Saved | Where-Object { $_.RowKey -like 'c*' }) }
            @($script:Folder, $Archive)
        }
        Mock New-GraphGetRequest { @(1..250 | ForEach-Object { [pscustomobject]@{ id = "s$_"; size = 10 } }) | Select-Object -Skip ([int]($uri -replace '.*skip=(\d+).*', '$1')) -First 100 }
        Push-MailboxCopyPlan -Item ([pscustomobject]@{ OperationId = '11111111-2222-3333-4444-555555555555'; TenantFilter = 't' })
        # 3 chunks per folder -> 2 lanes for MBX:d and 2 lanes for MBX:da
        Should -Invoke Start-CIPPOrchestrator -Times 4 -Exactly
        $Main = { $InputObject.Batch[0].ChunkKey -in @('c00001', 'c00002') }
        $Arch = { $InputObject.Batch[0].ChunkKey -in @('c00004', 'c00005') }
        Should -Invoke Start-CIPPOrchestrator -Times 2 -Exactly -ParameterFilter $Main
        Should -Invoke Start-CIPPOrchestrator -Times 2 -Exactly -ParameterFilter $Arch
    }
}
