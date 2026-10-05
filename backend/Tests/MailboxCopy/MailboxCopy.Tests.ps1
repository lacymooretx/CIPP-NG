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
    BeforeEach {
        $script:Saved = [System.Collections.Generic.List[object]]::new()
        $script:Op = [pscustomobject]@{ PartitionKey = 'Operation'; RowKey = 'op1'; Operation = 'Copy'; Status = 'Copying'; SrcMailboxId = 'MBX:s'; DstMailboxId = 'MBX:d'; SourceUser = 's'; DestinationUser = 'd' }
        $Ids = 1..25 | ForEach-Object { "item$_|1000" }
        $script:Chunk = [pscustomobject]@{ PartitionKey = 'op1'; RowKey = 'c00001'; SrcFolderId = 'sf'; DstFolderId = 'df'; Ids = (ConvertTo-Json -InputObject @($Ids) -Compress); Done = 0; Copied = 0; Failed = 0; State = 'Pending'; Errors = '[]' }
        Mock Get-CIPPAzDataTableEntity {
            if ($Filter -match "PartitionKey eq 'Operation'") { return $script:Op }
            if ($Filter -match "State ne 'Done'") { return @() }
            if ($Filter -match "RowKey eq 'c00001'") { return $script:Chunk }
            return @($script:Chunk)
        }
        Mock Add-CIPPAzDataTableEntity { $script:Saved.Add(($Entity | Select-Object *)) }
        Mock New-GraphPOSTRequest {
            if ($uri -match 'createImportSession') { return [pscustomobject]@{ importUrl = 'https://outlook/import?authtoken=x'; expirationDateTime = [DateTime]::UtcNow.AddHours(1).ToString('o') } }
            if ($uri -match 'exportItems') {
                $ids = ($body | ConvertFrom-Json).itemIds
                return [pscustomobject]@{ value = @($ids | ForEach-Object {
                        if ($_ -eq 'item3') { [pscustomobject]@{ itemId = $_; error = [pscustomobject]@{ code = 'ErrorCorruptData'; message = 'bad item' } } }
                        else { [pscustomobject]@{ itemId = $_; data = 'QUJD' } }
                    }) }
            }
        }
        Mock Invoke-RestMethod { [pscustomobject]@{ itemId = 'new'; changeKey = 'k' } }
    }

    It 'exports in groups of 10, imports each item, counts failures and closes the operation' {
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        # 3 groups + one solo retry of the item the group export flagged as corrupt
        Should -Invoke New-GraphPOSTRequest -Times 4 -Exactly -ParameterFilter { $uri -match 'exportItems' }
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -match 'createImportSession' }
        Should -Invoke Invoke-RestMethod -Times 24 -Exactly -ParameterFilter { $Body -match '"FolderId":"df"' -and $Body -match '"Mode":"create"' }
        $Final = $script:Saved | Where-Object { $_.RowKey -eq 'c00001' } | Select-Object -Last 1
        $Final.State | Should -Be 'Done'
        $Final.Copied | Should -Be 24
        $Final.Failed | Should -Be 1
        $Final.Errors | Should -Match 'ErrorCorruptData'
        ($script:Saved | Where-Object { $_.RowKey -eq 'op1' } | Select-Object -Last 1).Status | Should -Be 'CompletedWithErrors'
    }

    It 'deletes each source item after import in Move mode' {
        $script:Op.Operation = 'Move'
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        Should -Invoke New-GraphPOSTRequest -Times 24 -Exactly -ParameterFilter { $type -eq 'DELETE' -and $uri -match '/folders/sf/items/item\d+\?disposalType=softDelete$' }
    }

    It 'resumes after the saved position and does nothing for a finished or cancelled copy' {
        $script:Chunk.Done = 20; $script:Chunk.Copied = 20
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        Should -Invoke Invoke-RestMethod -Times 5 -Exactly
        $script:Op.Status = 'Cancelled'
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        Should -Invoke Invoke-RestMethod -Times 5 -Exactly
    }

    It 'reissues exports the archive redirected, and deletes moved items from the auxiliary mailbox' {
        $script:Op.Operation = 'Move'
        $script:Chunk | Add-Member -NotePropertyName SrcMailboxId -NotePropertyValue 'MBX:arch' -Force
        $script:Chunk | Add-Member -NotePropertyName SrcApi -NotePropertyValue 'beta' -Force
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10', 'item2|10') -Compress)
        Mock New-GraphPOSTRequest {
            if ($uri -match 'createImportSession') { return [pscustomobject]@{ importUrl = 'https://outlook/import'; expirationDateTime = [DateTime]::UtcNow.AddHours(1).ToString('o') } }
            if ($uri -match 'MBX:aux/exportItems') { return [pscustomobject]@{ value = @([pscustomobject]@{ itemId = 'item2'; data = 'QUJD' }) } }
            if ($uri -match 'exportItems') {
                return [pscustomobject]@{ value = @(
                        [pscustomobject]@{ itemId = 'item1'; data = 'QUJD' }
                        [pscustomobject]@{ itemId = 'item2'; error = [pscustomobject]@{ code = 'ErrorArchiveFolderMovedPermanently'; message = 'https://graph.microsoft.com/beta/admin/exchange/mailboxes/MBX:aux/exportItems' } }
                    ) }
            }
        }
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -match '/beta/admin/exchange/mailboxes/MBX:arch/exportItems' }
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -eq 'https://graph.microsoft.com/beta/admin/exchange/mailboxes/MBX:aux/exportItems' }
        Should -Invoke Invoke-RestMethod -Times 2 -Exactly
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $type -eq 'DELETE' -and $uri -match 'MBX:arch/folders/sf/items/item1\?' }
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $type -eq 'DELETE' -and $uri -match 'MBX:aux/folders/sf/items/item2\?' }
    }

    It 'opens a new import session in the mailbox a 409 names' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10') -Compress)
        $script:Imports = 0
        Mock Invoke-RestMethod {
            $script:Imports++
            if ($script:Imports -eq 1) {
                $Err = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Conflict'), 'x', 'InvalidOperation', $null)
                $Err.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"Message":"Invalid import session. The target session is expected in mailbox MBX:auxdst."}')
                $Resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Conflict)
                $Ex = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Conflict', $Resp)
                throw [System.Management.Automation.ErrorRecord]::new($Ex, 'x', 'InvalidOperation', $null) | ForEach-Object { $_.ErrorDetails = $Err.ErrorDetails; $_ }
            }
            [pscustomobject]@{ itemId = 'new' }
        }
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -match 'MBX:auxdst/createImportSession' }
        ($script:Saved | Where-Object { $_.RowKey -eq 'c00001' } | Select-Object -Last 1).Copied | Should -Be 1
    }

    It 'survives an OutOfMemory group export by retrying each item alone (3E failure)' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @(1..5 | ForEach-Object { "item$_|1000" }) -Compress)
        Mock New-GraphPOSTRequest {
            if ($uri -match 'createImportSession') { return [pscustomobject]@{ importUrl = 'https://outlook/import'; expirationDateTime = [DateTime]::UtcNow.AddHours(1).ToString('o') } }
            $ids = @(($body | ConvertFrom-Json).itemIds)
            if ($ids.Count -gt 1) { throw [System.OutOfMemoryException]::new() }
            if ($ids[0] -eq 'item4') { throw [System.OutOfMemoryException]::new() }
            [pscustomobject]@{ value = @([pscustomobject]@{ itemId = $ids[0]; data = 'QUJD' }) }
        }
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        $Final = $script:Saved | Where-Object { $_.RowKey -eq 'c00001' } | Select-Object -Last 1
        $Final.State | Should -Be 'Done'
        $Final.Copied | Should -Be 4
        $Final.Failed | Should -Be 1
        $Final.Errors | Should -Match 'ExportFailed'
    }

    It 'retries items a group export silently dropped (NotReturned)' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10', 'item2|10', 'item3|10') -Compress)
        Mock New-GraphPOSTRequest {
            if ($uri -match 'createImportSession') { return [pscustomobject]@{ importUrl = 'https://outlook/import'; expirationDateTime = [DateTime]::UtcNow.AddHours(1).ToString('o') } }
            $ids = @(($body | ConvertFrom-Json).itemIds)
            # The group answer leaves item2 out; asked alone, it comes back.
            [pscustomobject]@{ value = @($ids | Where-Object { $ids.Count -eq 1 -or $_ -ne 'item2' } | ForEach-Object { [pscustomobject]@{ itemId = $_; data = 'QUJD' } }) }
        }
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        ($script:Saved | Where-Object { $_.RowKey -eq 'c00001' } | Select-Object -Last 1).Copied | Should -Be 3
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $body -eq '{"itemIds":["item2"]}' }
    }

    It 'sends items reported over 1 MB in their own export and builds the import body without re-serialising' {
        $script:Chunk.Ids = (ConvertTo-Json -InputObject @('item1|10', 'item2|5000000', 'item4|10') -Compress)   # item3 is the mock's corrupt item
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $body -eq '{"itemIds":["item2"]}' }
        Should -Invoke Invoke-RestMethod -Times 3 -Exactly -ParameterFilter { $Body -eq '{"FolderId":"df","Mode":"create","Data":"QUJD"}' }
    }

    It 'stops between groups when the copy is cancelled mid-chunk' {
        $script:Calls = 0
        Mock Get-CIPPAzDataTableEntity {
            if ($Filter -match "PartitionKey eq 'Operation'") {
                $script:Calls++
                if ($script:Calls -ge 3) { $script:Op.Status = 'Cancelled' }
                return $script:Op
            }
            if ($Filter -match "RowKey eq 'c00001'") { return $script:Chunk }
            return @()
        }
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        Should -Invoke Invoke-RestMethod -Times 9 -Exactly   # first group of 10, minus the mock's corrupt item3
        ($script:Saved | Where-Object { $_.RowKey -eq 'c00001' } | Select-Object -Last 1).State | Should -Be 'Cancelled'
    }

    It 'ignores chunks superseded by a resume' {
        $script:Op | Add-Member -NotePropertyName PlanFirstChunk -NotePropertyValue 250 -Force
        Push-MailboxCopyChunk -Item ([pscustomobject]@{ OperationId = 'op1'; TenantFilter = 't'; ChunkKey = 'c00001' })
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
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
        Should -Invoke Start-CIPPOrchestrator -Times 1 -Exactly -ParameterFilter { $InputObject.Sequential -and $InputObject.Batch[0].ChunkKey -eq 'c00251' }
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
}
