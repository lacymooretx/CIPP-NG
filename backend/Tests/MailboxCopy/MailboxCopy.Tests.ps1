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
            if ($uri -match '/settings/exchange') { return [pscustomobject]@{ primaryMailboxId = "MBX:$($uri -replace '.*/users/([^/]+)/.*','$1')" } }
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
        Should -Invoke New-GraphPOSTRequest -Times 3 -Exactly -ParameterFilter { $uri -match 'exportItems' }
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
}
