function ConvertTo-CIPPSessionTimeline {
    <#
    .SYNOPSIS
        Keeps the Unified Audit Log records that belong to one sign-in session and merges them with the session's
        sign-ins into one timeline (US Central with UTC) and a summary.
    .DESCRIPTION
        Pure: no Graph calls, so the matching rules can be tested with synthetic records.

        A record belongs to the session when one of these equals the session (checked in this order; the first hit is
        reported as MatchedOn). Field locations were verified 2026-11-01 against live Graph auditLog/queries records:
          AADSessionId    auditData.AppAccessContext.AADSessionId. Exchange mailbox items (MailItemsAccessed, Create,
                          FolderBind, AttachmentAccess), Exchange admin cmdlets (Set-Mailbox, New-InboxRule, ...),
                          SharePoint and OneDrive file operations.
          SessionId       auditData.SessionId. Exchange records repeat the AAD session id here (always equal to
                          AADSessionId when both are present). Other workloads may use this name for their own
                          session; an exact match on the GUID is still the same session.
          DeviceSessionId auditData.DeviceProperties[Name=SessionId]. Entra STS logon records (UserLoggedIn,
                          UserLoginFailed) in the audit log.
          UniqueTokenId   auditData.AppAccessContext.UniqueTokenId equal to the uniqueTokenIdentifier of one of the
                          session's sign-ins. Catches records that carry the token but no AADSessionId (seen on some
                          MailItemsAccessed and Send records). Compared case-sensitively: it is base64url.
        Teams records were not present in the verification data; they are matched by the same fields if they carry them.
        Directory audit records (Update user, Add member to group, ...) carry no session field and cannot be matched.

        Mail subjects are never returned: mail is identified by InternetMessageId (or the item id) and folder path.
        Files are identified by their path (ObjectId / URL). Aspendora fork addition (Vikunja CIPP-12).
    .PARAMETER Records
        Graph security auditLog query records (id, createdDateTime, service, operation, clientIp, userPrincipalName,
        auditData).
    .PARAMETER SignIns
        The session's sign-ins from Get-CIPPSessionTimelineSignIns.
    .PARAMETER SessionId
        The session id being traced.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Records,
        [AllowNull()][object[]]$SignIns,
        [Parameter(Mandatory = $true)][string]$SessionId
    )

    $Target = $SessionId.Trim()
    $Tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($S in @($SignIns)) {
        if ($S -and $S.uniqueTokenIdentifier) { $null = $Tokens.Add([string]$S.uniqueTokenIdentifier) }
    }

    # Operation -> summary bucket. Anything not listed is still in the timeline and in ByOperation.
    $Buckets = @{
        MailItemsAccessed               = 'MailItemsRead'
        AttachmentAccess                = 'AttachmentsOpened'
        Send                            = 'MailsSent'
        SendAs                          = 'MailsSent'
        SendOnBehalf                    = 'MailsSent'
        SoftDelete                      = 'MailsDeleted'
        HardDelete                      = 'MailsDeleted'
        MoveToDeletedItems              = 'MailsDeleted'
        'New-InboxRule'                 = 'InboxRulesChanged'
        'Set-InboxRule'                 = 'InboxRulesChanged'
        'Remove-InboxRule'              = 'InboxRulesChanged'
        'Enable-InboxRule'              = 'InboxRulesChanged'
        'Disable-InboxRule'             = 'InboxRulesChanged'
        UpdateInboxRules                = 'InboxRulesChanged'
        'Add-MailboxPermission'         = 'MailboxPermissionsChanged'
        'Add-RecipientPermission'       = 'MailboxPermissionsChanged'
        'Add-MailboxFolderPermission'   = 'MailboxPermissionsChanged'
        'Set-MailboxFolderPermission'   = 'MailboxPermissionsChanged'
        FileAccessed                    = 'FilesAccessed'
        FileAccessedExtended            = 'FilesAccessed'
        FilePreviewed                   = 'FilesAccessed'
        FileDownloaded                  = 'FilesDownloaded'
        FileSyncDownloadedFull          = 'FilesDownloaded'
        FileSyncDownloadedPartial       = 'FilesDownloaded'
        FileUploaded                    = 'FilesChanged'
        FileModified                    = 'FilesChanged'
        FileModifiedExtended            = 'FilesChanged'
        FileRenamed                     = 'FilesChanged'
        FileMoved                       = 'FilesChanged'
        FileCopied                      = 'FilesChanged'
        FileSyncUploadedFull            = 'FilesChanged'
        FileDeleted                     = 'FilesDeleted'
        FileRecycled                    = 'FilesDeleted'
        FileDeletedFirstStageRecycleBin = 'FilesDeleted'
        SharingSet                      = 'SharesCreated'
        SharingInvitationCreated        = 'SharesCreated'
        AnonymousLinkCreated            = 'SharesCreated'
        CompanyLinkCreated              = 'SharesCreated'
        SecureLinkCreated               = 'SharesCreated'
        AddedToSecureLink               = 'SharesCreated'
        SharingLinkCreated              = 'SharesCreated'
        MessageSent                     = 'TeamsMessagesSent'
        MessageCreatedHasLink           = 'TeamsMessagesSent'
        'Consent to application.'       = 'AppConsents'
        'Add delegated permission grant.' = 'AppConsents'
    }
    $ForwardingParams = @('ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward')

    function Get-Prop($Object, [string]$Name) {
        if ($null -eq $Object) { return $null }
        if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
        $P = $Object.PSObject.Properties[$Name]
        if ($P) { return $P.Value }
        return $null
    }

    function Get-SessionMatch($AuditData) {
        $Ctx = Get-Prop $AuditData 'AppAccessContext'
        $Aad = [string](Get-Prop $Ctx 'AADSessionId')
        if ($Aad -and $Aad.Trim() -eq $Target) { return 'AADSessionId' }
        $Top = [string](Get-Prop $AuditData 'SessionId')
        if ($Top -and $Top.Trim() -eq $Target) { return 'SessionId' }
        foreach ($Dp in @(Get-Prop $AuditData 'DeviceProperties')) {
            if ($Dp -and [string](Get-Prop $Dp 'Name') -eq 'SessionId' -and ([string](Get-Prop $Dp 'Value')).Trim() -eq $Target) { return 'DeviceSessionId' }
        }
        $Uti = [string](Get-Prop $Ctx 'UniqueTokenId')
        if ($Uti -and $Tokens.Contains($Uti)) { return 'UniqueTokenId' }
        return $null
    }

    # The object a record touched, without mail subjects.
    function Get-RecordObject([string]$Operation, $Record, $AuditData) {
        $Folders = @(Get-Prop $AuditData 'Folders' | Where-Object { $_ })
        if ($Folders.Count -gt 0) {
            $ItemCount = 0
            foreach ($F in $Folders) { $ItemCount += @(Get-Prop $F 'FolderItems' | Where-Object { $_ }).Count }
            $Paths = @($Folders | ForEach-Object { [string](Get-Prop $_ 'Path') } | Where-Object { $_ } | Select-Object -Unique)
            return "$ItemCount item(s) in $($Paths -join ', ')"
        }
        $Item = Get-Prop $AuditData 'Item'
        if ($Item) {
            $MsgId = [string](Get-Prop $Item 'InternetMessageId')
            if (-not $MsgId) { $MsgId = [string](Get-Prop $Item 'Id') }
            $Path = [string](Get-Prop (Get-Prop $Item 'ParentFolder') 'Path')
            $Text = if ($MsgId) { "Message $MsgId" } else { 'Message' }
            if ($Path) { $Text += " in $Path" }
            return $Text
        }
        $Affected = @(Get-Prop $AuditData 'AffectedItems' | Where-Object { $_ })
        if ($Affected.Count -gt 0) {
            $Paths = @($Affected | ForEach-Object { [string](Get-Prop (Get-Prop $_ 'ParentFolder') 'Path') } | Where-Object { $_ } | Select-Object -Unique)
            return "$($Affected.Count) message(s)$(if ($Paths.Count) { " from $($Paths -join ', ')" })"
        }
        $Messages = @(Get-Prop $AuditData 'Messages' | Where-Object { $_ })
        if ($Messages.Count -gt 0) { return "$($Messages.Count) message(s)" }
        # Teams: chat/team names, never message text.
        $Team = [string](Get-Prop $AuditData 'TeamName')
        $Channel = [string](Get-Prop $AuditData 'ChannelName')
        if ($Team -or $Channel) { return (@($Team, $Channel) | Where-Object { $_ }) -join ' / ' }
        $Object = [string](Get-Prop $AuditData 'ObjectId')
        if (-not $Object) { $Object = [string](Get-Prop $Record 'objectId') }
        if (-not $Object) { $Object = [string](Get-Prop $AuditData 'SourceFileName') }
        return $Object
    }

    # Item count for the summary: MailItemsAccessed counts mails, not records.
    function Get-ItemCount([string]$Operation, $AuditData) {
        $Folders = @(Get-Prop $AuditData 'Folders' | Where-Object { $_ })
        if ($Folders.Count -gt 0) {
            $N = 0
            foreach ($F in $Folders) { $N += @(Get-Prop $F 'FolderItems' | Where-Object { $_ }).Count }
            if ($N -gt 0) { return $N }
        }
        $Affected = @(Get-Prop $AuditData 'AffectedItems' | Where-Object { $_ })
        if ($Affected.Count -gt 0) { return $Affected.Count }
        $Messages = @(Get-Prop $AuditData 'Messages' | Where-Object { $_ })
        if ($Messages.Count -gt 0) { return $Messages.Count }
        $OpCount = Get-Prop $AuditData 'OperationCount'
        if ($OpCount -as [int]) { return [int]$OpCount }
        return 1
    }

    function Get-UserAgent($AuditData) {
        foreach ($Name in 'UserAgent', 'ClientInfoString') {
            $V = [string](Get-Prop $AuditData $Name)
            if ($V) { return $V }
        }
        foreach ($Ep in @(Get-Prop $AuditData 'ExtendedProperties')) {
            if ($Ep -and [string](Get-Prop $Ep 'Name') -eq 'UserAgent') { return [string](Get-Prop $Ep 'Value') }
        }
        return $null
    }

    $Rows = [System.Collections.Generic.List[object]]::new()
    $MatchedBy = @{ AADSessionId = 0; SessionId = 0; DeviceSessionId = 0; UniqueTokenId = 0 }
    $Highlights = [ordered]@{
        SignIns = 0; FailedSignIns = 0; MailItemsRead = 0; AttachmentsOpened = 0; MailsSent = 0; MailsDeleted = 0
        InboxRulesChanged = 0; ForwardingChanged = 0; MailboxPermissionsChanged = 0; FilesAccessed = 0; FilesDownloaded = 0
        FilesChanged = 0; FilesDeleted = 0; SharesCreated = 0; TeamsMessagesSent = 0; AppConsents = 0
    }
    $RecordsRead = 0
    $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($Record in @($Records)) {
        if (-not $Record) { continue }
        $RecordsRead++
        $AuditData = Get-Prop $Record 'auditData'
        $Match = Get-SessionMatch $AuditData
        if (-not $Match) { continue }
        $RecordId = [string](Get-Prop $Record 'id')
        if ($RecordId -and -not $Seen.Add($RecordId)) { continue }
        $MatchedBy[$Match]++

        $Operation = [string](Get-Prop $Record 'operation')
        if (-not $Operation) { $Operation = [string](Get-Prop $AuditData 'Operation') }
        $Workload = [string](Get-Prop $Record 'service')
        if (-not $Workload) { $Workload = [string](Get-Prop $AuditData 'Workload') }
        $When = Get-Prop $Record 'createdDateTime'
        if (-not $When) { $When = Get-Prop $AuditData 'CreationTime' }
        $Time = ConvertTo-CIPPCentralTime -Value $When
        $RawIp = [string](Get-Prop $Record 'clientIp')
        if (-not $RawIp) { $RawIp = [string](Get-Prop $AuditData 'ClientIP') }
        if (-not $RawIp) { $RawIp = [string](Get-Prop $AuditData 'ClientIPAddress') }
        if (-not $RawIp) { $RawIp = [string](Get-Prop $AuditData 'ActorIpAddress') }
        $Items = Get-ItemCount -Operation $Operation -AuditData $AuditData

        $Bucket = $Buckets[$Operation]
        if ($Operation -eq 'Set-Mailbox') {
            $Names = @(Get-Prop $AuditData 'Parameters' | ForEach-Object { [string](Get-Prop $_ 'Name') })
            if (@($Names | Where-Object { $ForwardingParams -contains $_ }).Count -gt 0) { $Bucket = 'ForwardingChanged' }
        }
        if ($Bucket) {
            # Mail reads, attachment opens and deletes count messages (one record can cover many); the rest count actions.
            $Add = 1
            if ($Bucket -in @('MailItemsRead', 'AttachmentsOpened', 'MailsDeleted')) { $Add = $Items }
            $Highlights[$Bucket] = $Highlights[$Bucket] + $Add
        }

        $Rows.Add([pscustomobject]@{
                Time      = if ($Time) { $Time.Display } else { $null }
                TimeUtc   = if ($Time) { $Time.Utc } else { $null }
                Source    = 'AuditLog'
                Workload  = $Workload
                Operation = $Operation
                Object    = Get-RecordObject -Operation $Operation -Record $Record -AuditData $AuditData
                Count     = $Items
                Result    = [string](Get-Prop $AuditData 'ResultStatus')
                ClientIP  = ConvertTo-CIPPBecHostAddress -Address $RawIp
                UserAgent = Get-UserAgent $AuditData
                App       = [string](Get-Prop $AuditData 'ApplicationDisplayName')
                MatchedOn = $Match
                RecordId  = $RecordId
                Location  = $null
            })
    }

    foreach ($S in @($SignIns)) {
        if (-not $S) { continue }
        $Time = ConvertTo-CIPPCentralTime -Value (Get-Prop $S 'createdDateTime')
        $Status = Get-Prop $S 'status'
        $Code = Get-Prop $Status 'errorCode'
        $Failed = ($null -ne $Code) -and ([string]$Code -ne '0')
        $Highlights.SignIns++
        if ($Failed) { $Highlights.FailedSignIns++ }
        $Interactive = (Get-Prop $S 'isInteractive') -eq $true -or @(Get-Prop $S 'signInEventTypes') -contains 'interactiveUser'
        $App = [string](Get-Prop $S 'appDisplayName')
        $Resource = [string](Get-Prop $S 'resourceDisplayName')
        $Loc = Get-Prop $S 'location'
        $Place = (@([string](Get-Prop $Loc 'city'), [string](Get-Prop $Loc 'countryOrRegion')) | Where-Object { $_ }) -join ', '
        $Rows.Add([pscustomobject]@{
                Time      = if ($Time) { $Time.Display } else { $null }
                TimeUtc   = if ($Time) { $Time.Utc } else { $null }
                Source    = 'SignIn'
                Workload  = 'Entra sign-in'
                Operation = if ($Interactive) { 'Sign-in (interactive)' } else { 'Sign-in (non-interactive)' }
                Object    = (@($App, $Resource) | Where-Object { $_ }) -join ' -> '
                Count     = 1
                Result    = if ($Failed) { "Failure $Code" } else { 'Success' }
                ClientIP  = ConvertTo-CIPPBecHostAddress -Address ([string](Get-Prop $S 'ipAddress'))
                UserAgent = [string](Get-Prop $S 'userAgent')
                App       = $App
                MatchedOn = 'sessionId'
                RecordId  = [string](Get-Prop $S 'id')
                Location  = $Place
            })
    }

    # TimeUtc is ISO 8601 with a fixed format, so it sorts as text. -Stable keeps same-second rows in source order.
    $Timeline = @($Rows | Sort-Object -Property TimeUtc -Stable)

    $ByWorkload = @($Rows | Group-Object -Property Workload | Sort-Object -Property Count -Descending | ForEach-Object {
            [pscustomobject]@{ Workload = $_.Name; Count = $_.Count }
        })
    $ByOperation = @($Rows | Group-Object -Property Workload, Operation | Sort-Object -Property Count -Descending | ForEach-Object {
            $First = $_.Group[0]
            [pscustomobject]@{ Workload = $First.Workload; Operation = $First.Operation; Records = $_.Count; Items = ($_.Group | Measure-Object -Property Count -Sum).Sum }
        })
    $ByIP = @($Rows | Where-Object { $_.ClientIP } | Group-Object -Property ClientIP | Sort-Object -Property Count -Descending | ForEach-Object {
            $Sorted = @($_.Group | Sort-Object -Property TimeUtc)
            [pscustomobject]@{ ClientIP = $_.Name; Count = $_.Count; FirstSeen = $Sorted[0].Time; LastSeen = $Sorted[-1].Time }
        })

    [pscustomobject]@{
        SessionId      = $Target
        RecordsRead    = $RecordsRead
        RecordsMatched = $Rows.Count - @($SignIns | Where-Object { $_ }).Count
        SignInCount    = @($SignIns | Where-Object { $_ }).Count
        FirstSeen      = if ($Timeline.Count) { $Timeline[0].Time } else { $null }
        LastSeen       = if ($Timeline.Count) { $Timeline[-1].Time } else { $null }
        MatchedBy      = [pscustomobject]$MatchedBy
        Highlights     = [pscustomobject]$Highlights
        ByWorkload     = $ByWorkload
        ByOperation    = $ByOperation
        ByIP           = $ByIP
        Timeline       = $Timeline
    }
}
