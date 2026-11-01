function Resolve-CIPPMailTriageStep {
    <#
    .SYNOPSIS
        Grades one step of the mail-not-received triage from data already collected (no API calls).
    .DESCRIPTION
        Keys: ServiceHealth, MessageTrace, Quarantine, TransportRules, InboxRules, Restrictions, Quota,
        SenderBlocks, SignIn. Context carries Recipient, Sender (optional), SenderDomain, RecipientDomain,
        AcceptedDomains. Returns Status (OK / Problem / Unknown), a plain-English Summary, Findings (strings) and
        Evidence (trimmed rows, times in US Central with UTC alongside).
        Kept free of API calls so the grading rules can be unit-tested. Aspendora fork addition (Vikunja CIPP-38).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('ServiceHealth', 'MessageTrace', 'Quarantine', 'TransportRules', 'InboxRules', 'Restrictions', 'Quota', 'SenderBlocks', 'SignIn')][string]$Key,
        [hashtable]$Data = @{},
        [hashtable]$Context = @{}
    )

    $Sender = ([string]$Context.Sender).Trim().ToLowerInvariant()
    $SenderDomain = if ($Context.SenderDomain) { ([string]$Context.SenderDomain).ToLowerInvariant() } elseif ($Sender -match '@') { $Sender.Split('@')[-1] } else { '' }
    $Recipient = ([string]$Context.Recipient).Trim().ToLowerInvariant()
    $RecipientDomain = if ($Context.RecipientDomain) { ([string]$Context.RecipientDomain).ToLowerInvariant() } elseif ($Recipient -match '@') { $Recipient.Split('@')[-1] } else { '' }
    $Accepted = @($Context.AcceptedDomains | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $SenderIsInternal = $SenderDomain -and ($Accepted -contains $SenderDomain)
    $Findings = [System.Collections.Generic.List[string]]::new()
    $Status = 'OK'
    $Summary = ''
    $Evidence = $null

    # Size strings from EXO look like '43.68 GB (46,897,363,235 bytes)' or 'Unlimited'.
    $ToBytes = {
        param($Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [long] -or $Value -is [int] -or $Value -is [double] -or $Value -is [decimal]) { return [double]$Value }
        $Text = [string]$Value
        if ($Text -match '\(([\d,]+)\s*bytes\)') { return [double]($Matches[1] -replace ',', '') }
        return $null
    }
    $Time = { param($Value) (ConvertTo-CIPPCentralTime -Value $Value).Display }
    # Does a free-form entry (address, display string '"x" [SMTP:a@b]', domain) name this sender?
    $NamesSender = {
        param($Entry)
        if (-not $Sender) { return $false }
        $E = ([string]$Entry).ToLowerInvariant()
        if (-not $E) { return $false }
        return ($E.Contains($Sender) -or $E -eq $SenderDomain -or $E.EndsWith("@$SenderDomain") -or $E.Contains("smtp:$sender"))
    }

    switch ($Key) {
        'ServiceHealth' {
            $Issues = @($Data.Issues | Where-Object { $_ -and $_.isResolved -ne $true -and ([string]$_.service) -match 'Exchange' })
            $MailFlow = 'mail ?flow|deliver|transport|delay|queue|receiv|send|inbound|outbound|NDR|spam|quarantin'
            $Relevant = @($Issues | Where-Object { $_.classification -eq 'incident' -or ("$($_.title) $($_.feature) $($_.featureGroup) $($_.impactDescription)" -match $MailFlow) })
            $Evidence = @($Issues | ForEach-Object { [pscustomobject]@{ Id = $_.id; Classification = $_.classification; Status = $_.status; Title = $_.title; Feature = $_.feature; Started = (& $Time $_.startDateTime); LastUpdate = (& $Time $_.lastModifiedDateTime) } })
            if ($Relevant.Count -gt 0) {
                $Status = 'Problem'
                $Summary = "Microsoft has $($Relevant.Count) open Exchange Online issue(s) that could affect mail delivery: " + (($Relevant | ForEach-Object { "$($_.id) ($($_.classification)) $($_.title)" }) -join '; ') + '.'
            } elseif ($Issues.Count -gt 0) {
                $Summary = "$($Issues.Count) open Exchange Online advisory(ies), none about mail flow: " + (($Issues | ForEach-Object { "$($_.id) $($_.title)" }) -join '; ') + '.'
            } else {
                $Summary = 'No open Exchange Online incidents or advisories.'
            }
        }
        'MessageTrace' {
            $Rows = @($Data.Rows | Where-Object { $_ })
            $Rows = @($Rows | Sort-Object -Property { (ConvertTo-CIPPCentralTime -Value $_.Received).Utc } -Descending)
            $Evidence = @($Rows | Select-Object -First 25 | ForEach-Object { [pscustomobject]@{ Received = (& $Time $_.Received); ReceivedUtc = (ConvertTo-CIPPCentralTime -Value $_.Received).Utc; Sender = $_.SenderAddress; Recipient = $_.RecipientAddress; Subject = $_.Subject; Status = $_.Status; MessageTraceId = $_.MessageTraceId } })
            $Groups = @($Rows | Group-Object -Property Status | Sort-Object Count -Descending)
            $Counts = ($Groups | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
            $From = if ($Sender) { " from $Sender" } else { '' }
            if ($Data.Truncated -eq $true) { $Findings.Add('The trace hit its page cap; older messages in the window were not read.') }
            if ($Rows.Count -eq 0) {
                $Status = 'Problem'
                $Summary = if ($Sender) {
                    "No message$From to $Recipient reached Exchange Online in the window. The sender's server never handed it over or rejected it first - ask the sender for the bounce (NDR) or their sent-item time, and check the sender address is exact."
                } else {
                    "No mail at all reached $Recipient in the window. Check the address is right (aliases are traced under the primary address) and the domain's MX record."
                }
            } else {
                $Bad = @($Rows | Where-Object { $_.Status -in @('Failed', 'Quarantined', 'FilteredAsSpam', 'Pending', 'GettingStatus') })
                $Latest = $Rows[0]
                if ($Bad.Count -gt 0) {
                    $Status = 'Problem'
                    $Why = foreach ($G in ($Groups | Where-Object { $_.Name -ne 'Delivered' -and $_.Name -ne 'Expanded' })) {
                        switch ($G.Name) {
                            'FilteredAsSpam' { "$($G.Count) went to the Junk Email folder (filtered as spam)" }
                            'Quarantined' { "$($G.Count) were quarantined" }
                            'Failed' { "$($G.Count) failed delivery (the sender got an NDR)" }
                            'Pending' { "$($G.Count) are still pending / deferred (Exchange is retrying)" }
                            'GettingStatus' { "$($G.Count) are still being processed" }
                            default { "$($G.Count) $($G.Name)" }
                        }
                    }
                    $Summary = "$($Rows.Count) message row(s)$From to ${Recipient}: $Counts. " + (($Why | Where-Object { $_ }) -join '; ') + ". Latest: $($Latest.Status) at $(& $Time $Latest.Received)."
                } else {
                    $Summary = "$($Rows.Count) message row(s)$From to $Recipient, all delivered ($Counts). Latest delivered at $(& $Time $Latest.Received). If the user still cannot see it, check the inbox rules and Junk folder steps below."
                }
            }
        }
        'Quarantine' {
            $Msgs = @($Data.Messages | Where-Object { $_ -and $_.ReleaseStatus -ne 'RELEASED' -and $_.Released -ne $true })
            $Evidence = @($Msgs | Select-Object -First 25 | ForEach-Object { [pscustomobject]@{ Received = (& $Time $_.ReceivedTime); Sender = $_.SenderAddress; Subject = $_.Subject; Type = $_.Type; Policy = "$($_.PolicyType)/$($_.PolicyName)"; Expires = (& $Time $_.Expires); Identity = $_.Identity } })
            if ($Msgs.Count -gt 0) {
                $Status = 'Problem'
                $Types = ($Msgs | Group-Object Type | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
                $Summary = "$($Msgs.Count) unreleased message(s) in quarantine for $Recipient ($Types). Review and release from Email > Quarantine if legitimate; High Confidence Phish needs an admin to release."
            } else {
                $Summary = "Nothing in quarantine for $Recipient in the window."
            }
        }
        'TransportRules' {
            $Rules = @($Data.Rules | Where-Object { $_ -and $_.State -eq 'Enabled' })
            $Listify = { param($V) @($V | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() }) }
            $Hits = foreach ($R in $Rules) {
                $Touches = [System.Collections.Generic.List[string]]::new()
                if ($Sender) {
                    if ((& $Listify $R.From) | Where-Object { & $NamesSender $_ }) { $Touches.Add('From') }
                    if ($SenderDomain -and ((& $Listify $R.SenderDomainIs) -contains $SenderDomain)) { $Touches.Add('SenderDomainIs') }
                    if ((& $Listify $R.FromAddressContainsWords) | Where-Object { $Sender.Contains($_) }) { $Touches.Add('FromAddressContainsWords') }
                    foreach ($P in (& $Listify $R.FromAddressMatchesPatterns)) { try { if ($Sender -match $P) { $Touches.Add('FromAddressMatchesPatterns'); break } } catch { } }
                }
                if ($Recipient) {
                    if ((& $Listify $R.SentTo) | Where-Object { $_.Contains($Recipient) }) { $Touches.Add('SentTo') }
                    if ($RecipientDomain -and ((& $Listify $R.RecipientDomainIs) -contains $RecipientDomain)) { $Touches.Add('RecipientDomainIs') }
                    if ((& $Listify $R.AnyOfRecipientAddressContainsWords) | Where-Object { $Recipient.Contains($_) }) { $Touches.Add('AnyOfRecipientAddressContainsWords') }
                    if ((& $Listify $R.RecipientAddressContainsWords) | Where-Object { $Recipient.Contains($_) }) { $Touches.Add('RecipientAddressContainsWords') }
                }
                $Excepted = ($Sender -and (((& $Listify $R.ExceptIfFrom) | Where-Object { & $NamesSender $_ }) -or ($SenderDomain -and ((& $Listify $R.ExceptIfSenderDomainIs) -contains $SenderDomain)))) -or
                ($Recipient -and (((& $Listify $R.ExceptIfSentTo) | Where-Object { $_.Contains($Recipient) }) -or ($RecipientDomain -and ((& $Listify $R.ExceptIfRecipientDomainIs) -contains $RecipientDomain))))
                $Actions = [System.Collections.Generic.List[string]]::new()
                if ($R.DeleteMessage -eq $true) { $Actions.Add('deletes the message') }
                if ($R.Quarantine -eq $true) { $Actions.Add('quarantines it') }
                if ($R.RejectMessageReasonText -or $R.RejectMessageEnhancedStatusCode) { $Actions.Add('rejects it (NDR)') }
                if ($R.RedirectMessageTo) { $Actions.Add("redirects it to $(@($R.RedirectMessageTo) -join ', ')") }
                if ($R.ModerateMessageByUser -or $R.ModerateMessageByManager -eq $true) { $Actions.Add('holds it for moderation') }
                if ($R.SetSCL -and "$($R.SetSCL)" -match '^\d+$' -and [int]$R.SetSCL -ge 5) { $Actions.Add("sets SCL $($R.SetSCL) (Junk/quarantine)") }
                if ($R.RouteMessageOutboundConnector) { $Actions.Add("routes it via connector $($R.RouteMessageOutboundConnector)") }
                $Enforced = -not $R.Mode -or $R.Mode -eq 'Enforce'
                [pscustomobject]@{ Name = $R.Name; Priority = $R.Priority; Mode = $R.Mode; Touches = @($Touches); Excepted = [bool]$Excepted; Actions = @($Actions); Enforced = $Enforced; Description = $R.Description }
            }
            $Hits = @($Hits)
            $Direct = @($Hits | Where-Object { $_.Touches.Count -gt 0 -and -not $_.Excepted -and $_.Actions.Count -gt 0 -and $_.Enforced })
            $Broad = @($Hits | Where-Object { $_.Touches.Count -eq 0 -and $_.Actions.Count -gt 0 -and $_.Enforced })
            $Evidence = @($Hits | Where-Object { $_.Touches.Count -gt 0 -or $_.Actions.Count -gt 0 } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Priority = $_.Priority; Mode = $_.Mode; MatchesOn = ($_.Touches -join ', '); ExceptionApplies = $_.Excepted; Effect = ($_.Actions -join '; ') } })
            foreach ($B in $Broad) { $Findings.Add("'$($B.Name)' (priority $($B.Priority)) $($B.Actions -join '; ') when its other conditions match (attachment type, header, scope...). Check the trace detail for a Transport rule event.") }
            if ($Direct.Count -gt 0) {
                $Status = 'Problem'
                $Summary = "$($Direct.Count) enabled mail flow rule(s) name this sender/recipient and act on the message: " + (($Direct | ForEach-Object { "'$($_.Name)' ($($_.Touches -join '/')) $($_.Actions -join '; ')" }) -join ' | ') + '.'
            } else {
                $Summary = "$($Rules.Count) enabled mail flow rule(s); none names this sender or recipient with a blocking or diverting action." + $(if ($Broad.Count) { " $($Broad.Count) broad rule(s) could still apply depending on content - see findings." } else { '' })
            }
        }
        'InboxRules' {
            $Rules = @($Data.Rules | Where-Object { $_ -and $_.Enabled -eq $true -and $_.Name -ne 'Junk E-mail Rule' -and $_.Name -notlike 'Microsoft.Exchange.OOF.*' })
            $Classified = foreach ($R in $Rules) {
                $Effects = [System.Collections.Generic.List[string]]::new()
                if ($R.DeleteMessage -eq $true) { $Effects.Add('deletes') }
                if ($R.SoftDeleteMessage -eq $true) { $Effects.Add('soft-deletes') }
                if ($R.MoveToFolder) { $Effects.Add("moves to '$($R.MoveToFolder)'") }
                if ($R.RedirectTo) { $Effects.Add("redirects to $(@($R.RedirectTo) -join ', ')") }
                if ($R.ForwardTo) { $Effects.Add("forwards to $(@($R.ForwardTo) -join ', ')") }
                if ($R.ForwardAsAttachmentTo) { $Effects.Add("forwards as attachment to $(@($R.ForwardAsAttachmentTo) -join ', ')") }
                if ($R.MarkAsRead -eq $true) { $Effects.Add('marks read') }
                $FromConds = @(@($R.From) + @($R.FromAddressContainsWords) + @($R.SenderAddressContainsWords) | Where-Object { $_ })
                $SenderMatch = $Sender -and ($FromConds | Where-Object { (& $NamesSender $_) -or $Sender.Contains(([string]$_).ToLowerInvariant()) })
                $HasConditions = ([string]$R.Description) -match 'If the message'
                $Scope = if ($SenderMatch) { 'Sender' } elseif ($FromConds.Count -gt 0) { 'OtherSender' } elseif ($HasConditions) { 'Content' } else { 'All' }
                $Hides = @($Effects | Where-Object { $_ -match '^(deletes|soft-deletes|moves|redirects)' }).Count -gt 0
                [pscustomobject]@{ Name = $R.Name; Priority = $R.Priority; Scope = $Scope; Effects = @($Effects); Hides = $Hides; InError = $R.InError -eq $true; Description = ([string]$R.Description).Trim() }
            }
            $Classified = @($Classified)
            $Evidence = @($Classified | Where-Object { $_.Effects.Count -gt 0 } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Priority = $_.Priority; AppliesTo = $_.Scope; Effect = ($_.Effects -join '; '); Conditions = ($_.Description -replace '\s+', ' ') } })
            $Bad = @($Classified | Where-Object { $_.Hides -and ($_.Scope -eq 'Sender' -or $_.Scope -eq 'All') })
            foreach ($C in ($Classified | Where-Object { $_.Hides -and $_.Scope -eq 'Content' })) { $Findings.Add("'$($C.Name)' $($C.Effects -join '; ') when subject/body/header conditions match.") }
            foreach ($C in ($Classified | Where-Object { $_.InError })) { $Findings.Add("'$($C.Name)' is in error (Outlook can no longer run it).") }
            if ($Data.HiddenIncluded -eq $true) { $Findings.Add('Hidden rules were included (Get-InboxRule -IncludeHidden).') }
            if ($Bad.Count -gt 0) {
                $Status = 'Problem'
                $Summary = "$($Bad.Count) inbox rule(s) would take this mail out of the Inbox: " + (($Bad | ForEach-Object { "'$($_.Name)' ($(if ($_.Scope -eq 'All') { 'every message' } else { 'this sender' })) $($_.Effects -join '; ')" }) -join ' | ') + '. A rule nobody recognises can be a sign of a compromised account.'
            } else {
                $Summary = "$($Rules.Count) enabled inbox rule(s) (hidden rules included); none moves, deletes or redirects mail" + $(if ($Sender) { ' from this sender' } else { ' for every message' }) + '.'
            }
        }
        'Restrictions' {
            $M = $Data.Recipient
            if (-not $M) { $Status = 'Unknown'; $Summary = 'The recipient object could not be read.'; break }
            $AcceptOnly = @(@($M.AcceptMessagesOnlyFrom) + @($M.AcceptMessagesOnlyFromDLMembers) + @($M.AcceptMessagesOnlyFromSendersOrMembers) | Where-Object { $_ } | Sort-Object -Unique)
            $Reject = @(@($M.RejectMessagesFrom) + @($M.RejectMessagesFromDLMembers) + @($M.RejectMessagesFromSendersOrMembers) | Where-Object { $_ } | Sort-Object -Unique)
            $Problems = [System.Collections.Generic.List[string]]::new()
            if ($AcceptOnly.Count -gt 0) {
                $Listed = $Sender -and ($AcceptOnly | Where-Object { & $NamesSender $_ })
                if (-not $Listed) { $Problems.Add("only accepts mail from: $($AcceptOnly -join ', ')" + $(if ($Sender) { " - $Sender is not listed by address (it may still be a member of a listed group)" } else { '' })) }
            }
            if ($Reject.Count -gt 0) {
                if ($Sender -and ($Reject | Where-Object { & $NamesSender $_ })) { $Problems.Add("rejects mail from $Sender (RejectMessagesFrom)") } else { $Findings.Add("Rejects mail from: $($Reject -join ', ')") }
            }
            if ($M.RequireSenderAuthenticationEnabled -eq $true) {
                if ($Sender -and -not $SenderIsInternal) { $Problems.Add('only accepts mail from authenticated (internal) senders, so external mail is rejected') } else { $Findings.Add('Only accepts mail from internal senders (RequireSenderAuthenticationEnabled).') }
            }
            if ($M.ForwardingSmtpAddress -or $M.ForwardingAddress) {
                $Target = $M.ForwardingSmtpAddress ?? $M.ForwardingAddress
                if ($M.DeliverToMailboxAndForward -eq $true) { $Findings.Add("Mail is also forwarded to $Target (a copy stays in the mailbox).") } else { $Problems.Add("forwards all mail to $Target and does NOT keep a copy") }
            }
            $MaxReceive = & $ToBytes $M.MaxReceiveSize
            if ($MaxReceive -and $MaxReceive -lt 20MB) { $Findings.Add("MaxReceiveSize is $($M.MaxReceiveSize); larger messages bounce.") }
            if ($M.IsInactiveMailbox -eq $true) { $Problems.Add('is an inactive mailbox') }
            $Evidence = [pscustomobject]@{ RecipientType = $M.RecipientTypeDetails; AcceptMessagesOnlyFrom = $AcceptOnly; RejectMessagesFrom = $Reject; RequireSenderAuthenticationEnabled = $M.RequireSenderAuthenticationEnabled; ForwardingSmtpAddress = $M.ForwardingSmtpAddress; ForwardingAddress = $M.ForwardingAddress; DeliverToMailboxAndForward = $M.DeliverToMailboxAndForward; MaxReceiveSize = $M.MaxReceiveSize }
            if ($Problems.Count -gt 0) { $Status = 'Problem'; $Summary = "The recipient $($Problems -join '; ')." } else { $Summary = 'No sender or delivery restrictions that would block this mail.' }
        }
        'Quota' {
            $M = $Data.Mailbox
            $S = $Data.Stats
            if (-not $M -or -not $S) { $Status = 'Unknown'; $Summary = 'Mailbox size or quota could not be read (not a mailbox, or the statistics call failed).'; break }
            $Used = & $ToBytes $S.TotalItemSize
            $Full = & $ToBytes $M.ProhibitSendReceiveQuota
            $Warn = & $ToBytes $M.IssueWarningQuota
            $Pct = if ($Used -and $Full) { [math]::Round(100 * $Used / $Full, 1) } else { $null }
            $Evidence = [pscustomobject]@{ TotalItemSize = $S.TotalItemSize; ItemCount = $S.ItemCount; DeletedItemSize = $S.TotalDeletedItemSize; ProhibitSendReceiveQuota = $M.ProhibitSendReceiveQuota; IssueWarningQuota = $M.IssueWarningQuota; PercentOfReceiveQuota = $Pct; StorageLimitStatus = $S.StorageLimitStatus; ArchiveStatus = $M.ArchiveStatus; AutoExpandingArchive = $M.AutoExpandingArchiveEnabled; ArchiveSize = $Data.ArchiveStats.TotalItemSize; ArchiveQuota = $M.ArchiveQuota }
            if ($null -ne $Pct -and $Pct -ge 100) {
                $Status = 'Problem'; $Summary = "The mailbox is full ($($S.TotalItemSize) of $($M.ProhibitSendReceiveQuota)). New mail bounces with NDR 5.2.2 until space is freed or the archive is used."
            } elseif ($null -ne $Pct -and $Pct -ge 95) {
                $Status = 'Problem'; $Summary = "The mailbox is nearly full ($Pct% of $($M.ProhibitSendReceiveQuota)); it will start rejecting mail soon."
            } else {
                $Summary = if ($null -ne $Pct) { "Mailbox is at $Pct% of its receive quota ($($S.TotalItemSize) of $($M.ProhibitSendReceiveQuota))." } else { "Mailbox size $($S.TotalItemSize); receive quota $($M.ProhibitSendReceiveQuota)." }
                if ($Warn -and $Used -and $Used -ge $Warn) { $Findings.Add('Past the warning quota; the user is getting quota warnings.') }
            }
            if ($M.ArchiveStatus -ne 'Active') { $Findings.Add('No online archive is enabled.') }
            $ArchUsed = & $ToBytes $Data.ArchiveStats.TotalItemSize
            $ArchQuota = & $ToBytes $M.ArchiveQuota
            if ($ArchUsed -and $ArchQuota -and $ArchUsed -ge 0.9 * $ArchQuota -and $M.AutoExpandingArchiveEnabled -ne $true) { $Findings.Add("The archive is over 90% of its quota ($($Data.ArchiveStats.TotalItemSize) of $($M.ArchiveQuota)) and auto-expanding archive is off.") }
        }
        'SenderBlocks' {
            $Entries = @($Data.TablSender | Where-Object { $_ })
            $Junk = $Data.Junk
            $Problems = [System.Collections.Generic.List[string]]::new()
            $Matched = [System.Collections.Generic.List[object]]::new()
            if ($Sender) {
                foreach ($E in $Entries) {
                    $V = ([string]$E.Value).ToLowerInvariant()
                    $Hit = $V -eq $Sender -or $V -eq $SenderDomain -or ($V.StartsWith('*.') -and $SenderDomain.EndsWith($V.Substring(1)))
                    if ($Hit) {
                        $Matched.Add([pscustomobject]@{ List = 'Tenant Allow/Block List'; Value = $E.Value; Action = $E.Action; Notes = $E.Notes; Expires = (& $Time $E.ExpirationDate) })
                        if ($E.Action -eq 'Block') { $Problems.Add("the Tenant Allow/Block List blocks '$($E.Value)' - mail from it is quarantined as high confidence phishing (and users cannot send to it)") } else { $Findings.Add("Tenant Allow/Block List allows '$($E.Value)' (block entries still win).") }
                    }
                }
                if ($Junk) {
                    $Blocked = @($Junk.BlockedSendersAndDomains | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
                    $Trusted = @($Junk.TrustedSendersAndDomains | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
                    $B = @($Blocked | Where-Object { $_ -eq $Sender -or $_ -eq $SenderDomain -or $_ -eq "@$SenderDomain" })
                    if ($B.Count) { $Problems.Add("the user has blocked '$($B -join ', ')' in Outlook, so it goes to the Junk Email folder"); $Matched.Add([pscustomobject]@{ List = 'User Blocked Senders'; Value = ($B -join ', '); Action = 'Junk' }) }
                    $T = @($Trusted | Where-Object { $_ -eq $Sender -or $_ -eq $SenderDomain -or $_ -eq "@$SenderDomain" })
                    if ($T.Count) { $Findings.Add("The user trusts '$($T -join ', ')' (Safe Senders).") }
                    if ($Junk.TrustedListsOnly -eq $true -and $T.Count -eq 0) { $Problems.Add('the user only accepts mail from Safe Senders (TrustedListsOnly), so this sender goes to Junk') }
                }
            } elseif ($Junk -and $Junk.TrustedListsOnly -eq $true) {
                $Problems.Add('the user only accepts mail from Safe Senders (TrustedListsOnly); everything else goes to the Junk Email folder')
            }
            if ($Junk -and $Junk.Enabled -eq $false) { $Findings.Add('The junk email rule is turned off for this mailbox.') }
            $Evidence = [pscustomobject]@{ TenantSenderBlocks = @($Entries | Where-Object { $_.Action -eq 'Block' }).Count; UserBlockedSenders = @($Junk.BlockedSendersAndDomains | Where-Object { $_ }).Count; UserSafeSenders = @($Junk.TrustedSendersAndDomains | Where-Object { $_ }).Count; TrustedListsOnly = $Junk.TrustedListsOnly; Matches = @($Matched) }
            if ($Problems.Count -gt 0) { $Status = 'Problem'; $Summary = "For this sender, $($Problems -join '; ')." }
            elseif ($Sender) { $Summary = "No Tenant Allow/Block List or user Blocked Senders entry matches $Sender." }
            else { $Summary = 'No sender given, so no block entry could be matched; the user does not restrict mail to Safe Senders only.' }
            if (-not $Junk) { $Findings.Add('The user junk email settings could not be read.') }
        }
        'SignIn' {
            $U = $Data.User
            if (-not $U) { $Status = 'Unknown'; $Summary = 'The user account could not be read from Entra ID (it may be a shared mailbox or group).'; break }
            $SignIns = @($Data.SignIns | Where-Object { $_ })
            $Failures = @($SignIns | Where-Object { $_.status.errorCode -and $_.status.errorCode -ne 0 })
            $Last = $U.signInActivity.lastSuccessfulSignInDateTime ?? $U.signInActivity.lastSignInDateTime
            $Evidence = [pscustomobject]@{ AccountEnabled = $U.accountEnabled; LastSuccessfulSignIn = (& $Time $Last); RecentSignIns = @($SignIns | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ When = (& $Time $_.createdDateTime); App = $_.appDisplayName; Result = $(if ($_.status.errorCode -and $_.status.errorCode -ne 0) { "Failed $($_.status.errorCode): $($_.status.failureReason)" } else { 'Success' }); Client = $_.clientAppUsed; Location = "$($_.location.city) $($_.location.countryOrRegion)".Trim() } }) }
            if ($U.accountEnabled -eq $false) {
                $Status = 'Problem'; $Summary = 'The account is disabled: mail is still delivered to the mailbox, but the user cannot sign in to read it.'
            } elseif ($SignIns.Count -ge 3 -and $Failures.Count -eq $SignIns.Count) {
                $Status = 'Problem'; $Summary = "The last $($SignIns.Count) sign-ins all failed (latest: $($Failures[0].status.failureReason)). The user may not be able to open their mailbox to see new mail."
            } else {
                $Summary = 'The account is enabled' + $(if ($Last) { "; last successful sign-in $(& $Time $Last)" } else { '' }) + $(if ($Failures.Count) { "; $($Failures.Count) of the last $($SignIns.Count) sign-ins failed" } else { '' }) + '.'
                if ($Last) {
                    $LastUtc = [DateTime]::Parse((ConvertTo-CIPPCentralTime -Value $Last).Utc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                    if (([DateTime]::UtcNow - $LastUtc).TotalDays -gt 14) { $Findings.Add('No successful sign-in for over 14 days - is the user looking at the right mailbox or device?') }
                }
            }
            if ($Data.SignInError) { $Findings.Add("Sign-in log not available: $($Data.SignInError)") }
        }
    }

    [pscustomobject]@{
        Status   = $Status
        Summary  = $Summary
        Findings = @($Findings)
        Evidence = $Evidence
    }
}
