function New-CippExtAlert {
    [CmdletBinding()]
    param (
        [switch]$TestRun = $false,
        [pscustomobject]$Alert
    )
    #Get the current CIPP Alerts table and see what system is configured to receive alerts
    $Table = Get-CIPPTable -TableName Extensionsconfig
    $Configuration = (Get-CIPPAzDataTableEntity @Table).config | ConvertFrom-Json -Depth 10 -ErrorAction SilentlyContinue
    $MappingTable = Get-CIPPTable -TableName CippMapping

    foreach ($ConfigItem in $Configuration.psobject.properties.name) {
        switch ($ConfigItem) {
            'HaloPSA' {
                if ($Configuration.HaloPSA.enabled) {
                    $MappingFile = Get-CIPPAzDataTableEntity @MappingTable -Filter "PartitionKey eq 'HaloMapping'"
                    $TenantId = (Get-Tenants -TenantFilter $Alert.TenantId).customerId
                    $MappedId = ($MappingFile | Where-Object { $_.RowKey -eq $TenantId }).IntegrationId
                    if (!$MappedId) {
                        # Unmapped tenants land on client 1; say so instead of doing it silently.
                        $MappedId = 1
                        Write-LogMessage -API 'HaloPSATicket' -tenant $Alert.TenantId -message "No HaloPSA client mapping for tenant $($Alert.TenantId) - the ticket was raised against Halo client id 1. Map the tenant under Settings > Integrations > HaloPSA." -sev Warning
                    }
                    Write-Information "HaloPSA client for tenant $($Alert.TenantId): $MappedId"

                    $TicketParams = @{
                        Title       = $Alert.AlertTitle
                        Description = $Alert.AlertText
                        Client      = $MappedId
                    }

                    # A task can name the ticket the work came from, so the PSA copy lands as a note
                    # on that ticket instead of opening a second one. Two sources, in order:
                    #
                    #   PsaTicketId  - the ticket box on the user/offboarding/scheduler forms, shown
                    #                  only when this integration is enabled. Unambiguous, so it wins.
                    #   Reference    - free text, and only an [ID:nnnn] token in it counts. That is
                    #                  HaloPSA's own subject token, which is also what makes the
                    #                  emailed copy thread onto the same ticket. A bare number is
                    #                  deliberately NOT accepted: the reference legitimately holds
                    #                  order numbers, asset tags and change ids, and treating one as
                    #                  a ticket id would append a starter's password to an unrelated
                    #                  ticket.
                    #
                    # Reading both is this extension's job: the formats are Halo's, and the scheduler
                    # passes the values through untouched.
                    $ReferencedTicketId = 0
                    $TicketCandidate = if ($Alert.PsaTicketId) {
                        "$($Alert.PsaTicketId)".Trim()
                    } elseif ("$($Alert.Reference)" -match '\[ID:(\d+)\]') {
                        $Matches[1]
                    } else {
                        $null
                    }
                    if ($TicketCandidate) {
                        # TryParse rather than a cast: a long run of digits is a valid match but an
                        # invalid ticket id, and an overflow here would cost the alert entirely.
                        $ParsedTicketId = 0
                        if ([int]::TryParse($TicketCandidate, [ref]$ParsedTicketId) -and $ParsedTicketId -gt 0) {
                            $ReferencedTicketId = $ParsedTicketId
                            $TicketParams.TicketId = $ReferencedTicketId
                            Write-Information "Alert targets HaloPSA ticket $ReferencedTicketId - adding a note to it instead of creating a ticket"
                            # Setting both and disagreeing is easy to do by accident, and the effect is
                            # confusing: the reference is what the notification title shows, so the note
                            # lands on a ticket the title never mentions and it looks like nothing
                            # happened. Say where it actually went.
                            if ($Alert.PsaTicketId -and "$($Alert.Reference)" -match '\[ID:(\d+)\]' -and $Matches[1] -ne "$ReferencedTicketId") {
                                Write-LogMessage -API 'HaloPSATicket' -tenant $Alert.TenantId -message "Task targets HaloPSA ticket $ReferencedTicketId from its ticket field, but its reference names ticket $($Matches[1]). The note was added to $ReferencedTicketId." -sev Warning
                            }
                        } else {
                            Write-LogMessage -API 'HaloPSATicket' -tenant $Alert.TenantId -message "'$TicketCandidate' is not a usable HaloPSA ticket id - raising a new ticket instead." -sev Warning
                        }
                    }

                    # A referenced ticket already carries its own end user, so skip the contact lookup
                    # (and the Graph call under it) entirely.
                    if ($ReferencedTicketId -le 0 -and $Alert.AffectedUser -and $Configuration.HaloPSA.LinkTicketsToUsers) {
                        $UPN = $Alert.AffectedUser.UPN
                        $OID = $Alert.AffectedUser.AzureOID
                        $Display = $Alert.AffectedUser.DisplayName

                        # Best-effort: resolve UPN -> Azure Object ID via Graph if we don't already have it.
                        # Failure here is non-fatal; Get-HaloUser will still try the email-based lookup.
                        if (-not $OID -and $UPN -and $Alert.TenantId) {
                            try {
                                $EncodedUPN = [System.Uri]::EscapeDataString($UPN)
                                $GraphUser = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$EncodedUPN`?`$select=id,displayName,userPrincipalName" -tenantid $Alert.TenantId -AsApp $true
                                if ($GraphUser.id) { $OID = $GraphUser.id }
                                if (-not $Display -and $GraphUser.displayName) { $Display = $GraphUser.displayName }
                            } catch {
                                Write-Information "Could not resolve Graph user for $UPN in tenant $($Alert.TenantId): $($_.Exception.Message)"
                            }
                        }

                        if ($UPN) { $TicketParams.UserUPN = $UPN }
                        if ($OID) { $TicketParams.AzureOID = $OID }
                        if ($Display) { $TicketParams.DisplayName = $Display }
                    }

                    # Per-alert priority beats the integration-wide DefaultPriority. Unlike the
                    # user fields above this is NOT gated on LinkTicketsToUsers - priority applies
                    # to every ticket, and it must also work when no global default is configured.
                    if ($Alert.PsaTicketPriority) {
                        $TicketParams.TicketPriority = $Alert.PsaTicketPriority
                    }

                    # HaloPSA may use a stable consolidation key independently
                    # from the visible ticket title.
                    if ($Alert.PSAConsolidationKey) {
                        $TicketParams.ConsolidationKey = $Alert.PSAConsolidationKey
                    }

                    New-HaloPSATicket @TicketParams
                }
            }
            'Syncro' {
                if ($Configuration.Syncro.enabled) {
                    # First step of the Syncro PSA integration: one new ticket per alert with the
                    # right priority. The ticket reference, affected-user and consolidation
                    # fields on the alert are HaloPSA features and are not read here yet.
                    $MappingFile = Get-CIPPAzDataTableEntity @MappingTable -Filter "PartitionKey eq 'SyncroMapping'"
                    $TenantId = (Get-Tenants -TenantFilter $Alert.TenantId).customerId
                    $MappedId = ($MappingFile | Where-Object { $_.RowKey -eq $TenantId }).IntegrationId
                    if (!$MappedId) {
                        # Syncro has no safe default customer, so an unmapped tenant is a failure
                        # the pipeline reports rather than a ticket on the wrong customer.
                        $Message = "No Syncro customer mapping for tenant $($Alert.TenantId) - no ticket was raised. Map the tenant under Settings > Integrations > Syncro."
                        Write-LogMessage -API 'SyncroTicket' -tenant $Alert.TenantId -message $Message -sev Error
                        "Failed to send ticket to Syncro: $Message"
                    } else {
                        Write-Information "Syncro customer for tenant $($Alert.TenantId): $MappedId"
                        $SyncroParams = @{
                            Title       = $Alert.AlertTitle
                            Description = $Alert.AlertText
                            Client      = $MappedId
                        }
                        # Per-alert priority beats the integration-wide DefaultPriority. A value
                        # that is not a Syncro priority (a HaloPSA id, when both are enabled) is
                        # skipped inside New-SyncroPSATicket, so passing it through is safe.
                        if ($Alert.PsaTicketPriority) {
                            $SyncroParams.TicketPriority = $Alert.PsaTicketPriority
                        }
                        New-SyncroPSATicket @SyncroParams
                    }
                }
            }
            'NinjaOne' {
                if ($Configuration.NinjaOne.Enabled -and $Configuration.NinjaOne.TicketingEnabled) {
                    $TenantId = (Get-Tenants -TenantFilter $Alert.TenantId).customerId
                    $Mapping = Get-CIPPAzDataTableEntity @MappingTable -Filter "PartitionKey eq 'NinjaOneMapping' and RowKey eq '$TenantId'"
                    if ($Mapping.IntegrationId) {
                        # PsaTicketId and Reference are HaloPSA ticket ids, so they are not passed on.
                        $TicketParams = @{
                            Title          = $Alert.AlertTitle
                            Description    = $Alert.AlertText
                            Client         = $Mapping.IntegrationId
                            TicketPriority = $Alert.PsaTicketPriority
                        }
                        if ($Alert.PSAConsolidationKey) { $TicketParams.ConsolidationKey = $Alert.PSAConsolidationKey }
                        if ($Alert.AffectedUser -and $Configuration.NinjaOne.LinkTicketsToUsers) {
                            $UPN = $Alert.AffectedUser.UPN
                            $Display = $Alert.AffectedUser.DisplayName
                            # NinjaOne matches on email only, so an alert that carries just the object id
                            # needs the UPN from Graph first. Best effort: a miss just skips the link.
                            if (-not $UPN -and $Alert.AffectedUser.AzureOID) {
                                try {
                                    $GraphUser = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($Alert.AffectedUser.AzureOID)?`$select=userPrincipalName,displayName" -tenantid $Alert.TenantId -AsApp $true
                                    $UPN = $GraphUser.userPrincipalName
                                    if (-not $Display) { $Display = $GraphUser.displayName }
                                } catch {
                                    Write-Information "Could not resolve Graph user $($Alert.AffectedUser.AzureOID) in tenant $($Alert.TenantId): $($_.Exception.Message)"
                                }
                            }
                            if ($UPN) { $TicketParams.UserUPN = $UPN }
                            if ($Display) { $TicketParams.DisplayName = $Display }
                        }
                        if ($Alert.AffectedDevice) {
                            $TicketParams.AffectedDevice = $Alert.AffectedDevice
                            $TicketParams.TenantCustomerId = $TenantId
                        }
                        New-NinjaOneTicket @TicketParams
                    } else {
                        Write-LogMessage -API 'NinjaOneTicket' -tenant $Alert.TenantId -message "No NinjaOne organisation mapping for tenant $($Alert.TenantId) - no NinjaOne ticket was raised. Map the tenant under Settings > Integrations > NinjaOne." -sev Warning
                        "Skipped NinjaOne ticket: tenant $($Alert.TenantId) is not mapped to a NinjaOne organisation"
                    }
                }
            }
            'Gradient' {
                if ($Configuration.Gradient.enabled) {
                    New-GradientAlert -Title $Alert.AlertTitle -Description $Alert.AlertText -Client $Alert.TenantId
                }
            }
            'ConnectWise' {
                if ($Configuration.ConnectWise.enabled) {
                    $MappingFile = Get-CIPPAzDataTableEntity @MappingTable -Filter "PartitionKey eq 'ConnectWiseMapping'"
                    $TenantId = (Get-Tenants | Where-Object defaultDomainName -EQ $Alert.TenantId).customerId
                    Write-Host "TenantId: $TenantId"
                    $MappedId = ($MappingFile | Where-Object { $_.RowKey -eq $TenantId }).IntegrationId
                    Write-Host "MappedId: $MappedId"
                    if ($MappedId) {
                        # Our own change naming its ticket (Get-CIPPAuditTicketReference) becomes an internal note
                        # there. These are security alerts, so anything short of a posted note opens a ticket:
                        # a closed, missing or other client's ticket, or any error reaching ConnectWise.
                        $NotePosted = $false
                        if ($Alert.ConnectWiseNoteTicketId) {
                            try {
                                $CompanyId = [int]($MappedId | Select-Object -Last 1)
                                if ($CompanyId -le 0) { throw "'$MappedId' is not a usable ConnectWise company id" }
                                $NoteText = "$($Alert.AlertTitle)`n`nFiled here instead of opening a new ticket: the change was made by one of our identities and its name or comment names this ticket. If this change was not expected, treat it as a security incident.`n`n$(ConvertFrom-CIPPHtmlToText -Html $Alert.AlertText)"
                                $Note = Add-ConnectWiseTicketNote -TicketId ([int]$Alert.ConnectWiseNoteTicketId) -Text $NoteText -ExpectedCompanyId $CompanyId -RequireOpen -Configuration $Configuration.ConnectWise
                                if ($Note.Success) {
                                    $NotePosted = $true
                                    $Note.Message
                                } else {
                                    Write-LogMessage -API 'Alerts' -tenant $Alert.TenantId -message "ConnectWise: raising a new ticket instead of a note on ticket $($Alert.ConnectWiseNoteTicketId): $($Note.Message)" -sev Warning
                                }
                            } catch {
                                Write-LogMessage -API 'Alerts' -tenant $Alert.TenantId -message "ConnectWise: raising a new ticket instead of a note on ticket $($Alert.ConnectWiseNoteTicketId): $($_.Exception.Message)" -sev Warning
                            }
                        }
                        # A ticket window (role grants, Vikunja MSP-3): the first alert of the hour opens a ticket
                        # and later ones become notes on it, so a burst of grants is one ticket and each grant stays
                        # on record. Anchored on the first ticket, so a long burst still opens one ticket an hour.
                        # Doubt fails toward a ticket: a closed ticket, an unreadable window or any error opens one.
                        $WindowTable = $null
                        $WindowRowKey = $null
                        if (-not $NotePosted -and $Alert.ConnectWiseTicketWindow) {
                            try {
                                $CompanyId = [int]($MappedId | Select-Object -Last 1)
                                if ($CompanyId -le 0) { throw "'$MappedId' is not a usable ConnectWise company id" }
                                $WindowTable = Get-CIPPTable -TableName 'PSATickets'
                                $WindowRowKey = "$CompanyId-$($Alert.ConnectWiseTicketWindow)"
                                $WindowRow = Get-CIPPAzDataTableEntity @WindowTable -Filter "PartitionKey eq 'ConnectWiseAlertWindow' and RowKey eq '$WindowRowKey'" | Select-Object -First 1
                                if ($WindowRow.TicketID -and [datetimeoffset]::Parse([string]$WindowRow.OpenedUtc, [cultureinfo]::InvariantCulture) -gt [datetimeoffset]::UtcNow.AddHours(-1)) {
                                    $NoteText = "$($Alert.AlertTitle)`n`nFiled here instead of opening a new ticket: this ticket was opened for the same kind of change in this tenant within the last hour. If this change was not expected, treat it as a security incident.`n`n$(ConvertFrom-CIPPHtmlToText -Html $Alert.AlertText)"
                                    $Note = Add-ConnectWiseTicketNote -TicketId ([int]$WindowRow.TicketID) -Text $NoteText -ExpectedCompanyId $CompanyId -RequireOpen -Configuration $Configuration.ConnectWise
                                    if ($Note.Success) {
                                        $NotePosted = $true
                                        $Note.Message
                                    } else {
                                        # Someone closing the ticket inside the hour is routine; anything else is worth a look.
                                        $WindowSev = if ("$($Note.Message)" -match 'is closed') { 'Info' } else { 'Warning' }
                                        Write-LogMessage -API 'Alerts' -tenant $Alert.TenantId -message "ConnectWise: raising a new ticket instead of a note on window ticket $($WindowRow.TicketID): $($Note.Message)" -sev $WindowSev
                                    }
                                }
                            } catch {
                                Write-LogMessage -API 'Alerts' -tenant $Alert.TenantId -message "ConnectWise: raising a new ticket because the ticket window could not be used: $($_.Exception.Message)" -sev Warning
                            }
                        }
                        if (-not $NotePosted) {
                            $TicketResult = New-ConnectWiseTicket -Title $Alert.AlertTitle -Description $Alert.AlertText -Client $MappedId
                            if ($WindowRowKey -and "$TicketResult" -match 'Ticket created in ConnectWise: (\d+)') {
                                try {
                                    Add-CIPPAzDataTableEntity @WindowTable -Entity @{ PartitionKey = 'ConnectWiseAlertWindow'; RowKey = $WindowRowKey; TicketID = [string]$Matches[1]; OpenedUtc = [datetimeoffset]::UtcNow.ToString('o') } -Force
                                } catch {
                                    Write-LogMessage -API 'Alerts' -tenant $Alert.TenantId -message "ConnectWise: could not record ticket window $WindowRowKey, so the next alert may open another ticket: $($_.Exception.Message)" -sev Warning
                                }
                            }
                            $TicketResult
                        }
                    } else {
                        Write-LogMessage -API 'Alerts' -tenant $Alert.TenantId -message 'ConnectWise: No mapping found for tenant. Skipping ticket creation.' -sev Warning
                    }
                }
            }
        }
    }

}
