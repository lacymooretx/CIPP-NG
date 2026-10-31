function Invoke-CIPPGDAPHealthCheck {
    <#
    .SYNOPSIS
        Daily GDAP relationship, partner token and SAM credential health check.
    .DESCRIPTION
        Reads every GDAP relationship and its access assignments, probes Graph in each managed tenant,
        checks the CIPP-SAM token and credential, and evaluates them with Get-CIPPGDAPHealthFindings.
        Only new findings (and still-open "access is broken" findings every RealertDays) are sent, as one
        consolidated email/PSA/webhook alert. State and the latest report are kept in table GDAPHealthState.
        -SkipAlerts evaluates and returns the report without sending or touching state.
        -Resend sends every open Error/Warning finding now, whether or not it was alerted before.
        Aspendora fork addition (Vikunja CIPP-2).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipAlerts,
        # Send every open Error/Warning finding now, even ones already alerted.
        [switch]$Resend,
        [int]$RealertDays = 7,
        $APIName = 'GDAP Health'
    )

    $Now = (Get-Date).ToUniversalTime()
    $PartnerTenantId = $env:TenantID
    $CollectionErrors = [System.Collections.Generic.List[string]]::new()
    $Table = Get-CIPPTable -tablename 'GDAPHealthState'

    # Previous snapshot, used for the "was active, now isn't" and "assignment removed" rules.
    $Previous = $null
    $SnapshotRow = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Snapshot' and RowKey eq 'Latest'"
    if ($SnapshotRow.Data) {
        try {
            $Parsed = $SnapshotRow.Data | ConvertFrom-Json -AsHashtable
            $Previous = @{ ActiveRelationshipIds = @($Parsed.ActiveRelationshipIds); AssignmentIds = @{} }
            foreach ($Key in @($Parsed.AssignmentIds.Keys)) { $Previous.AssignmentIds[$Key] = @($Parsed.AssignmentIds[$Key]) }
        } catch { Write-Warning "GDAP health: could not read the previous snapshot: $($_.Exception.Message)" }
    }

    # 1. Relationships. If this fails, nothing else is trustworthy, so the snapshot is not overwritten.
    $Relationships = $null
    $RelationshipError = $null
    try {
        $Relationships = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/tenantRelationships/delegatedAdminRelationships' -tenantid $PartnerTenantId -NoAuthCheck $true -ErrorAction Stop)
    } catch {
        $RelationshipError = (Get-CippException -Exception $_).NormalizedError
        $CollectionErrors.Add("Listing GDAP relationships failed: $RelationshipError")
    }

    # 2. Access assignments for every active relationship. A failed read leaves that relationship out,
    #    so it can never be reported as "assignment removed".
    $AccessAssignments = @{}
    $ActiveRelationships = @($Relationships | Where-Object { $_.status -eq 'active' })
    if ($ActiveRelationships.Count -gt 0) {
        $Requests = @($ActiveRelationships | ForEach-Object {
                @{ id = [string]$_.id; method = 'GET'; url = "tenantRelationships/delegatedAdminRelationships/$($_.id)/accessAssignments" }
            })
        try {
            $Responses = New-GraphBulkRequest -tenantid $PartnerTenantId -NoAuthCheck $true -Requests $Requests
            foreach ($Response in @($Responses)) {
                if ([int]$Response.status -eq 200) {
                    $AccessAssignments[[string]$Response.id] = @($Response.body.value | Where-Object { $_.status -eq 'active' })
                } else {
                    $CollectionErrors.Add("Access assignments for relationship $($Response.id): HTTP $($Response.status)")
                }
            }
        } catch {
            $CollectionErrors.Add("Reading access assignments failed: $((Get-CippException -Exception $_).NormalizedError)")
        }
    }

    # 3. Graph probe per managed tenant.
    $Tenants = @(Get-Tenants)
    $TenantProbeErrors = @{}
    foreach ($Tenant in $Tenants) {
        if ($Tenant.delegatedPrivilegeStatus -eq 'directTenant' -or $Tenant.customerId -eq $PartnerTenantId) { continue }
        try {
            $null = New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/organization?$select=id' -tenantid $Tenant.customerId -ErrorAction Stop
        } catch {
            $TenantProbeErrors[[string]$Tenant.customerId] = (Get-CippException -Exception $_).NormalizedError
        }
    }

    # 4. CIPP-SAM: can it still get a token, and when does the credential it uses expire?
    $SamStatus = @{ Ready = $true; Message = '' }
    if ($RelationshipError) {
        $SamStatus = @{ Ready = $false; Message = $RelationshipError }
    } elseif (-not $env:CertificateAuthMode) {
        try {
            $null = Get-CIPPAuthentication
            $Probe = Test-CIPPSAMSecret -IncludeRefreshGrant
            if (-not $Probe.ready -and $Probe.reason -ne 'propagating') { $SamStatus = @{ Ready = $false; Message = $Probe.message } }
        } catch {
            $CollectionErrors.Add("SAM token probe failed to run: $($_.Exception.Message)")
        }
    }
    try {
        $Sam = Get-CIPPSAMCredentials
        $Own = if ($env:CertificateAuthMode) {
            $Sam.Credentials | Where-Object { $_.type -eq 'Certificate' -and $Sam.OwnThumbprint -and $_.thumbprint -eq $Sam.OwnThumbprint } | Select-Object -First 1
        } else {
            ($Sam.Credentials | Where-Object { $_.type -eq 'Secret' -and $_.keyId -eq $Sam.OwnSecretKeyId } | Select-Object -First 1) ??
            ($Sam.Credentials | Where-Object { $_.type -eq 'Secret' } | Sort-Object endDateTime -Descending | Select-Object -First 1)
        }
        if ($Own) {
            $SamStatus.CredentialType = $Own.type
            $SamStatus.CredentialExpires = $Own.endDateTime
        }
    } catch {
        $CollectionErrors.Add("Reading CIPP-SAM credentials failed: $($_.Exception.Message)")
    }

    # Customers an operator chose to ignore (ExecGDAPHealthIgnore).
    $Ignored = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Ignore'")
    $IgnoredIds = @($Ignored | ForEach-Object { [string]$_.RowKey })

    $FindingParams = @{
        Relationships     = @($Relationships)
        AccessAssignments = $AccessAssignments
        Tenants           = $Tenants
        TenantProbeErrors = $TenantProbeErrors
        SamStatus         = $SamStatus
        Previous          = if ($Relationships) { $Previous } else { $null }
        PartnerTenantId   = $PartnerTenantId
        Now               = $Now
        IgnoredCustomers  = $IgnoredIds
    }
    if ($RelationshipError) { $FindingParams.RelationshipsUnavailable = $true }
    $Findings = @(Get-CIPPGDAPHealthFindings @FindingParams)

    $Summary = [ordered]@{
        Relationships       = @($Relationships).Count
        ActiveRelationships = $ActiveRelationships.Count
        ManagedTenants      = @($Tenants | Where-Object { $_.delegatedPrivilegeStatus -ne 'directTenant' -and $_.customerId -ne $PartnerTenantId }).Count
        Errors              = @($Findings | Where-Object Severity -EQ 'Error').Count
        Warnings            = @($Findings | Where-Object Severity -EQ 'Warning').Count
        Info                = @($Findings | Where-Object Severity -EQ 'Info').Count
    }
    $Report = [ordered]@{
        GeneratedUtc     = $Now.ToString('o')
        Summary          = $Summary
        Findings         = $Findings
        CollectionErrors = @($CollectionErrors)
        Ignored          = @($Ignored | ForEach-Object { [pscustomobject]@{ TenantId = $_.RowKey; Name = $_.Name; Reason = $_.Reason; IgnoredBy = $_.IgnoredBy; IgnoredUtc = $_.IgnoredUtc } })
        Alerted          = @()
    }
    if ($SkipAlerts) { return [pscustomobject]$Report }

    # Decide what to alert on: new keys, plus re-alert keys that are still broken after RealertDays.
    $StateRows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Finding'")
    $StateByKey = @{}
    foreach ($Row in $StateRows) { $StateByKey[[string]$Row.FindingKey] = $Row }
    $ToAlert = [System.Collections.Generic.List[object]]::new()
    foreach ($Finding in $Findings) {
        if ($Finding.Severity -eq 'Info') { continue }
        $Row = $StateByKey[$Finding.Key]
        # Never alerted (new, or every channel failed last time) means due.
        $Due = $Resend -or -not $Row -or -not $Row.LastAlerted
        if (-not $Due -and $Finding.Realert) {
            try { $Due = ([datetimeoffset]$Row.LastAlerted).UtcDateTime -lt $Now.AddDays(-$RealertDays) } catch { $Due = $true }
        }
        if ($Due) { $ToAlert.Add($Finding) }
    }

    # A collection failure is itself worth knowing about, but only once a day at most (the timer is daily).
    $AlertSent = $false
    if ($ToAlert.Count -gt 0 -or ($CollectionErrors.Count -gt 0 -and $RelationshipError)) {
        $Title = if ($ToAlert.Count -gt 0) {
            "GDAP health: $($ToAlert.Count) $(if ($Resend) { 'open' } else { 'new' }) issue(s), $(@($ToAlert | Where-Object Severity -EQ 'Error').Count) error(s)"
        } else { 'GDAP health check could not list GDAP relationships' }
        $Rows = @($ToAlert | Select-Object Severity, Tenant, Category, Relationship, @{ n = 'Ends'; e = { if ($_.EndDateTime) { ([datetimeoffset]$_.EndDateTime).UtcDateTime.ToString('yyyy-MM-dd') } } }, Message)
        $Intro = "<p>The daily GDAP and token health check found $($ToAlert.Count) $(if ($Resend) { 'open' } else { 'new' }) issue(s). Open issues total: $($Summary.Errors) error(s), $($Summary.Warnings) warning(s). The full report is at /api/ListGDAPHealth.</p>"
        $ErrorsHtml = if ($CollectionErrors.Count -gt 0) { "<p><b>Collection problems:</b></p><ul>$(($CollectionErrors | ForEach-Object { "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>" }) -join '')</ul>" } else { '' }
        $Html = "$Intro$(if ($Rows) { $Rows | ConvertTo-Html -Fragment | Out-String })$ErrorsHtml"
        $Json = ConvertTo-Json -InputObject ([pscustomobject]@{ title = $Title; summary = $Summary; findings = @($ToAlert); collectionErrors = @($CollectionErrors) }) -Depth 6 -Compress
        # The PSA extensions resolve the ticket's company by the tenant's default domain, so a tenant id
        # never matches a mapping. Send as the partner tenant's domain (map it under Extensions > ConnectWise).
        $AlertTenant = (@(Get-Tenants -IncludeAll) | Where-Object { $_.customerId -eq $PartnerTenantId } | Select-Object -First 1).defaultDomainName
        if (-not $AlertTenant) { $AlertTenant = $PartnerTenantId }
        foreach ($Channel in 'email', 'psa', 'webhook') {
            try {
                if ($Channel -eq 'webhook') {
                    $null = Send-CIPPAlert -Type $Channel -Title $Title -JSONContent $Json -TenantFilter $AlertTenant -APIName $APIName
                } else {
                    $null = Send-CIPPAlert -Type $Channel -Title $Title -HTMLContent $Html -TenantFilter $AlertTenant -APIName $APIName -PSAConsolidationKey 'GDAPHealth'
                }
                $AlertSent = $true
            } catch {
                Write-LogMessage -API $APIName -tenant 'Global' -message "Could not send $Channel alert for '$Title': $($_.Exception.Message)" -Sev 'Warning'
            }
        }
        # Info on purpose: Alert/Error log entries are forwarded to the PSA by the notification config,
        # which would duplicate the ticket this alert just raised.
        Write-LogMessage -API $APIName -tenant 'Global' -message "$Title. $(($ToAlert | ForEach-Object { "[$($_.Severity)] $($_.Message)" }) -join ' | ')" -Sev 'Info'
    }

    # Persist finding state: keep open findings, drop resolved ones so a recurrence alerts again.
    $AlertedKeys = @($ToAlert | ForEach-Object Key)
    $OpenKeys = @{}
    foreach ($Finding in $Findings) {
        $OpenKeys[$Finding.Key] = $true
        $Row = $StateByKey[$Finding.Key]
        $RowKey = ($Finding.Key -replace '[\\/#?\t\n\r]', '_')
        $Entity = @{
            PartitionKey = 'Finding'
            RowKey       = $RowKey
            FindingKey   = [string]$Finding.Key
            Severity     = [string]$Finding.Severity
            Message      = [string]$Finding.Message
            FirstSeen    = [string]($Row.FirstSeen ?? $Now.ToString('o'))
            LastSeen     = $Now.ToString('o')
            LastAlerted  = [string]$(if ($AlertSent -and $Finding.Key -in $AlertedKeys) { $Now.ToString('o') } else { $Row.LastAlerted ?? '' })
        }
        Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force
    }
    # Only clear resolved rows when the relationship list was read; otherwise "resolved" just means "not seen".
    if (-not $RelationshipError) {
        $Resolved = @($StateRows | Where-Object { -not $OpenKeys.ContainsKey([string]$_.FindingKey) })
        if ($Resolved.Count -gt 0) { Remove-AzDataTableEntity @Table -Entity $Resolved -Force }
    }

    # New snapshot. Assignments that could not be read this run keep their previous ids.
    if (-not $RelationshipError) {
        $AssignmentIds = @{}
        foreach ($Relationship in $ActiveRelationships) {
            $Id = [string]$Relationship.id
            if ($AccessAssignments.ContainsKey($Id)) { $AssignmentIds[$Id] = @($AccessAssignments[$Id] | ForEach-Object { [string]$_.id }) }
            elseif ($Previous -and $Previous.AssignmentIds.ContainsKey($Id)) { $AssignmentIds[$Id] = @($Previous.AssignmentIds[$Id]) }
        }
        $Snapshot = @{ ActiveRelationshipIds = @($ActiveRelationships | ForEach-Object { [string]$_.id }); AssignmentIds = $AssignmentIds }
        Add-CIPPAzDataTableEntity @Table -Entity @{ PartitionKey = 'Snapshot'; RowKey = 'Latest'; Data = [string](ConvertTo-Json -InputObject $Snapshot -Depth 5 -Compress) } -Force
    }

    $Report.Alerted = $AlertedKeys
    Add-CIPPAzDataTableEntity @Table -Entity @{ PartitionKey = 'Report'; RowKey = 'Latest'; Data = [string](ConvertTo-Json -InputObject $Report -Depth 6 -Compress) } -Force
    return [pscustomobject]$Report
}
