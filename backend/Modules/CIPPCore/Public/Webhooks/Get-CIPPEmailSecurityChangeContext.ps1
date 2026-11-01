function Get-CIPPEmailSecurityChangeContext {
    <#
    .SYNOPSIS
        Builds the alert body for a change to an email security policy, the Tenant Allow/Block List or a transport rule.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-32). Called by New-CIPPAlertTemplate for an audit-log alert whose
        Operation is one of the cmdlets in the email-security map below; returns $null for anything else, so it is
        safe to call for every record.

        The body carries:
          - who did it (the resolved UPN, the raw actor and the CIPPActorClass verdict), the client IP and the cmdlet;
          - every parameter the cmdlet was called with (the audit record holds the new values only);
          - "before" values for those parameters from the tenant's last CIPP DB cache snapshot of the object, when
            the object is in the cache. That snapshot is as old as the last cache refresh, not the instant before the
            change, and the alert says so;
          - one "drift: <standard>" line per CIPP standard that manages this kind of object for the tenant, so the
            operator can re-apply it. Nothing is reverted automatically.

        Each lookup is best effort and memoised per record id, because New-CIPPAlertTemplate renders the same alert
        up to three times (json, html, psa).
    .PARAMETER Data
        The shaped audit record (Test-CIPPAuditLogRules output).
    .PARAMETER Tenant
        The tenant's default domain.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Data,
        [string]$Tenant
    )

    $Operation = [string]$Data.Operation
    $OpMatch = [regex]::Match($Operation, '^(?<Verb>New|Set|Remove|Enable|Disable)-(?<Noun>[A-Za-z0-9]+)$')
    if (-not $OpMatch.Success) { return $null }
    $Verb = $OpMatch.Groups['Verb'].Value
    $Noun = $OpMatch.Groups['Noun'].Value

    # Noun -> what it is, where CIPP caches it, and which standards manage it. Standard names are the keys of
    # frontend/src/data/standards.json without the 'standards.' prefix.
    $Map = @{
        AntiPhishPolicy                = @{ Kind = 'Anti-phishing policy'; Cache = 'ExoAntiPhishPolicies'; Standards = @{ AntiPhishPolicy = 'Default Anti-Phishing Policy' } }
        AntiPhishRule                  = @{ Kind = 'Anti-phishing rule'; Cache = 'ExoAntiPhishRules'; Standards = @{ AntiPhishPolicy = 'Default Anti-Phishing Policy' } }
        HostedContentFilterPolicy      = @{ Kind = 'Anti-spam (inbound) policy'; Cache = 'ExoHostedContentFilterPolicy'; Standards = @{ SpamFilterPolicy = 'Default Spam Filter Policy' } }
        HostedContentFilterRule        = @{ Kind = 'Anti-spam (inbound) rule'; Cache = 'ExoHostedContentFilterRule'; Standards = @{ SpamFilterPolicy = 'Default Spam Filter Policy' } }
        HostedOutboundSpamFilterPolicy = @{ Kind = 'Outbound spam policy'; Cache = 'ExoHostedOutboundSpamFilterPolicy'; Standards = @{ EXOOutboundSpamLimits = 'Set Exchange Outbound Spam Limits'; OutBoundSpamAlert = 'Set Outbound Spam Alert e-mail' } }
        HostedOutboundSpamFilterRule   = @{ Kind = 'Outbound spam rule'; Cache = $null; Standards = @{ EXOOutboundSpamLimits = 'Set Exchange Outbound Spam Limits' } }
        HostedConnectionFilterPolicy   = @{ Kind = 'Connection filter policy'; Cache = 'ExoHostedConnectionFilterPolicy'; Standards = @{ AntiSpamSafeList = 'Set Anti-Spam Connection Filter Safe List'; EmptyFilterIPAllowList = 'Ensure connection filter IP allow list is empty' } }
        MalwareFilterPolicy            = @{ Kind = 'Anti-malware policy'; Cache = 'ExoMalwareFilterPolicies'; Standards = @{ MalwareFilterPolicy = 'Default Malware Filter Policy' } }
        MalwareFilterRule              = @{ Kind = 'Anti-malware rule'; Cache = 'ExoMalwareFilterRules'; Standards = @{ MalwareFilterPolicy = 'Default Malware Filter Policy' } }
        SafeAttachmentPolicy           = @{ Kind = 'Safe Attachments policy'; Cache = 'ExoSafeAttachmentPolicies'; Standards = @{ SafeAttachmentPolicy = 'Default Safe Attachment Policy' } }
        SafeAttachmentRule             = @{ Kind = 'Safe Attachments rule'; Cache = 'ExoSafeAttachmentRules'; Standards = @{ SafeAttachmentPolicy = 'Default Safe Attachment Policy' } }
        AtpPolicyForO365               = @{ Kind = 'Safe Attachments for SharePoint/OneDrive/Teams and Safe Documents'; Cache = 'ExoAtpPolicyForO365'; Standards = @{} }
        SafeLinksPolicy                = @{ Kind = 'Safe Links policy'; Cache = 'ExoSafeLinksPolicies'; Standards = @{ SafeLinksPolicy = 'Default Safe Links Policy'; SafeLinksTemplatePolicy = 'SafeLinks Policy Template' } }
        SafeLinksRule                  = @{ Kind = 'Safe Links rule'; Cache = 'ExoSafeLinksRules'; Standards = @{ SafeLinksPolicy = 'Default Safe Links Policy'; SafeLinksTemplatePolicy = 'SafeLinks Policy Template' } }
        ATPProtectionPolicyRule        = @{ Kind = 'Preset security policy (Defender) rule'; Cache = $null; Standards = @{} }
        EOPProtectionPolicyRule        = @{ Kind = 'Preset security policy (EOP) rule'; Cache = $null; Standards = @{} }
        TenantAllowBlockListItems      = @{ Kind = 'Tenant Allow/Block List entry'; Cache = 'ExoTenantAllowBlockList'; Standards = @{ TenantAllowBlockListTemplate = 'Tenant Allow/Block List Template' } }
        TenantAllowBlockListSpoofItems = @{ Kind = 'Tenant Allow/Block List spoofed-sender entry'; Cache = 'ExoTenantAllowBlockListSpoofItems'; Standards = @{ PhishSimSpoofIntelligence = 'Add allowed domains to Spoof Intelligence' } }
        TransportRule                  = @{ Kind = 'Transport (mail flow) rule'; Cache = 'ExoTransportRules'; Standards = @{ TransportRuleTemplate = 'Transport Rule Template' } }
    }
    $Entry = $Map[$Noun]
    if (-not $Entry) { return $null }

    if ($null -eq $script:EmailSecurityContextMemo -or $script:EmailSecurityContextMemo.Count -gt 200) { $script:EmailSecurityContextMemo = @{} }
    $MemoKey = '{0}|{1}' -f $Tenant, $Data.Id
    if ($Data.Id -and $script:EmailSecurityContextMemo.ContainsKey($MemoKey)) { return $script:EmailSecurityContextMemo[$MemoKey] }

    $Encode = { param($Value) [System.Net.WebUtility]::HtmlEncode([string]$Value) }
    $Parameters = @(try { $Data.CIPPParameters | ConvertFrom-Json -ErrorAction Stop } catch { @() }) | Where-Object { $_ -and $_.Name }
    $Noise = @('Confirm', 'Force', 'ErrorAction', 'WarningAction', 'Verbose', 'Debug')
    $Changed = @($Parameters | Where-Object { $_.Name -notin $Noise })
    $IdentityParam = @($Parameters | Where-Object { $_.Name -in @('Identity', 'Name') } | Select-Object -First 1)
    $Identity = if ($IdentityParam) { [string]$IdentityParam[0].Value } else { [string]$Data.ObjectId }
    $Actor = if ($Data.CIPPUserId -is [string] -and $Data.CIPPUserId) { $Data.CIPPUserId } else { [string]$Data.UserId }
    $ClientIp = [string]($Data.CIPPIPDetected ?? $Data.ClientIP)

    # Before: the last cached copy of the object.
    $Before = [System.Collections.Generic.List[object]]::new()
    $BeforeNote = $null
    if ($Entry.Cache -and $Tenant -and $Verb -ne 'New') {
        try {
            $Cached = @(New-CIPPDbRequest -TenantFilter $Tenant -Type $Entry.Cache | Where-Object { $_ })
            $Object = $null
            if ($Identity) {
                $Object = @($Cached | Where-Object {
                        $Identity -in @([string]$_.Identity, [string]$_.Name, [string]$_.Guid, [string]$_.Id, [string]$_.Value)
                    }) | Select-Object -First 1
            }
            if (-not $Object -and $Noun -eq 'TenantAllowBlockListItems') {
                # Entries/Ids identify TABL items rather than an Identity.
                $Keys = @($Parameters | Where-Object { $_.Name -in @('Entries', 'Ids') } | ForEach-Object { ([string]$_.Value) -split '[,;\s]+' } | Where-Object { $_ })
                $Object = @($Cached | Where-Object { $Keys -contains [string]$_.Value -or $Keys -contains [string]$_.Identity }) | Select-Object -First 1
            }
            if ($Object) {
                foreach ($Param in $Changed) {
                    if ($Param.Name -in @('Identity', 'Name', 'Entries', 'Ids')) { continue }
                    $Property = $Object.PSObject.Properties | Where-Object { $_.Name -ieq $Param.Name } | Select-Object -First 1
                    if (-not $Property) { continue }
                    $Old = if ($Property.Value -is [System.Collections.IEnumerable] -and $Property.Value -isnot [string]) { @($Property.Value) -join ', ' } else { [string]$Property.Value }
                    $Before.Add([pscustomobject]@{ Parameter = $Param.Name; Before = $Old; After = [string]$Param.Value })
                }
                if ($Before.Count -eq 0) { $BeforeNote = 'The object is in the CIPP cache, but none of the changed parameters are cached properties.' }
            } else {
                $BeforeNote = "No cached copy of '$Identity' in the CIPP DB cache ($($Entry.Cache)), so the previous values are not known. The audit log records only the new values."
            }
        } catch {
            $BeforeNote = "Previous values unavailable: $($_.Exception.Message)"
        }
    } elseif ($Verb -eq 'New') {
        $BeforeNote = 'A new object: there is no previous value.'
    } else {
        $BeforeNote = 'CIPP does not cache this object type, so the previous values are not known.'
    }

    # Drift: the standards that manage this kind of object for the tenant.
    $Drift = [System.Collections.Generic.List[string]]::new()
    if ($Entry.Standards.Count -gt 0 -and $Tenant) {
        try {
            $Applied = @(Get-CIPPStandards -TenantFilter $Tenant | Where-Object { $Entry.Standards.ContainsKey([string]$_.Standard) })
            $TemplateNames = @{}
            if ($Applied.Count -gt 0) {
                try {
                    $Templates = Get-CippTable -tablename 'templates'
                    foreach ($Template in @(Get-CIPPAzDataTableEntity @Templates -Filter "PartitionKey eq 'StandardsTemplateV2'")) {
                        $Name = try { ($Template.JSON | ConvertFrom-Json -ErrorAction Stop).templateName } catch { $null }
                        if ($Name) { $TemplateNames[[string]$Template.RowKey] = $Name }
                    }
                } catch { Write-Information "Template names unavailable: $($_.Exception.Message)" }
            }
            foreach ($Standard in ($Applied | Group-Object { [string]$_.Standard })) {
                $Ids = @($Standard.Group | ForEach-Object { @($_.TemplateId) } | Where-Object { $_ } | Select-Object -Unique)
                $Names = @($Ids | ForEach-Object { $TemplateNames[[string]$_] ?? $_ })
                $Drift.Add(("drift: {0} (standards.{1}{2})" -f $Entry.Standards[$Standard.Name], $Standard.Name, $(if ($Names) { ", template '$($Names -join "', '")'" } else { '' })))
            }
        } catch {
            Write-Information "Standards lookup failed for $($Tenant): $($_.Exception.Message)"
        }
    }

    $Subject = if ($Identity) { "$($Entry.Kind) '$Identity'" } else { $Entry.Kind }
    $ActorText = "$Actor" + $(if ($Data.CIPPActorClass) { " ($($Data.CIPPActorClass)$(if ($Data.CIPPActorDetail -and $Data.CIPPActorDetail -ne $Actor) { ": $($Data.CIPPActorDetail)" }))" })
    $Rows = [ordered]@{
        'Change'    = "$Operation - $Subject"
        'Actor'     = $ActorText
        'Client IP' = $ClientIp
        'When'      = [string]$Data.CreationTime
        'Result'    = [string]$Data.ResultStatus
    }
    $SummaryTable = '<table class="table-modern">' + (($Rows.GetEnumerator() | ForEach-Object { "<tr><th>$(& $Encode $_.Key)</th><td>$(& $Encode $_.Value)</td></tr>" }) -join '') + '</table>'
    $ParamTable = if ($Changed.Count -gt 0) {
        '<table class="table-modern"><tr><th>Parameter</th><th>Value</th></tr>' + (($Changed | ForEach-Object { "<tr><td>$(& $Encode $_.Name)</td><td>$(& $Encode $_.Value)</td></tr>" }) -join '') + '</table>'
    } else { '<p>The audit record lists no parameters.</p>' }
    $BeforeHtml = if ($Before.Count -gt 0) {
        '<p>Before (last CIPP cache snapshot, which may be older than the change) and after:</p><table class="table-modern"><tr><th>Parameter</th><th>Before</th><th>After</th></tr>' +
        (($Before | ForEach-Object { "<tr><td>$(& $Encode $_.Parameter)</td><td>$(& $Encode $_.Before)</td><td>$(& $Encode $_.After)</td></tr>" }) -join '') + '</table>'
    } else { "<p>$(& $Encode $BeforeNote)</p>" }
    $DriftHtml = if ($Drift.Count -gt 0) {
        '<p><b>' + (($Drift | ForEach-Object { & $Encode $_ }) -join '<br/>') + '</b><br/>A CIPP standard manages this kind of object here. If the change is unwanted, re-apply the standard from Standards (Run now) or fix it by hand. CIPP has not reverted anything.</p>'
    } else { '<p>No CIPP standard applied to this tenant manages this kind of object.</p>' }

    $Context = [pscustomobject]@{
        Title     = "$Tenant - Email security change: $Operation on $Subject by $Actor"
        IntroText = "<p>$(& $Encode $Actor) ran <b>$(& $Encode $Operation)</b> on the $(& $Encode $Subject). Changes to email protection are a common step in business email compromise: an attacker weakens filtering, allow-lists their own domain or adds a mail-flow rule. Confirm with whoever made the change.</p>$SummaryTable<p>Parameters it was called with (new values):</p>$ParamTable$BeforeHtml$DriftHtml"
        Drift     = $Drift.ToArray()
        Before    = $Before.ToArray()
        Kind      = $Entry.Kind
        Identity  = $Identity
        Actor     = $Actor
    }
    if ($Data.Id) { $script:EmailSecurityContextMemo[$MemoKey] = $Context }
    $Context
}
