function Get-CIPPBackupItemList {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Flattens a parsed backup into one entry per restorable object, each with a stable key.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23).

        Works on both backup shapes:
          - Scheduled (tenant) backups: an object whose properties are the backup components
            (users, groups, ca, intuneconfig, ...). Components are stored in several forms - arrays of
            Graph objects, arrays of JSON strings (ca), arrays of template rows (intune*), or one JSON
            string holding { policies, rules } (antispam, antiphishing). All of them are unpacked here.
          - CIPP (core) backups: an array of table rows, grouped by their 'table' column.

        Each entry is [pscustomobject]@{ Type; Key; AltKey; Name; Raw; Content; Unparsed }.
          Key      lower-case identity used to match the same object across backups. Intune and CA
                   policies are keyed by name because that is how restore finds an existing policy;
                   users and groups by object id (users also carry the UPN as AltKey).
          Raw      the item exactly as it sits in the backup - this is what gets hashed.
          Content  the comparable form: nested JSON strings (CA policies, Intune TemplateJson) parsed.
          Unparsed true when the backup holds an error string instead of an object (a failed capture).
        Duplicate keys inside one type get ' #2', ' #3' appended so every key is unique.
    .PARAMETER Backup
        The parsed backup (ConvertFrom-Json -NoEnumerate of the blob, or a Get-CIPPBackupLiveSnapshot result).
    .PARAMETER Types
        Only return these component types.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Backup,
        [string[]]$Types
    )

    $MetadataProperties = @('PartitionKey', 'RowKey', 'TenantFilter', 'ETag', 'Timestamp', 'odata.etag', 'BackupIsBlob', 'BackupIsBlobLink', 'BlobResourcePath')
    $Items = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Backup) { return , $Items.ToArray() }

    $TryParseJson = {
        param([string]$Text)
        try {
            $Parsed = ConvertFrom-Json -InputObject $Text -Depth 100 -NoEnumerate -ErrorAction Stop
            if ($null -ne $Parsed -and -not ($Parsed -is [string]) -and -not ($Parsed -is [ValueType])) { return , $Parsed }
        } catch {
            Write-Verbose "Backup entry is not JSON: $($_.Exception.Message)"
        }
        return $null
    }

    $Seen = @{}
    $AddItem = {
        param([string]$Type, [string]$Key, [string]$AltKey, [string]$Name, $Raw, $Content, [bool]$Unparsed)
        $Key = $Key.ToLowerInvariant()
        $SeenKey = "$Type`n$Key"
        if ($Seen.ContainsKey($SeenKey)) {
            $Seen[$SeenKey]++
            $Key = "$Key #$($Seen[$SeenKey])"
        } else {
            $Seen[$SeenKey] = 1
        }
        $Items.Add([pscustomobject]@{
                Type     = $Type
                Key      = $Key
                AltKey   = if ($AltKey) { $AltKey.ToLowerInvariant() } else { $null }
                Name     = $Name
                Raw      = $Raw
                Content  = $Content
                Unparsed = $Unparsed
            })
    }

    $AddUnparsed = {
        param([string]$Type, [string]$Text)
        $Short = if ($Text.Length -gt 120) { $Text.Substring(0, 120) + '...' } else { $Text }
        & $AddItem $Type ('unparsed|' + (Get-CIPPBackupSha256 -Text $Text).Substring(0, 12)) $null $Short $Text $Text $true
    }

    $FirstValue = {
        param($Object, [string[]]$Names)
        foreach ($N in $Names) {
            if ($null -ne $Object.PSObject.Properties[$N] -and -not [string]::IsNullOrWhiteSpace([string]$Object.$N)) { return [string]$Object.$N }
        }
        return $null
    }

    # ---- CIPP core backups: array of table rows ----
    if ($Backup -is [System.Array]) {
        $Index = 0
        foreach ($Row in $Backup) {
            $Index++
            if ($null -eq $Row) { continue }
            $Table = [string]$Row.table
            if (-not $Table) { $Table = 'unknown' }
            if ($Types -and $Table -notin $Types) { continue }
            $Key = if ($Row.PartitionKey -or $Row.RowKey) { "$($Row.PartitionKey)|$($Row.RowKey)" } else { "row|$Index" }
            & $AddItem $Table $Key $null $Key $Row $Row $false
        }
        return , $Items.ToArray()
    }

    # ---- Scheduled (tenant) backups: one property per component ----
    foreach ($Property in $Backup.PSObject.Properties) {
        $Type = $Property.Name
        if ($Type -in $MetadataProperties) { continue }
        if ($Types -and $Type -notin $Types) { continue }
        $Value = $Property.Value
        if ($null -eq $Value) { continue }

        # A component stored as one JSON string (antispam/antiphishing, or a component that was serialised whole)
        if ($Value -is [string]) {
            $Parsed = & $TryParseJson $Value
            if ($null -eq $Parsed) { & $AddUnparsed $Type $Value; continue }
            $Value = $Parsed
        }

        # Policy + rule bundles
        if (-not ($Value -is [System.Array]) -and $null -ne $Value.PSObject.Properties['policies'] -and $null -ne $Value.PSObject.Properties['rules']) {
            foreach ($Kind in 'policies', 'rules') {
                $Label = if ($Kind -eq 'policies') { 'policy' } else { 'rule' }
                foreach ($Entry in @($Value.$Kind)) {
                    if ($null -eq $Entry) { continue }
                    $Name = & $FirstValue $Entry @('Identity', 'Name')
                    if (-not $Name) { $Name = 'unnamed' }
                    & $AddItem $Type "$Label|$Name" $null "$Label`: $Name" $Entry $Entry $false
                }
            }
            continue
        }

        $Index = 0
        foreach ($Entry in @($Value)) {
            $Index++
            if ($null -eq $Entry) { continue }
            switch -Regex ($Type) {
                '^ca$' {
                    $Policy = if ($Entry -is [string]) { & $TryParseJson $Entry } else { $Entry }
                    if ($null -eq $Policy) { & $AddUnparsed $Type ([string]$Entry); break }
                    $Name = & $FirstValue $Policy @('displayName')
                    if (-not $Name) { $Name = "policy $Index" }
                    & $AddItem $Type $Name $null $Name $Entry $Policy $false
                    break
                }
                '^intune' {
                    if ($Entry -is [string]) { & $AddUnparsed $Type $Entry; break }
                    $TemplateType = [string]$Entry.Type
                    $Template = if ($Entry.TemplateJson -is [string]) { & $TryParseJson $Entry.TemplateJson } else { $Entry.TemplateJson }
                    if ($null -eq $Template) { $Template = $Entry.TemplateJson }
                    $Name = [string]$Entry.DisplayName
                    if ($TemplateType) {
                        $Name = Get-CIPPIntunePolicyName -TemplateType $TemplateType -RawJSON $Template -DisplayName $Entry.DisplayName
                    }
                    if (-not $Name) { $Name = "policy $Index" }
                    $Content = [ordered]@{
                        Type        = $TemplateType
                        DisplayName = $Name
                        Description = $Entry.Description
                        Template    = $Template
                    }
                    & $AddItem $Type "$TemplateType|$Name" $null $Name $Entry $Content $false
                    break
                }
                default {
                    if ($Entry -is [string]) {
                        $Parsed = & $TryParseJson $Entry
                        if ($null -eq $Parsed) { & $AddUnparsed $Type $Entry; break }
                        $Entry = $Parsed
                    }
                    $Id = switch ($Type) {
                        'users' { & $FirstValue $Entry @('id', 'userPrincipalName') }
                        'groups' { & $FirstValue $Entry @('id', 'displayName') }
                        'teamsvoice' { & $FirstValue $Entry @('telephoneNumber') }
                        default { & $FirstValue $Entry @('RowKey', 'id', 'Identity', 'displayName', 'name', 'Name') }
                    }
                    if (-not $Id) { $Id = "item $Index" }
                    $Alt = if ($Type -eq 'users') { & $FirstValue $Entry @('userPrincipalName') } else { $null }
                    $Name = & $FirstValue $Entry @('userPrincipalName', 'displayName', 'Name', 'name', 'telephoneNumber', 'RowKey')
                    if (-not $Name) { $Name = $Id }
                    & $AddItem $Type $Id $Alt $Name $Entry $Entry $false
                }
            }
        }
    }
    return , $Items.ToArray()
}
