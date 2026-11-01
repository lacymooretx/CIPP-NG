function Invoke-CIPPCAPreflight {
    <#
    .SYNOPSIS
        Runs the Conditional Access pre-flight (lockout) check for one policy in one tenant. Read-only.
    .DESCRIPTION
        The policy can be given three ways:
          -PolicyId    an existing policy; it is evaluated as if switched to enabled
          -Policy      policy JSON (string or object) as it would be written; the existing policy is found by
                       id or display name (the same match New-CIPPCAPolicy uses)
          -TemplateId  a CA template GUID from the template library; custom variables are resolved and group /
                       user names looked up, like a deploy would
        Returns Test-CIPPCAPreflight's result plus Tenant, PolicyId, Source, Errors and CheckedUtc.
        Aspendora fork addition (Vikunja CIPP-5).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        $Policy,
        [string]$PolicyId,
        [string]$TemplateId,
        # Pass when the caller already has it; skips the lookup.
        $ExistingPolicy,
        # The caller already looked: a $null ExistingPolicy means "new policy", so do not look again.
        [switch]$ExistingKnown,
        $Headers,
        [int]$RequiredDays = 7,
        [switch]$SkipSignIns
    )

    $Graph = 'https://graph.microsoft.com'
    $Errors = [System.Collections.Generic.List[string]]::new()
    $GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $Source = $null

    if ($PolicyId) {
        if ($PolicyId -notmatch $GuidPattern) { throw "PolicyId '$PolicyId' is not a GUID." }
        if (-not $ExistingPolicy) { $ExistingPolicy = New-GraphGetRequest -uri "$Graph/beta/identity/conditionalAccess/policies/$PolicyId" -tenantid $TenantFilter -ErrorAction Stop }
        if (-not $Policy) { $Policy = $ExistingPolicy }
        $Source = 'policy'
    } elseif ($TemplateId) {
        $Table = Get-CIPPTable -tablename 'templates'
        $Key = ConvertTo-CIPPODataFilterValue -Value $TemplateId -Type String
        $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'CATemplate' and (RowKey eq '$Key' or GUID eq '$Key')" | Select-Object -First 1
        if (-not $Row.JSON) { throw "CA template $TemplateId was not found." }
        $Policy = Get-CIPPTextReplacement -TenantFilter $TenantFilter -Text $Row.JSON -EscapeForJson
        $Source = 'template'
    } elseif (-not $Policy) {
        throw 'Give a PolicyId, a TemplateId or the policy JSON.'
    } else {
        $Source = 'json'
    }
    if ($Policy -is [string]) { $Policy = $Policy | ConvertFrom-Json -Depth 30 }
    $Policy = ConvertTo-Json -InputObject $Policy -Depth 30 | ConvertFrom-Json -Depth 30

    if (-not $ExistingPolicy -and -not $ExistingKnown -and $Source -ne 'policy') {
        try {
            $All = @(New-GraphGetRequest -uri "$Graph/beta/identity/conditionalAccess/policies?`$top=999" -tenantid $TenantFilter -ErrorAction Stop)
            $ExistingPolicy = @($All | Where-Object { ($Policy.id -and $_.id -eq $Policy.id) -or $_.displayName -eq $Policy.displayName }) | Select-Object -First 1
        } catch { $Errors.Add("Existing policies: $((Get-CippException -Exception $_).NormalizedError)") }
    }

    # Templates (and hand-written JSON) may name users and groups instead of using ids; resolve them so
    # exclusions match. A name that cannot be resolved is reported, since it would be ignored by the check.
    $Users = $Policy.conditions.users
    if ($Users -and $Source -ne 'policy') {
        foreach ($Prop in 'includeUsers', 'excludeUsers') {
            $Values = @($Users.$Prop)
            if (-not ($Values | Where-Object { $_ -and $_ -notin 'All', 'None', 'GuestsOrExternalUsers' -and $_ -notmatch $GuidPattern })) { continue }
            $Users.$Prop = @(foreach ($V in $Values) {
                    if (-not $V -or $V -in 'All', 'None', 'GuestsOrExternalUsers' -or $V -match $GuidPattern) { $V; continue }
                    try { (New-GraphGetRequest -uri "$Graph/v1.0/users/$([System.Uri]::EscapeDataString($V))?`$select=id" -tenantid $TenantFilter -ErrorAction Stop).id } catch { $Errors.Add("User '$V' in $Prop could not be resolved; it is ignored by the check."); $V }
                })
        }
        foreach ($Prop in 'includeGroups', 'excludeGroups') {
            $Values = @($Users.$Prop)
            if (-not ($Values | Where-Object { $_ -and $_ -notmatch $GuidPattern })) { continue }
            $Users.$Prop = @(foreach ($V in $Values) {
                    if (-not $V -or $V -match $GuidPattern) { $V; continue }
                    $Name = ConvertTo-CIPPODataFilterValue -Value $V -Type String
                    $Found = try { @(New-GraphGetRequest -uri "$Graph/v1.0/groups?`$filter=displayName eq '$Name'&`$select=id" -tenantid $TenantFilter -ErrorAction Stop) } catch { @() }
                    if ($Found) { [string]$Found[0].id } else { $Errors.Add("Group '$V' in $Prop does not exist in the tenant yet; it is ignored by the check."); $V }
                })
        }
    }

    $Context = Get-CIPPCAPreflightContext -TenantFilter $TenantFilter -Policy $Policy -ExistingPolicy $ExistingPolicy -Headers $Headers -RequiredDays $RequiredDays -SkipSignIns:$SkipSignIns
    foreach ($E in @($Context.Errors)) { $Errors.Add($E) }
    $Context.Remove('Errors')
    $Result = Test-CIPPCAPreflight @Context

    $Result | Add-Member -NotePropertyName Tenant -NotePropertyValue $TenantFilter -Force
    $Result | Add-Member -NotePropertyName PolicyId -NotePropertyValue ($ExistingPolicy.id ?? $Policy.id) -Force
    $Result | Add-Member -NotePropertyName CurrentState -NotePropertyValue $ExistingPolicy.state -Force
    $Result | Add-Member -NotePropertyName Source -NotePropertyValue $Source -Force
    $Result | Add-Member -NotePropertyName Errors -NotePropertyValue @($Errors) -Force
    $Result | Add-Member -NotePropertyName CheckedUtc -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
    $Result
}
