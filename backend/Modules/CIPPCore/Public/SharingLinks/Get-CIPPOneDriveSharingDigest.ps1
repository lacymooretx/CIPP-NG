function Get-CIPPOneDriveSharingDigest {
    <#
    .SYNOPSIS
        A tenant's cached OneDrive sharing links, grouped by the OneDrive's owner, for the weekly digest email.
    .DESCRIPTION
        Reads the SharePointSharingLinks cache (Get-CIPPSharingLinks) and keeps the OneDrive rows. Graph has
        no field for who created a link, so a user's links are the links on items in their own OneDrive.
        The owner of each OneDrive is resolved live (sites/{id}/drive owner, then the user's mail address),
        one batched call per tenant.

        A "specific people" link whose only recipients are the OneDrive's owner is not sharing (nobody else can
        open it), so it is left out; a user left with no links is left out entirely and gets no email (CW #60357).

        Each user's links are split into Outside (Anyone links, links to external people, direct grants to
        external people) and Inside (everything else), riskiest first.

        Aspendora fork addition.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $Audience = @{
        anonymous      = 'Anyone with the link'
        organization   = 'Everyone in your organization'
        users          = 'Specific people'
        existingAccess = 'People who already have access'
        direct         = 'Shared directly'
    }

    $Links = @(Get-CIPPSharingLinks -TenantFilter $TenantFilter | Where-Object { $_.workload -eq 'OneDrive' })

    # Freshness of the cache, so the sender can refuse to mail stale data.
    $Summary = try {
        $StateTable = Get-CippTable -tablename 'CippSharingLinksState'
        $Domain = @(Get-Tenants -TenantFilter $TenantFilter -IncludeErrors)[0].defaultDomainName ?? $TenantFilter
        $SafeTenant = ConvertTo-CIPPODataFilterValue -Value $Domain -Type String
        Get-CIPPAzDataTableEntity @StateTable -Filter "PartitionKey eq '$SafeTenant' and RowKey eq 'summary'"
    } catch { $null }
    $LastScanUtc = if ($Summary.CompletedUtc) { [DateTimeOffset]::Parse([string]$Summary.CompletedUtc) } else { $null }

    $Result = [PSCustomObject]@{
        TenantFilter = $TenantFilter
        LastScanUtc  = $LastScanUtc
        Users        = @()
        Unresolved   = @()
        OwnerOnly    = 0
    }
    if ($Links.Count -eq 0) { return $Result }

    # --- OneDrive owner per site, then that user's mailbox ---
    $SiteIds = @($Links | ForEach-Object { [string]$_.siteId } | Where-Object { $_ } | Sort-Object -Unique)
    $OwnerBySite = @{}
    $DriveRequests = @(for ($i = 0; $i -lt $SiteIds.Count; $i++) { @{ id = "$i"; method = 'GET'; url = "sites/$($SiteIds[$i])/drive?`$select=owner,webUrl" } })
    foreach ($Response in @(New-GraphBulkRequest -tenantid $TenantFilter -Requests $DriveRequests -asapp $true)) {
        if ($Response.status -ne 200) { continue }
        $OwnerId = $Response.body.owner.user.id
        if ($OwnerId) { $OwnerBySite[$SiteIds[[int]$Response.id]] = @{ Id = [string]$OwnerId; DriveUrl = [string]$Response.body.webUrl } }
    }

    $OwnerIds = @($OwnerBySite.Values | ForEach-Object { $_.Id } | Sort-Object -Unique)
    $UserById = @{}
    if ($OwnerIds.Count -gt 0) {
        $UserRequests = @(foreach ($Id in $OwnerIds) { @{ id = $Id; method = 'GET'; url = "users/$($Id)?`$select=id,displayName,givenName,mail,userPrincipalName,accountEnabled,userType" } })
        foreach ($Response in @(New-GraphBulkRequest -tenantid $TenantFilter -Requests $UserRequests -asapp $true)) {
            if ($Response.status -eq 200) { $UserById[[string]$Response.id] = $Response.body }
        }
    }

    $CanEdit = { param($Link) @($Link.roles) -contains 'write' -or @($Link.roles) -contains 'owner' }
    # Lower sorts first: anonymous edit, anonymous, external, then internal; never-expiring before expiring.
    $Rank = {
        param($Link)
        $Base = switch ($Link.classification) { 'Anonymous' { 0 } 'External' { 2 } default { 4 } }
        if ($Base -lt 4 -and -not (& $CanEdit $Link)) { $Base++ }
        $Base
    }

    # True when a specific-people link reaches nobody but the OneDrive's owner.
    $IsOwnerOnly = {
        param($Link, $OwnerNames)
        if ([string]$Link.linkScope -ne 'users') { return $false }
        $Recipients = @($Link.sharedWith | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
        if ($Recipients.Count -eq 0) { return $false }
        return @($Recipients | Where-Object { $_ -notin $OwnerNames }).Count -eq 0
    }
    $OwnerOnlyCount = 0

    $Users = [System.Collections.Generic.List[object]]::new()
    $Unresolved = [System.Collections.Generic.List[object]]::new()
    foreach ($Group in @($Links | Group-Object -Property siteId)) {
        $Owner = $OwnerBySite[[string]$Group.Name]
        $User = if ($Owner) { $UserById[$Owner.Id] }
        if (-not $User) {
            $Unresolved.Add([PSCustomObject]@{ siteName = $Group.Group[0].siteName; siteUrl = $Group.Group[0].siteUrl; links = $Group.Count })
            continue
        }

        $OwnerNames = @(@($User.userPrincipalName, $User.mail) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $Shared = @($Group.Group | Where-Object { -not (& $IsOwnerOnly $_ $OwnerNames) })
        $OwnerOnlyCount += $Group.Count - $Shared.Count
        if ($Shared.Count -eq 0) { continue }

        $Rows = foreach ($Link in @($Shared | Sort-Object -Property @{ Expression = { & $Rank $_ } }, @{ Expression = { [string]$_.fileName } })) {
            $Recipients = @($Link.sharedWith | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            [PSCustomObject]@{
                Name        = [string]$Link.fileName
                Url         = [string]$Link.itemUrl
                ItemType    = [string]$Link.itemType
                Outside     = $Link.classification -in @('Anonymous', 'External')
                Anonymous   = $Link.classification -eq 'Anonymous'
                Audience    = $Audience[[string]$Link.linkScope] ?? [string]$Link.linkScope
                Access      = if (& $CanEdit $Link) { 'Can edit' } else { 'Can view' }
                Recipients  = $Recipients
                Expires     = if ($Link.expirationDateTime) { [DateTimeOffset]::Parse([string]$Link.expirationDateTime) } else { $null }
                HasPassword = [bool]$Link.hasPassword
            }
        }
        $Rows = @($Rows)

        $Users.Add([PSCustomObject]@{
                Id             = [string]$User.id
                DisplayName    = [string]$User.displayName
                GivenName      = [string]$User.givenName
                Mail           = [string]$User.mail
                UPN            = [string]$User.userPrincipalName
                AccountEnabled = [bool]$User.accountEnabled
                DriveUrl       = $Owner.DriveUrl
                Outside        = @($Rows | Where-Object { $_.Outside })
                Inside         = @($Rows | Where-Object { -not $_.Outside })
            })
    }

    $Result.Users = @($Users | Sort-Object -Property DisplayName)
    $Result.Unresolved = @($Unresolved)
    $Result.OwnerOnly = $OwnerOnlyCount
    return $Result
}
