function Get-CIPPOIBLatestRelease {
    <#
    .SYNOPSIS
        Latest OpenIntuneBaseline Windows release (windows-v*) and the policies in it, cached for a day.
    .DESCRIPTION
        Reads SkipToTheEndpoint/OpenIntuneBaseline through Invoke-GitHubApiRequest, the same path the community
        repo feature uses: the GitHub integration's token when one is configured, otherwise CIPP's anonymous
        proxy, which is rate-limited. That is why the result is cached in the CIPPOIBRelease table for
        -CacheHours (24). The repo also publishes macos-v* and win365-v* releases, so /releases/latest is not
        used; the highest windows-v* tag that is not a draft or pre-release wins.
        Three calls on a refresh: the release list, the git tree at the tag, and WINDOWS/PolicyManifest.json.
        If GitHub cannot be reached and a cached copy exists, the cached copy is returned with Stale = $true.
        Returns @{ Tag; Version; PublishedAt; Url; FetchedAt; Stale; Policies }.
        Aspendora fork addition (Vikunja CIPP-20).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,
        [int]$CacheHours = 24
    )

    $Repo = 'SkipToTheEndpoint/OpenIntuneBaseline'
    $Table = Get-CIPPTable -TableName 'CIPPOIBRelease'
    $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'OIB' and RowKey eq 'WindowsLatest'" | Select-Object -First 1

    $FromRow = {
        param($R, [bool]$Stale)
        [pscustomobject]@{
            Tag         = [string]$R.Tag
            Version     = [string]$R.Version
            PublishedAt = [string]$R.PublishedAt
            Url         = [string]$R.Url
            FetchedAt   = [string]$R.FetchedAt
            Stale       = $Stale
            Policies    = @([string]$R.Policies | ConvertFrom-Json -Depth 10)
        }
    }

    $Fresh = $false
    if ($Row -and $Row.FetchedAt -and $Row.Policies) {
        $Fetched = [datetime]::MinValue
        if ([datetime]::TryParse([string]$Row.FetchedAt, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$Fetched)) {
            $Fresh = $Fetched -gt [datetime]::UtcNow.AddHours(-$CacheHours)
        }
    }
    if ($Fresh -and -not $Force) { return (& $FromRow $Row $false) }

    try {
        $Releases = @(Invoke-GitHubApiRequest -Path "repos/$Repo/releases?per_page=50")
        $Latest = $Releases | Where-Object { $_.tag_name -match '^windows-v\d+(\.\d+)*$' -and -not $_.draft -and -not $_.prerelease } |
            Sort-Object -Property @{ Expression = { [version](($_.tag_name -replace '^windows-v', '') + $(if ($_.tag_name -notmatch '\.') { '.0' })) } } -Descending |
            Select-Object -First 1
        if (-not $Latest) { throw "No windows-v* release found in $Repo." }
        $Tag = [string]$Latest.tag_name

        $Tree = Get-GitHubFileTree -FullName $Repo -Branch $Tag
        $Paths = @($Tree.tree | Where-Object { $_.type -eq 'blob' } | ForEach-Object { [string]$_.path })
        $Manifest = try {
            (Get-GitHubFileContents -FullName $Repo -Path 'WINDOWS/PolicyManifest.json' -Branch $Tag).content | ConvertFrom-Json -Depth 20
        } catch {
            Write-Information "OIB: no readable PolicyManifest.json at $($Tag): $($_.Exception.Message)"
            $null
        }
        $Release = ConvertFrom-CIPPOIBRelease -Tag $Tag -Paths $Paths -Manifest $Manifest
        if (@($Release.Policies).Count -eq 0) { throw "OIB $Tag has no Windows policy files under WINDOWS/IntuneManagement." }

        $Entity = @{
            PartitionKey = 'OIB'
            RowKey       = 'WindowsLatest'
            Tag          = $Tag
            Version      = [string]$Release.Version
            PublishedAt  = [string]$Latest.published_at
            Url          = [string]$Latest.html_url
            FetchedAt    = [datetime]::UtcNow.ToString('o')
            Policies     = [string](ConvertTo-Json -InputObject @($Release.Policies) -Depth 5 -Compress)
        }
        Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force | Out-Null
        return (& $FromRow ([pscustomobject]$Entity) $false)
    } catch {
        if ($Row -and $Row.Policies) {
            Write-LogMessage -API 'OIBDrift' -tenant 'Global' -message "Could not refresh the OIB release from GitHub, using the cached $($Row.Tag) from $($Row.FetchedAt): $($_.Exception.Message)" -sev Warning
            return (& $FromRow $Row $true)
        }
        throw "Could not read the latest OIB release from GitHub: $($_.Exception.Message)"
    }
}
