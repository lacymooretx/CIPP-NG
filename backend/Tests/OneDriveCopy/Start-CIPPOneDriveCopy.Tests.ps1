BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/OneDriveCopy/Start-CIPPOneDriveCopy.ps1')

    function Write-LogMessage { param($headers, $API, $tenant, $message, $sev) }
    function Get-CIPPSharePointLibraryRootChildUris { param($TenantFilter, $SiteUrl, $ListId) }
    function Invoke-CIPPSharePointCreateCopyJobs { param($TenantFilter, $SourceSiteUrl, $ExportObjectUris, $DestinationUri, $NameConflictBehavior) }
    function Set-CIPPSharePointLibraryCopyOperation { param($TenantFilter, $OperationId, $Entity) }
    function New-GraphPOSTRequest { param($uri, $tenantid, $body, $AsApp) }
    function New-GraphGetRequest {
        param($uri, $tenantid, $AsApp, $noPagination, $ErrorAction)
        $u = [uri]::UnescapeDataString($uri)
        if ($u -match '/users/([^/?]+)/drive') {
            $id = $Matches[1]
            if ($script:NoDrive -contains $id) { throw 'itemNotFound' }
            return [pscustomobject]@{ id = "drive-$id"; webUrl = "https://t-my.sharepoint.com/personal/$id/Documents"; quota = [pscustomobject]@{ remaining = $script:FreeBytes } }
        }
        if ($u -match '/users/([^/?]+)\?') {
            $upn = $Matches[1]
            if ($upn -eq 'ghost@t.com') { throw 'Request_ResourceNotFound' }
            return [pscustomobject]@{ id = "id-$($upn.Split('@')[0])"; displayName = "Name $($upn.Split('@')[0])"; userPrincipalName = $upn }
        }
        if ($u -match '/drives/[^/]+/root\?') {
            return [pscustomobject]@{ size = $script:SourceBytes; sharepointIds = [pscustomobject]@{ siteUrl = 'https://t-my.sharepoint.com/personal/src'; listId = 'list-1' } }
        }
        throw "unexpected GET $u"
    }
}

Describe 'Start-CIPPOneDriveCopy' {
    BeforeEach {
        $script:NoDrive = @()
        $script:FreeBytes = 100GB
        $script:SourceBytes = 2GB
        Mock Get-CIPPSharePointLibraryRootChildUris { [pscustomobject]@{ ChildUris = @('u1', 'u2', 'u3'); EligibleRootCount = 3 } }
        Mock New-GraphPOSTRequest { [pscustomobject]@{ name = 'From Name src (2026-10-05)'; webUrl = 'https://t-my.sharepoint.com/personal/dst/Documents/From%20Name%20src' } }
        Mock Invoke-CIPPSharePointCreateCopyJobs { @([pscustomobject]@{ JobId = 'j1' }, [pscustomobject]@{ JobId = 'j2' }) }
        Mock Set-CIPPSharePointLibraryCopyOperation { }
    }

    It 'preflight reports counts and the default folder name without creating anything' {
        $R = Start-CIPPOneDriveCopy -TenantFilter 't.com' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -Mode Preflight
        $R.RootItemCount | Should -Be 3
        $R.DestinationFolder | Should -Match '^From Name src \(\d{4}-\d{2}-\d{2}\)$'
        $R.SourceSizeGB | Should -Be 2
        Should -Invoke New-GraphPOSTRequest -Times 0 -Exactly
        Should -Invoke Invoke-CIPPSharePointCreateCopyJobs -Times 0 -Exactly
    }

    It 'start creates the folder (rename on conflict), copies into it and records a OneDriveCopy operation' {
        $R = Start-CIPPOneDriveCopy -TenantFilter 't.com' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -Mode Start
        Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly -ParameterFilter { $uri -like '*/drives/drive-id-dst/root/children' -and $body -match 'rename' }
        Should -Invoke Invoke-CIPPSharePointCreateCopyJobs -Times 1 -Exactly -ParameterFilter {
            $SourceSiteUrl -eq 'https://t-my.sharepoint.com/personal/src' -and $DestinationUri -like '*From%20Name%20src' -and @($ExportObjectUris).Count -eq 3
        }
        Should -Invoke Set-CIPPSharePointLibraryCopyOperation -Times 1 -Exactly -ParameterFilter {
            $Entity.Kind -eq 'OneDriveCopy' -and $Entity.SourceUser -eq 'src@t.com' -and $Entity.DestinationUser -eq 'dst@t.com' -and $Entity.JobHandleCount -eq 2
        }
        $R.JobCount | Should -Be 2
        $R.OperationId | Should -Not -BeNullOrEmpty
    }

    It 'strips characters OneDrive does not allow from a custom folder name' {
        $R = Start-CIPPOneDriveCopy -TenantFilter 't.com' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' -FolderName 'Jane: files/2026?' -Mode Preflight
        $R.DestinationFolder | Should -Be 'Jane- files-2026-'
    }

    It 'refuses to copy a user onto themselves' {
        { Start-CIPPOneDriveCopy -TenantFilter 't.com' -SourceUser 'Src@t.com' -DestinationUser 'src@t.com' } | Should -Throw '*different users*'
    }

    It 'explains how to fix an unprovisioned destination OneDrive' {
        $script:NoDrive = @('id-dst')
        { Start-CIPPOneDriveCopy -TenantFilter 't.com' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' } | Should -Throw '*open OneDrive once*'
    }

    It 'stops when the destination does not have room' {
        $script:FreeBytes = 1GB
        { Start-CIPPOneDriveCopy -TenantFilter 't.com' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' } | Should -Throw '*Not enough space*'
    }

    It 'stops on an unknown user and on the 1,000 root item limit' {
        { Start-CIPPOneDriveCopy -TenantFilter 't.com' -SourceUser 'ghost@t.com' -DestinationUser 'dst@t.com' } | Should -Throw '*was not found*'
        Mock Get-CIPPSharePointLibraryRootChildUris { [pscustomobject]@{ ChildUris = @(); EligibleRootCount = 1500 } }
        { Start-CIPPOneDriveCopy -TenantFilter 't.com' -SourceUser 'src@t.com' -DestinationUser 'dst@t.com' } | Should -Throw '*limit is 1,000*'
    }
}
