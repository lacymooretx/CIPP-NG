function Get-CIPPTenantChanges {
    <#
    .SYNOPSIS
        Builds the "what changed" record for one tenant from data CIPP already holds.
    .DESCRIPTION
        Read only, with no new tenant permissions and no stored output. Each source is read on its own, so one failure
        cannot hide the others, and its Status says how far it can be trusted:
          OK             read, and fresh enough to rely on
          CouldNotRead   the read failed or found nothing to read. Its counts are $null, never 0
          NotComparable  read, but there is nothing to compare with for this window
          Stale          read, but the data is older than it should be

        Verdict: Changes when anything changed. Quiet only when nothing changed and every change source is OK.
        Incomplete when nothing changed but a change source is not OK. Unreadable when every source failed. The data
        age source reports on the others and has no say in Quiet, since some cache types are always old.
        Aspendora fork addition (Vikunja CIPP-58, stage 1).
    .PARAMETER TenantFilter
        A tenant default domain or customerId.
    .PARAMETER Days
        The window, in days back from Now.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [int]$Days = 1,
        [datetime]$Now = [datetime]::UtcNow
    )

    $NowUtc = ConvertTo-CIPPTenantChangeUtc -Value $Now

    $Tenant = Get-Tenants -TenantFilter $TenantFilter -IncludeErrors | Select-Object -First 1
    if (-not $Tenant -or -not $Tenant.defaultDomainName) {
        throw [System.Management.Automation.ItemNotFoundException]::new("Tenant '$TenantFilter' was not found.")
    }
    $Domain = [string]$Tenant.defaultDomainName

    $Readers = @(
        @{ Name = 'Alerts'; Label = 'Alerts'; Read = { Get-CIPPTenantChangeAlerts -Tenant $Domain -Days $Days -Now $NowUtc } }
        @{ Name = 'Tests'; Label = 'Test results'; Read = { Get-CIPPTenantChangeTests -Tenant $Domain -Days $Days -Now $NowUtc } }
        @{ Name = 'SecureScore'; Label = 'Secure Score'; Read = { Get-CIPPTenantChangeSecureScore -Tenant $Domain -Days $Days -Now $NowUtc } }
        @{ Name = 'MessageCenter'; Label = 'Message Center'; Read = { Get-CIPPTenantChangeMessageCenter -Tenant $Domain -Days $Days -Now $NowUtc } }
        @{ Name = 'Health'; Label = 'Data age'; Read = { Get-CIPPTenantChangeHealth -Tenant $Domain -Now $NowUtc } }
    )
    $StatusText = @{ OK = 'Read'; CouldNotRead = 'Could not read'; NotComparable = 'Nothing to compare with'; Stale = 'Read, but old data' }

    $Results = @{}
    $Sources = [System.Collections.Generic.List[object]]::new()
    $Changes = [System.Collections.Generic.List[object]]::new()
    foreach ($Reader in $Readers) {
        $Result = $null
        $Status = 'CouldNotRead'
        $Detail = ''
        try {
            $Result = & $Reader.Read
            $Status = [string]$Result.Status
            $Detail = [string]$Result.Detail
        } catch {
            $Result = $null
            $Detail = [string]$_.Exception.Message
            Write-LogMessage -API 'TenantChanges' -tenant $Domain -message "Could not read $($Reader.Label) for the change record: $Detail" -Sev 'Warning'
        }
        $Results[$Reader.Name] = $Result
        $Rows = if ($Result) { @($Result.Changes | Where-Object { $null -ne $_ }) } else { @() }
        foreach ($Row in $Rows) { $Changes.Add($Row) }
        $Sources.Add([pscustomobject]@{
                Name        = $Reader.Name
                Label       = $Reader.Label
                Status      = $Status
                StatusText  = $StatusText[$Status]
                Detail      = $Detail
                ChangeCount = $(if ($Result) { $Rows.Count } else { $null })
            })
    }

    $ChangeSources = @($Sources | Where-Object { $_.Name -ne 'Health' })
    $Failed = @($Sources | Where-Object { $_.Status -eq 'CouldNotRead' }).Count
    $Verdict = if ($Failed -eq $Sources.Count) { 'Unreadable' }
    elseif ($Changes.Count -gt 0) { 'Changes' }
    elseif (@($ChangeSources | Where-Object { $_.Status -ne 'OK' }).Count -eq 0) { 'Quiet' }
    else { 'Incomplete' }

    $Alerts = $Results['Alerts']
    $Tests = $Results['Tests']
    $Score = $Results['SecureScore']
    $Posts = $Results['MessageCenter']
    $WindowStart = $NowUtc.AddDays(-$Days)

    [pscustomobject]@{
        Tenant           = $Domain
        Days             = $Days
        GeneratedAt      = Format-CIPPCentralTime -Value $NowUtc
        GeneratedAtUtc   = $NowUtc.ToString('o')
        WindowStart      = Format-CIPPCentralTime -Value $WindowStart
        WindowStartUtc   = $WindowStart.ToString('o')
        Verdict          = $Verdict
        Summary          = [pscustomobject]@{
            TotalChanges   = $Changes.Count
            # $null means "could not read" and the page shows it that way. Only a real read reports 0.
            NewAlerts      = $(if ($Alerts) { $Alerts.New } else { $null })
            ReopenedAlerts = $(if ($Alerts) { $Alerts.Reopened } else { $null })
            ResolvedAlerts = $(if ($Alerts) { $Alerts.Resolved } else { $null })
            NewIssues      = $(if ($Tests) { $Tests.NewIssues } else { $null })
            FixedTests     = $(if ($Tests) { $Tests.Fixed } else { $null })
            ScorePercent   = $(if ($Score) { $Score.Percent } else { $null })
            ScoreDelta     = $(if ($Score) { $Score.Delta } else { $null })
            MessageCenter  = $(if ($Posts) { @($Posts.Changes).Count } else { $null })
            SourcesFailed  = $Failed
            SourcesTotal   = $Sources.Count
        }
        Sources          = @($Sources)
        Changes          = @($Changes)
        OlderTestChanges = $(if ($Tests) { @($Tests.OlderChanges) } else { @() })
        TestBaselineDate = $(if ($Tests) { $Tests.BaselineDate } else { $null })
        TestBaselineDays = $(if ($Tests) { $Tests.BaselineDays } else { $null })
    }
}
