# Stale Device Report (enhancement B5) - orphans in BOTH directions.
#
# The join key is the load-bearing detail. Intune's managedDevice id and the Entra deviceId are
# different identifiers; joining on the wrong one matches nothing and reports every device in the
# tenant as orphaned - a convincing, entirely wrong report. Asserted directly.
#
# Actions are distinguished rather than lumped into one "stale" bucket, because the remedies differ:
# an Intune record with no Entra object can never be managed again (DELETE), a quiet device may just
# be in a drawer (RETIRE), a disabled owner needs a human decision (REVIEW), and an active but
# unenrolled device is an enrolment gap rather than cleanup (MONITOR).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Reports/Get-CIPPStaleDeviceReportData.ps1')

    function New-GraphGetRequest {
        param($uri, $tenantid)
        switch -Regex ($uri) {
            '/organization$'   { return @([pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @([pscustomobject]@{ name = 'contoso.com'; isDefault = $true }) }) }
            'managedDevices'   { return $script:Managed }
            'accountEnabled eq false' { return $script:DisabledUsers }
            '/devices\?'       { return $script:EntraDevices }
        }
        return @()
    }

    function New-Managed {
        param($Name = 'PC1', $AadId = 'aad-1', $SyncDaysAgo = 1, $Upn = 'user@contoso.com')
        [pscustomobject]@{ id = "md-$Name"; deviceName = $Name; azureADDeviceId = $AadId
            lastSyncDateTime = $(if ($null -ne $SyncDaysAgo) { (Get-Date).ToUniversalTime().AddDays(-$SyncDaysAgo).ToString('o') } else { $null })
            operatingSystem = 'Windows'; userPrincipalName = $Upn }
    }
    function New-Entra {
        param($Name = 'PC1', $DeviceId = 'aad-1', $SignInDaysAgo = 1, $Enabled = $true)
        [pscustomobject]@{ id = "dir-$Name"; deviceId = $DeviceId; displayName = $Name; accountEnabled = $Enabled
            approximateLastSignInDateTime = $(if ($null -ne $SignInDaysAgo) { (Get-Date).ToUniversalTime().AddDays(-$SignInDaysAgo).ToString('o') } else { $null })
            operatingSystem = 'Windows' }
    }
    # Return the SECTION (a hashtable, which PowerShell does not enumerate on return) and index
    # .Rows inline. Returning the row collection from a function unrolls it: a single row is itself
    # an array, so it comes back as seven loose cells.
    function Get-Section { param($Model, $Title) $Model.Sections | Where-Object { $_.Title -eq $Title } }
    function Get-Actions { param($Model, $Title = 'Device Records Needing Action')
        $Rows = (Get-Section $Model $Title).Rows
        $Out = @{}
        for ($i = 0; $i -lt $Rows.Count; $i++) { $Out[[string]$Rows[$i][1]] = $Rows[$i] }
        return $Out
    }
    function Get-RowCount { param($Model, $Title = 'Device Records Needing Action') (Get-Section $Model $Title).Rows.Count }
}

Describe 'Get-CIPPStaleDeviceReportData' {
    BeforeEach { $script:Managed = @(); $script:EntraDevices = @(); $script:DisabledUsers = @() }

    It 'returns the model shape the renderer expects' {
        $m = Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com'
        $m.Title | Should -Be 'Stale Device Report'
        $m.TenantDomain | Should -Be 'contoso.com'
        $m.Keys | Should -Contain 'GeneratedDate'
    }

    It 'reports nothing when Intune and Entra agree and devices are checking in' {
        $script:Managed = @(New-Managed)
        $script:EntraDevices = @(New-Entra)

        $m = Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com'

        Get-RowCount $m | Should -Be 0
        ($m.Findings | Where-Object { $_.Title -match 'clean' }).Status | Should -Be 'pass'
    }

    It 'joins on the Entra deviceId, not the Intune managedDevice id' {
        # The managedDevice id is 'md-PC1' and deliberately does not match any deviceId. If the join
        # used it, this healthy device would be reported as orphaned.
        $script:Managed = @(New-Managed -Name 'PC1' -AadId 'aad-1')
        $script:EntraDevices = @(New-Entra -Name 'PC1' -DeviceId 'aad-1')

        Get-RowCount (Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com') | Should -Be 0
    }

    It 'DELETEs an Intune record whose Entra object is gone' {
        $script:Managed = @(New-Managed -Name 'Orphan' -AadId 'missing')

        $m = Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com'

        (Get-Actions $m)['Orphan'][0] | Should -Be 'DELETE'
        (Get-Actions $m)['Orphan'][6] | Should -Match 'no matching Entra device object'
    }

    It 'RETIREs a device that stopped checking in' {
        $script:Managed = @(New-Managed -Name 'Quiet' -SyncDaysAgo 200)
        $script:EntraDevices = @(New-Entra -Name 'Quiet')

        (Get-Actions (Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com'))['Quiet'][0] | Should -Be 'RETIRE'
    }

    It 'does not RETIRE a device that is merely on holiday' {
        # 30 days quiet is a drawer, not a dead device.
        $script:Managed = @(New-Managed -Name 'Drawer' -SyncDaysAgo 30)
        $script:EntraDevices = @(New-Entra -Name 'Drawer')

        Get-RowCount (Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com') | Should -Be 0
    }

    It 'REVIEWs a device whose owner is disabled, ahead of any staleness rule' {
        $script:Managed = @(New-Managed -Name 'Leaver' -Upn 'gone@contoso.com' -SyncDaysAgo 1)
        $script:EntraDevices = @(New-Entra -Name 'Leaver')
        $script:DisabledUsers = @([pscustomobject]@{ userPrincipalName = 'gone@contoso.com'; accountEnabled = $false })

        $m = Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com'

        (Get-Actions $m)['Leaver'][0] | Should -Be 'REVIEW'
        (Get-Actions $m)['Leaver'][6] | Should -Match 'is disabled'
    }

    It 'MONITORs an active Entra device that was never enrolled' {
        # An enrolment gap, not a cleanup item - lumping it with stale records would bury it.
        $script:EntraDevices = @(New-Entra -Name 'Unenrolled' -DeviceId 'solo' -SignInDaysAgo 2)

        $m = Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com'

        (Get-Actions $m)['Unenrolled'][0] | Should -Be 'MONITOR'
    }

    It 'DELETEs an Entra device that was never enrolled and went quiet' {
        $script:EntraDevices = @(New-Entra -Name 'DeadEntra' -DeviceId 'solo' -SignInDaysAgo 400)

        (Get-Actions (Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com'))['DeadEntra'][0] | Should -Be 'DELETE'
    }

    It 'does not double-report a device present on both sides' {
        $script:Managed = @(New-Managed -Name 'Both' -AadId 'aad-9' -SyncDaysAgo 200)
        $script:EntraDevices = @(New-Entra -Name 'Both' -DeviceId 'aad-9' -SignInDaysAgo 200)

        Get-RowCount (Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com') | Should -Be 1
    }

    It 'sorts the most final action first' {
        $script:Managed = @((New-Managed -Name 'Gone' -AadId 'missing'), (New-Managed -Name 'Quiet' -AadId 'aad-2' -SyncDaysAgo 200))
        $script:EntraDevices = @(New-Entra -Name 'Quiet' -DeviceId 'aad-2' -SignInDaysAgo 200)

        (Get-Section (Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com') 'Device Records Needing Action').Rows[0][0] | Should -Be 'DELETE'
    }

    It 'summarises both sides of the join' {
        $script:Managed = @(New-Managed -AadId 'aad-1')
        $script:EntraDevices = @((New-Entra -DeviceId 'aad-1'), (New-Entra -Name 'Extra' -DeviceId 'aad-2'))

        $Rows = (Get-Section (Get-CIPPStaleDeviceReportData -TenantFilter 'contoso.com') 'Inventory Summary').Rows

        $Matched = $null
        for ($i = 0; $i -lt $Rows.Count; $i++) { if ($Rows[$i][0] -match 'Matched') { $Matched = $Rows[$i][1] } }
        $Matched | Should -Be '1'
    }
}
