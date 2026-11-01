# Aspendora fork (Vikunja CIPP-37): weekly Message Center digest alert. Write-AlertTrace is stubbed to capture the rows
# handed to the lifecycle (state mode, stable Id per post). The partner tenant id is set on $env:TenantID for the run
# and restored afterwards, so the tests do not depend on the host environment.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Core = Join-Path $RepoRoot 'Modules/CIPPCore/Public'
    . (Join-Path $Core 'MessageCenter/Get-CIPPMessageCenterClassification.ps1')
    . (Join-Path $Core 'MessageCenter/Get-CIPPMessageCenterDigest.ps1')
    . (Join-Path $Core 'IntuneOps/Format-CIPPCentralTime.ps1')
    . (Join-Path $Core 'Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $Core 'GraphHelper/Get-AlertContentHash.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertMessageCenterDigest.ps1')

    function Get-CIPPDbItem { param($TenantFilter, $Type, [switch]$ByTenant, $Partition) }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) }
    function New-GraphGetRequest { param($uri, $tenantid) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Write-AlertTrace {
        param($cmdletName, $tenantFilter, $data, [switch]$Append)
        $script:Traced = @($data)
        $script:Appended = [bool]$Append
        $script:TraceCalls++
        $script:TraceTenant = $tenantFilter
    }

    $script:SavedTenantId = $env:TenantID
    $env:TenantID = '11111111-1111-1111-1111-111111111111'
    $script:PartnerTenant = [pscustomobject]@{ defaultDomainName = 'msp.com'; customerId = $env:TenantID }
    $script:ClientTenant = [pscustomobject]@{ defaultDomainName = 'client.com'; customerId = '22222222-2222-2222-2222-222222222222' }

    function New-Item2 {
        param([string]$Id, [string]$Category = 'Retirement', [bool]$Notify = $true, $DaysLeft = $null, [string]$Status = '', [string]$Deadline = '')
        [pscustomobject]@{
            MessageId      = $Id
            Title          = "Post $Id"
            Category       = $Category
            CategoryLabel  = $Category
            Notify         = $Notify
            Deadline       = $Deadline
            DaysLeft       = $DaysLeft
            DeadlineStatus = $Status
            DueSoon        = $Status -eq 'Due soon'
            WindowReason   = 'Updated'
            TenantCount    = 2
            TenantsText    = 'a.com, b.com'
            Services       = 'Exchange Online'
            Reasons        = 'Tagged Retirement'
            Link           = "https://admin.microsoft.com/#/MessageCenter/:/messages/$Id"
        }
    }
}

AfterAll {
    $env:TenantID = $script:SavedTenantId
}

Describe 'MessageCenterDigest alert' {
    BeforeEach {
        $script:Traced = $null; $script:Appended = $null; $script:TraceCalls = 0; $script:TraceTenant = $null
        Mock Write-LogMessage {}
        Mock Get-Tenants { if ($TenantFilter -eq 'msp.com') { $script:PartnerTenant } else { $script:ClientTenant } }
        Mock Get-CIPPMessageCenterDigest {
            [pscustomobject]@{
                Items   = @(
                    New-Item2 -Id 'MC3' -Category 'Security'
                    New-Item2 -Id 'MC2' -Category 'ActionRequired' -DaysLeft 5 -Status 'Due soon' -Deadline '2026-11-06'
                    New-Item2 -Id 'MC1' -Category 'ActionRequired' -DaysLeft -31 -Status 'Overdue' -Deadline '2026-10-01'
                    New-Item2 -Id 'MC4' -Category 'ActionRequired' -DaysLeft 90 -Status 'Upcoming' -Deadline '2027-01-30'
                    New-Item2 -Id 'MC9' -Category 'OptIn' -Notify $false
                    New-Item2 -Id 'MC8' -Category 'Informational' -Notify $false
                )
                Summary = [pscustomobject]@{ Total = 6 }
                Errors  = @()
            }
        }
    }

    Context 'scope' {
        It 'digests every tenant when run on the partner tenant' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' | Out-Null
            Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $TenantFilter -eq 'AllTenants' -and $Days -eq 7 -and $DeadlineDays -eq 30 -and $IncludeOpenDeadlines }
            $script:TraceTenant | Should -Be 'msp.com'
        }

        It 'treats the partner tenant id itself as the partner tenant' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter $env:TenantID | Out-Null
            Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $TenantFilter -eq 'AllTenants' }
        }

        It 'digests only the tenant it runs on elsewhere' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'client.com' | Out-Null
            Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $TenantFilter -eq 'client.com' }
        }

        It 'digests every tenant from any tenant with MCDigestAllTenants, and reads "false" as off' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'client.com' -InputValue @{ MCDigestAllTenants = $true } | Out-Null
            Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $TenantFilter -eq 'AllTenants' }
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'client.com' -InputValue @{ MCDigestAllTenants = 'false' } | Out-Null
            Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $TenantFilter -eq 'client.com' }
        }

        It 'passes the deadline and look-back inputs' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' -InputValue @{ MCDigestDeadlineDays = '45'; MCDigestLookbackDays = '14' } | Out-Null
            Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $DeadlineDays -eq 45 -and $Days -eq 14 }
        }
    }

    Context 'rows' {
        It 'raises only alerting categories, in state mode, deadline items first' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' | Out-Null
            $script:TraceCalls | Should -Be 1
            $script:Appended | Should -BeFalse
            @($script:Traced.MessageId) | Should -Be @('MC1', 'MC2', 'MC4', 'MC3')
        }

        It 'marks due and overdue posts and gives due posts their own Id' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' | Out-Null
            $Due = $script:Traced | Where-Object MessageId -EQ 'MC2'
            $Due.Id | Should -Be 'MC|MC2|due'
            $Due.Priority | Should -Be 'DUE IN 5 DAYS'
            $Due.Message | Should -Match '^\[DUE IN 5 DAYS\] MC2 Post MC2\. Act by 2026-11-06 \(US Central\)\.'
            $Over = $script:Traced | Where-Object MessageId -EQ 'MC1'
            $Over.Id | Should -Be 'MC|MC1'
            $Over.Priority | Should -Be 'OVERDUE'
            ($script:Traced | Where-Object MessageId -EQ 'MC4').Priority | Should -Be ''
            ($script:Traced | Where-Object MessageId -EQ 'MC3').Id | Should -Be 'MC|MC3'
        }

        It 'carries what a ticket needs: MC id, title, deadline, tenants and link' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' | Out-Null
            $Row = $script:Traced | Where-Object MessageId -EQ 'MC2'
            $Row.Title | Should -Be 'Post MC2'
            $Row.Deadline | Should -Be '2026-11-06'
            $Row.Tenants | Should -Be 'a.com, b.com'
            $Row.TenantCount | Should -Be 2
            $Row.Link | Should -Be 'https://admin.microsoft.com/#/MessageCenter/:/messages/MC2'
            $Row.PSObject.Properties.Name | Should -Not -Contain 'UserPrincipalName'
        }

        It 'hashes the same as the days left count down' {
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' | Out-Null
            $Row = $script:Traced | Where-Object MessageId -EQ 'MC2'
            $A = (Get-AlertContentHash -AlertItem $Row).ContentHash
            $Row.DaysLeft = 4
            $Row.Priority = 'DUE IN 4 DAYS'
            $Row.Message = 'changed'
            (Get-AlertContentHash -AlertItem $Row).ContentHash | Should -Be $A
        }

        It 'reconciles an empty run so resolved posts close' {
            Mock Get-CIPPMessageCenterDigest { [pscustomobject]@{ Items = @(New-Item2 -Id 'MC8' -Category 'Informational' -Notify $false); Summary = $null; Errors = @() } }
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' | Out-Null
            $script:TraceCalls | Should -Be 1
            @($script:Traced).Count | Should -Be 0
        }

        It 'does not reconcile when posts cannot be read' {
            Mock Get-CIPPMessageCenterDigest { throw 'No Message Center posts are cached for any tenant yet.' }
            Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' | Out-Null
            $script:TraceCalls | Should -Be 0
            Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $sev -eq 'Warning' -and $message -match 'could not read posts' }
        }
    }
}

Describe 'MessageCenterDigest alert end to end with the real digest' {
    BeforeEach {
        $script:Traced = $null; $script:TraceCalls = 0
        Mock Write-LogMessage {}
        Mock Get-Tenants { if ($TenantFilter -eq 'msp.com') { $script:PartnerTenant } else { @([pscustomobject]@{ defaultDomainName = 'a.com' }, [pscustomobject]@{ defaultDomainName = 'b.com' }) } }
        $Iso = { param([double]$Days) [datetime]::UtcNow.AddDays($Days).ToString('yyyy-MM-ddTHH:mm:ssZ') }
        # Announced months ago, not updated since, deadline 60 days out: in the digest only because its deadline is open.
        $Post = [pscustomobject]@{
            id = 'MC1325414'; title = 'Microsoft Entra ID SSPR will require registered authentication methods'; category = 'planForChange'
            severity = 'normal'; tags = @('Admin impact'); services = @('Microsoft Entra'); isMajorChange = $true
            actionRequiredByDateTime = (& $Iso 60); startDateTime = (& $Iso -120); lastModifiedDateTime = (& $Iso -90)
            details = @()
        }
        $script:PostJson = ConvertTo-Json -InputObject $Post -Depth 5 -Compress
        Mock Get-CIPPDbItem {
            [ordered]@{
                'a.com' = [System.Collections.Generic.List[object]]@([pscustomobject]@{ PartitionKey = 'a.com'; Timestamp = [datetimeoffset]::UtcNow; Data = $script:PostJson })
                'b.com' = [System.Collections.Generic.List[object]]@([pscustomobject]@{ PartitionKey = 'b.com'; Timestamp = [datetimeoffset]::UtcNow; Data = $script:PostJson })
            }
        }
    }

    It 'keeps an open deadline as one row, then switches to the due row inside the window' {
        Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' | Out-Null
        Should -Invoke Get-CIPPDbItem -Times 1 -ParameterFilter { $TenantFilter -eq 'allTenants' -and $Type -eq 'MessageCenterMessages' }
        @($script:Traced).Count | Should -Be 1
        $script:Traced[0].Id | Should -Be 'MC|MC1325414'
        $script:Traced[0].TenantCount | Should -Be 2
        $script:Traced[0].Status | Should -Be 'Open deadline'
        $script:Traced[0].Priority | Should -Be ''

        Get-CIPPAlertMessageCenterDigest -TenantFilter 'msp.com' -InputValue @{ MCDigestDeadlineDays = 90 } | Out-Null
        $script:Traced[0].Id | Should -Be 'MC|MC1325414|due'
        $script:Traced[0].Status | Should -Be 'Deadline approaching'
        $script:Traced[0].Priority | Should -Match '^DUE IN (59|60|61) DAYS$'
    }
}
