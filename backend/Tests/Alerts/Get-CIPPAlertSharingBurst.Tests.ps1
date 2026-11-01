# Aspendora fork (Vikunja CIPP-13): the SharingBurst alert and the report behind it (Get-CIPPSharingBurstReport), end to
# end over mocked Search-UnifiedAuditLog, message trace, sign-in log and sharing-links cache reads. Nothing in it
# writes to a tenant; these tests also pin that the remediation is only offered.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    foreach ($File in @(
            'CIPPAlerts/Public/Alerts/Get-CIPPAlertSharingBurst.ps1'
            'CIPPCore/Public/SharingLinks/Get-CIPPSharingBurstReport.ps1'
            'CIPPCore/Public/SharingLinks/Get-CIPPSharingBurstFindings.ps1'
            'CIPPCore/Public/SharingLinks/ConvertTo-CIPPSharingEvent.ps1'
            'CIPPCore/Public/SharingLinks/Measure-CIPPSendSpread.ps1'
            'CIPPCore/Public/SharingLinks/Get-CIPPSharingBurstSignInContext.ps1'
            'CIPPCore/Public/BEC/ConvertTo-CIPPBecHostAddress.ps1'
        )) { . (Join-Path $RepoRoot "Modules/$File") }

    function Search-CIPPBecAuditLog { param($TenantFilter, $StartDate, $EndDate, $Operations, $UserIds, $MaxPages) }
    function New-ExoRequest { param($tenantid, $cmdlet, $cmdParams) }
    function Get-CIPPBecMessageTrace { param($TenantFilter, $SenderAddress, $StartDate, $EndDate) }
    function Get-CIPPSharingLinks { param($TenantFilter) }
    function New-GraphGetRequest { param($uri, $tenantid, $AsApp, $noPagination) }
    function New-GraphPostRequest { param($uri, $tenantid, $type, $AsApp, $body) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }
    function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data, [switch]$Append) $data }

    $script:Lure = 'https://contoso-my.sharepoint.com/personal/victim_contoso_com/Documents/Invoice Review.one'
    function New-Record {
        param([int]$Minute, [string]$Recipient, [string]$Operation = 'AddedToSecureLink', [string]$User = 'victim@contoso.com')
        $When = (Get-Date).ToUniversalTime().AddHours(-3).AddMinutes($Minute)
        [pscustomobject]@{
            Identity     = [guid]::NewGuid().ToString()
            CreationDate = $When
            Operation    = $Operation
            UserId       = $User
            AuditData    = [pscustomobject]@{
                CreationTime          = $When.ToString('o')
                Operation             = $Operation
                UserId                = $User
                Workload              = 'OneDrive'
                ObjectId              = $script:Lure
                SourceFileName        = 'Invoice Review.one'
                SourceFileExtension   = 'one'
                SiteUrl               = 'https://contoso-my.sharepoint.com/personal/victim_contoso_com/'
                TargetUserOrGroupName = $Recipient
                TargetUserOrGroupType = 'Guest'
                ClientIP              = '52.108.0.10'
            }
        }
    }
}

Describe 'Get-CIPPAlertSharingBurst' {
    BeforeEach {
        $script:Records = @(1..30 | ForEach-Object { New-Record -Minute $_ -Recipient "person$_@outside$($_ % 3).example" })
        $script:SignIns = @()
        $script:Cache = @()
        Mock Search-CIPPBecAuditLog { [pscustomobject]@{ Records = $script:Records; Complete = $true; Cap = $null; Pages = 1 } }
        Mock New-ExoRequest { @([pscustomobject]@{ DomainName = 'contoso.com' }) } -ParameterFilter { $cmdlet -eq 'Get-AcceptedDomain' }
        Mock Get-CIPPBecMessageTrace { [pscustomobject]@{ Rows = @(); Complete = $true } }
        Mock Get-CIPPSharingLinks { $script:Cache }
        Mock New-GraphGetRequest { $script:SignIns } -ParameterFilter { $uri -match 'signIns' }
        Mock New-GraphGetRequest { [pscustomobject]@{ id = 'item1'; name = 'Invoice Review.one'; parentReference = @{ driveId = 'drive1' }; permissions = @([pscustomobject]@{ id = 'perm-anyone'; link = @{ scope = 'anonymous' } }, [pscustomobject]@{ id = 'perm-inherited'; link = @{ scope = 'organization' }; inheritedFrom = @{ id = 'x' } }) } } -ParameterFilter { $uri -match '/shares/' }
        Mock New-GraphPostRequest { throw 'must not write' }
        Mock Write-LogMessage { }
    }

    It 'raises a High UserBurst for a OneNote lure shared with 30 outsiders in half an hour' {
        $R = @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com')
        $R.Count | Should -Be 1
        $R[0].Detection | Should -Be 'UserBurst'
        $R[0].Severity | Should -Be 'High'
        $R[0].Account | Should -Be 'victim@contoso.com'
        $R[0].ExternalRecipients | Should -Be 30
        $R[0].Id | Should -Match '^UserBurst\|victim@contoso\.com\|\d{8}$'
        $R[0].PSObject.Properties.Name | Should -Not -Contain 'Remediation'
    }

    It 'offers the ready parameters for the existing actions and never calls a write' {
        $R = @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com')
        $R[0].ReadyActions | Should -Match 'ExecSetOneDriveSharing \{"tenantFilter":"contoso.com","UPN":"victim@contoso.com","SharingCapability":"Disabled"\}'
        $R[0].ReadyActions | Should -Match 'ExecBulkRemoveSharingLinks \{"tenantFilter":"contoso.com","SiteUrl":"https://contoso-my.sharepoint.com/personal/victim_contoso_com/","Scope":"External"\}'
        $R[0].ReadyActions | Should -Match 'resolve=true'
        Should -Invoke New-GraphPostRequest -Times 0
    }

    It 'takes ExecRemoveSharingLink ids from the sharing-links cache when the item is there' {
        $script:Cache = @([pscustomobject]@{ id = 'c1'; itemUrl = 'https://contoso-my.sharepoint.com/personal/victim_contoso_com/Documents/Invoice%20Review.one'; classification = 'Anonymous'; driveId = 'd1'; itemId = 'i1'; permissionId = 'p1'; fileName = 'Invoice Review.one' })
        $R = @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com')
        $R[0].ReadyActions | Should -Match 'ExecRemoveSharingLink \{"tenantFilter":"contoso.com","DriveId":"d1","ItemId":"i1","PermissionId":"p1"'
        $R[0].ReadyActions | Should -Not -Match 'resolve=true'
    }

    It 'includes a preceding risky sign-in' {
        $script:SignIns = @([pscustomobject]@{ createdDateTime = (Get-Date).ToUniversalTime().AddHours(-5).ToString('o'); ipAddress = '198.51.100.9'; location = @{ city = 'Lagos'; countryOrRegion = 'NG' }; appDisplayName = 'OfficeHome'; riskLevelDuringSignIn = 'medium'; riskState = 'atRisk'; riskEventTypes_v2 = @('unfamiliarFeatures') })
        $R = @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com')
        $R[0].PrecedingSignIn | Should -Match '198\.51\.100\.9'
        $R[0].PrecedingSignIn | Should -Match 'risk medium'
    }

    It 'says so when sign-in logs are not licensed instead of failing' {
        Mock New-GraphGetRequest { throw 'Authentication_RequestFromNonPremiumTenantOrB2CTenant' } -ParameterFilter { $uri -match 'signIns' }
        $R = @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com')
        $R.Count | Should -Be 1
        $R[0].PrecedingSignIn | Should -Match 'Entra ID P1'
    }

    It 'raises LinkMailBlast for an anyone link followed by a mail spike, below the sharing threshold' {
        $script:Records = @(New-Record -Minute 1 -Recipient $null -Operation 'AnonymousLinkCreated')
        $script:TraceAt = (Get-Date).ToUniversalTime().AddHours(-1).ToString('o')
        Mock Get-CIPPBecMessageTrace { [pscustomobject]@{ Rows = @(1..40 | ForEach-Object { [pscustomobject]@{ RecipientAddress = "contact$_@elsewhere.example"; Received = $script:TraceAt } }); Complete = $true } }
        $R = @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com')
        $R.Count | Should -Be 1
        $R[0].Detection | Should -Be 'LinkMailBlast'
        $R[0].Severity | Should -Be 'High'
        $R[0].SendSpread | Should -Match 'SPIKE'
    }

    It 'raises nothing for ordinary sharing' {
        $script:Records = @(1..5 | ForEach-Object { New-Record -Minute $_ -Recipient "person$_@outside.example" })
        @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com').Count | Should -Be 0
    }

    It 'honours the alert inputs' {
        $script:Records = @(1..8 | ForEach-Object { New-Record -Minute $_ -Recipient "person$_@outside.example" })
        $R = @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com' -InputValue ([pscustomobject]@{ SharingBurstRecipients = '5'; SharingBurstFileRecipients = '100' }))
        $R.Count | Should -Be 1
        @(Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com' -InputValue ([pscustomobject]@{ SharingBurstRecipients = '5'; SharingBurstAllowList = 'victim@contoso.com' })).Count | Should -Be 0
    }

    It 'logs an incomplete audit search' {
        Mock Search-CIPPBecAuditLog { [pscustomobject]@{ Records = @(); Complete = $false; Cap = 'stopped after 0 record(s) on a page error: timeout' } }
        $null = Get-CIPPAlertSharingBurst -TenantFilter 'contoso.com'
        Should -Invoke Write-LogMessage -ParameterFilter { $message -match 'incomplete' } -Times 1
    }
}

Describe 'Get-CIPPSharingBurstReport -Resolve' {
    BeforeEach {
        $script:Records = @(1..30 | ForEach-Object { New-Record -Minute $_ -Recipient "person$_@outside.example" })
        Mock Search-CIPPBecAuditLog { [pscustomobject]@{ Records = $script:Records; Complete = $true } }
        Mock New-ExoRequest { @([pscustomobject]@{ DomainName = 'contoso.com' }) }
        Mock Get-CIPPBecMessageTrace { [pscustomobject]@{ Rows = @() } }
        Mock Get-CIPPSharingLinks { @() }
        Mock New-GraphGetRequest { @() } -ParameterFilter { $uri -match 'signIns' }
        Mock New-GraphGetRequest { [pscustomobject]@{ id = 'item1'; name = 'Invoice Review.one'; parentReference = @{ driveId = 'drive1' }; permissions = @([pscustomobject]@{ id = 'perm-anyone'; link = @{ scope = 'anonymous' } }, [pscustomobject]@{ id = 'perm-inherited'; link = @{ scope = 'organization' }; inheritedFrom = @{ id = 'x' } }, [pscustomobject]@{ id = 'perm-guest'; grantedToV2 = @{ user = @{ email = 'person1@outside.example' } } }) } } -ParameterFilter { $uri -match '/shares/' }
        Mock New-GraphPostRequest { throw 'must not write' }
    }

    It 'resolves link and invitation permissions live, skips inherited ones, and writes nothing' {
        $Report = Get-CIPPSharingBurstReport -TenantFilter 'contoso.com' -Resolve
        $Remove = @($Report.Findings[0].Remediation | Where-Object Action -EQ 'ExecRemoveSharingLink')
        @($Remove | ForEach-Object { $_.Body['PermissionId'] }) | Should -Be @('perm-anyone', 'perm-guest')
        $Remove[0].Body['DriveId'] | Should -Be 'drive1'
        Should -Invoke New-GraphGetRequest -ParameterFilter { $uri -match '/shares/u!' -and $AsApp -eq $true } -Times 1
        Should -Invoke New-GraphPostRequest -Times 0
    }
}
