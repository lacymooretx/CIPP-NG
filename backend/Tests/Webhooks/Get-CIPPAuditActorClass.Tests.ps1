# Aspendora fork (Vikunja CIPP-32): who performed an audit-logged change. Actor strings below follow the real records:
# the GDAP Exchange shape was seen in production on 2026-10-29 (customer domain, then the PARTNER tenant id and the
# partner user's object id), the NT SERVICE actor is Exchange re-applying its own config.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Webhooks/Get-CIPPAuditActorClass.ps1')
    $script:Customer = 'e75dcc09-5152-44ca-8550-f8f22fa4cfa3'
    $script:Msp = '8d6a4ab1-ca4b-4899-b961-c13b1fe0323d'
    $script:Other = '11111111-2222-4333-8444-555555555555'
    $script:CippApp = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
    function New-Rec {
        param([string]$UserId, [string]$UserKey, $UserType = 2, [hashtable]$Extra = @{})
        $R = [ordered]@{ OrganizationId = $script:Customer; UserId = $UserId; UserKey = ($UserKey ? $UserKey : $UserId); UserType = $UserType; AppId = ''; ClientAppId = '' }
        foreach ($K in $Extra.Keys) { $R[$K] = $Extra[$K] }
        [pscustomobject]$R
    }
}

Describe 'Get-CIPPAuditActorClass' {
    It 'classifies a GDAP admin of the MSP partner tenant as MSP' {
        $R = Get-CIPPAuditActorClass -Record (New-Rec "contoso.onmicrosoft.com\tenant: $script:Msp, object: ca2a58ac-0202-49db-b889-193fd5ed0bad") -MappedUserId 'tech@fabrikampartner.com' -MspTenantIds @($script:Msp)
        $R.Class | Should -Be 'MSP'
        $R.IsMsp | Should -BeTrue
        $R.Detail | Should -Match 'tech@fabrikampartner.com'
    }

    It 'classifies a GDAP admin of a different partner tenant as OtherPartner, not MSP' {
        $R = Get-CIPPAuditActorClass -Record (New-Rec "contoso.onmicrosoft.com\tenant: $script:Other, object: ca2a58ac-0202-49db-b889-193fd5ed0bad") -MspTenantIds @($script:Msp)
        $R.Class | Should -Be 'OtherPartner'
        $R.IsMsp | Should -BeFalse
    }

    It 'treats any partner as the MSP when no MSP tenant id is configured' {
        (Get-CIPPAuditActorClass -Record (New-Rec "contoso.onmicrosoft.com\tenant: $script:Other, object: ca2a58ac-0202-49db-b889-193fd5ed0bad")).Class | Should -Be 'MSP'
    }

    It 'classifies a customer admin as Tenant' {
        $R = Get-CIPPAuditActorClass -Record (New-Rec 'admin@contoso.com' '10032000ABCDEF12') -MspTenantIds @($script:Msp)
        $R.Class | Should -Be 'Tenant'
        $R.IsMsp | Should -BeFalse
    }

    It 'classifies Exchange service actors as Microsoft' {
        (Get-CIPPAuditActorClass -Record (New-Rec 'NT SERVICE\MSExchangeAdminApiNetCore (Microsoft.Exchange.AdminApi.NetCore)')).Class | Should -Be 'Microsoft'
        (Get-CIPPAuditActorClass -Record (New-Rec 'NT AUTHORITY\SYSTEM (Microsoft.Exchange.ServiceHost)')).Class | Should -Be 'Microsoft'
        (Get-CIPPAuditActorClass -Record (New-Rec 'something' -UserType 4)).Class | Should -Be 'Microsoft'
    }

    It 'classifies the CIPP application acting app-only as CIPP' {
        $R = Get-CIPPAuditActorClass -Record (New-Rec 'ServicePrincipal_x' -UserType 5 -Extra @{ AppId = $script:CippApp }) -CippAppId $script:CippApp -MspTenantIds @($script:Msp)
        $R.Class | Should -Be 'CIPP'
        $R.IsMsp | Should -BeTrue
        $Mapped = [pscustomobject]@{ appId = $script:CippApp; displayName = 'CIPP-SAM' }
        (Get-CIPPAuditActorClass -Record (New-Rec 'ServicePrincipal_x' -UserType 5) -MappedUserId $Mapped -CippAppId $script:CippApp).Class | Should -Be 'CIPP'
    }

    It 'classifies any other service principal as App' {
        (Get-CIPPAuditActorClass -Record (New-Rec 'ServicePrincipal_6f1c2a4e-1b0e-4f6e-9a55-0d6a3f1e2b7c' -UserType 5) -CippAppId $script:CippApp -MspTenantIds @($script:Msp)).Class | Should -Be 'App'
    }

    It 'uses the Entra ActorContextId for a partner admin acting in Entra' {
        $Rec = New-Rec 'tech@fabrikampartner.com' -Extra @{ ActorContextId = $script:Msp }
        (Get-CIPPAuditActorClass -Record $Rec -MspTenantIds @($script:Msp)).Class | Should -Be 'MSP'
        $Own = New-Rec 'admin@contoso.com' -Extra @{ ActorContextId = $script:Customer }
        (Get-CIPPAuditActorClass -Record $Own -MspTenantIds @($script:Msp)).Class | Should -Be 'Tenant'
    }

    It 'recognises a legacy partner UPN only when the partner user is known' {
        $Rec = New-Rec 'user_ca2a58ac020249dbb889193fd5ed0bad@fabrikampartner.onmicrosoft.com'
        (Get-CIPPAuditActorClass -Record $Rec -MspTenantIds @($script:Msp) -PartnerUserLookup @{ 'ca2a58ac-0202-49db-b889-193fd5ed0bad' = @{} }).Class | Should -Be 'MSP'
        (Get-CIPPAuditActorClass -Record $Rec -MspTenantIds @($script:Msp) -PartnerUserLookup @{}).Class | Should -Be 'OtherPartner'
    }
}
