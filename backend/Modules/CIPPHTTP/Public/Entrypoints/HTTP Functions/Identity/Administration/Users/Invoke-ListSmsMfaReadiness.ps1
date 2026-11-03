function Invoke-ListSmsMfaReadiness {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .SYNOPSIS
        SMS/voice MFA readiness: which users would break if SMS or voice MFA were disabled
    .DESCRIPTION
        Single tenant: reads the MFA registration report (Entra ID P1), the tenant's users and the authentication
        methods policy and returns Summary (ReadyToDisableSms, ReadyToDisableVoice, ReadyToDisableBoth, coverage of
        Authenticator/passkey/Windows Hello, counts), Users (every enabled member with Category PhoneOnly,
        DefaultPhone, NoMfa or Ready), Findings (admins on SMS/voice or without MFA, users relying only on SMS/voice,
        users without MFA, readiness), RegisteredByMethod and Errors.
        Retirement of Microsoft-provided SMS/voice (CIPP-46): each user with a phone method carries RetirementDate
        (2027-02-01, or 2027-07-01 for Global Administrators and external users), DaysRemaining (US Central) and
        RetirementBasis; Guests lists enabled guests whose only MFA is SMS/voice; Summary adds per-date counts,
        NearestDeadline, ReadyByFeb2027, PasskeyDynamicMigrationOptOut (true/false/unknown), Passkey (FIDO2)
        state and scope, registration campaign state and target, and TelephonyProvider.
        CIPP-53: Summary adds CaWouldBlockRegistration (Yes, ReportOnly, No or Unknown), the matching policy names,
        CaBlockPhoneOnlyUsers and RegisterSecurityInfoPolicy.
        tenantFilter=AllTenants: returns the stored per-tenant summaries (Results) written by the last single-tenant
        view or SmsMfaReliance alert run, with CheckedUtc; tenants never checked are not listed.
        Report only: nothing in the tenant is changed. Aspendora fork addition (Vikunja CIPP-6).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'tenantFilter is required.' } })
    }
    try {
        if ($TenantFilter -eq 'AllTenants') {
            $Table = Get-CIPPTable -tablename 'SmsMfaReadiness'
            # Only tenants this caller may see.
            $AllowedIds = @(Test-CIPPAccess -Request $Request -TenantList)
            $Allowed = @(Get-Tenants | Where-Object { $AllowedIds -contains 'AllTenants' -or $_.customerId -in $AllowedIds } | ForEach-Object { [string]$_.defaultDomainName })
            $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Summary'" | Where-Object { $_.RowKey -in $Allowed } |
                    Select-Object Tenant, CheckedUtc, ReadyToDisableSms, ReadyToDisableVoice, ReadyToDisableBoth, SmsState, VoiceState, UsersEnabled, CoveragePercent, PhoneOnly, SmsDependent, VoiceDependent, DefaultPhone, NoMfa, AdminsPhoneOnly, AdminsNoMfa, Errors, Warnings,
                    ReadyByFeb2027, RetirementFebruary2027, RetirementJuly2027, NearestDeadline, NearestDeadlineDaysRemaining, PasskeyDynamicMigrationOptOut, PasskeyState, PasskeyScope, RegistrationCampaignState, RegistrationCampaignMethods, RegistrationCampaignOk, TelephonyProvider, CaWouldBlockRegistration, CaBlockEnforcedPolicies, CaBlockReportOnlyPolicies, CaBlockPhoneOnlyUsers, RegisterSecurityInfoPolicy |
                    Sort-Object Tenant)
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = $Rows } })
        }
        $Report = Get-CIPPSmsMfaReadiness -TenantFilter $TenantFilter
        Save-CIPPSmsMfaReadinessSummary -TenantFilter $TenantFilter -Report $Report
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
