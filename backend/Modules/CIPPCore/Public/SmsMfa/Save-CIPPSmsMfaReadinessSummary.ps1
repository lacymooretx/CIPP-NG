function Save-CIPPSmsMfaReadinessSummary {
    <#
    .SYNOPSIS
        Stores the latest SMS/voice MFA readiness summary for a tenant, for the AllTenants view.
    .DESCRIPTION
        Table SmsMfaReadiness, PartitionKey 'Summary', RowKey = tenant. Written by ListSmsMfaReadiness and the
        SmsMfaReliance alert after a complete (error-free) collection, so ListSmsMfaReadiness?tenantFilter=AllTenants
        can answer from storage instead of reading every tenant live. This is CIPP's own table: nothing in the
        tenant is changed. Aspendora fork addition (Vikunja CIPP-6).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)]$Report
    )
    if (-not $Report.Summary -or @($Report.Errors).Count -gt 0) { return }
    try {
        $Table = Get-CIPPTable -tablename 'SmsMfaReadiness'
        $S = $Report.Summary
        Add-CIPPAzDataTableEntity @Table -Force -Entity @{
            PartitionKey           = 'Summary'
            RowKey                 = [string]$TenantFilter
            Tenant                 = [string]$TenantFilter
            CheckedUtc             = [datetime]::UtcNow.ToString('o')
            UsersEnabled           = [int]$S.UsersEnabled
            CoveragePercent        = [string]$S.CoveragePercent
            PhoneOnly              = [int]$S.PhoneOnly
            SmsDependent           = [int]$S.SmsDependent
            VoiceDependent         = [int]$S.VoiceDependent
            DefaultPhone           = [int]$S.DefaultPhone
            NoMfa                  = [int]$S.NoMfa
            AdminsPhoneOnly        = [int]$S.AdminsPhoneOnly
            AdminsNoMfa            = [int]$S.AdminsNoMfa
            SmsState               = [string]$S.SmsState
            VoiceState             = [string]$S.VoiceState
            ReadyToDisableSms      = [bool]$S.ReadyToDisableSms
            ReadyToDisableVoice    = [bool]$S.ReadyToDisableVoice
            ReadyToDisableBoth     = [bool]$S.ReadyToDisableBoth
            Errors                 = @($Report.Findings | Where-Object Severity -EQ 'Error').Count
            Warnings               = @($Report.Findings | Where-Object Severity -EQ 'Warning').Count
        } | Out-Null
    } catch {
        Write-Information "SMS MFA readiness: could not store the summary for $($TenantFilter): $($_.Exception.Message)"
    }
}
