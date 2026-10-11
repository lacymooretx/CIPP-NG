function Set-CippHuduUserPassword {
    <#
    .SYNOPSIS
    Creates or updates the Hudu password record for an M365 user.

    .DESCRIPTION
    The Hudu counterpart of Set-ITGluePassword, written for the IT Glue -> Hudu
    migration. One record per user, updated in place on every reset, so Hudu's own
    activity log is the audit trail instead of the company filling with dated
    duplicates.

    Record shape (identical to what the IT Glue importer produced from the old
    IT Glue records, so imported and new records are the same records):

      name         'M365 - <UPN>'   (the match key; derived from the UPN, not the
                                     display name, so a renamed user still matches)
      username     the UPN
      description  display name + provenance note
      company_id   the tenant's mapped Hudu company
      passwordable the user's People asset, when exactly one matches the UPN

    Hudu's `name` filter on /asset_passwords is exact-match, but Hudu silently ignores
    unknown parameters, so the result is still re-checked client-side before trusting it.

    Never throws. Returns a result object whose Success/Message explain what happened.

    Aspendora fork addition (IT Glue -> Hudu migration, 2026-10).

    .PARAMETER TenantFilter
    Tenant to resolve to a Hudu company via the Hudu extension mapping.

    .PARAMETER UserPrincipalName
    The user's UPN. Used as the record username and in the match key.

    .PARAMETER Password
    The password to store.

    .PARAMETER DisplayName
    The user's display name, recorded in the description.

    .PARAMETER Notes
    Provenance text. A default is generated when omitted.

    .PARAMETER CompanyId
    Skips the tenant lookup when the caller already resolved the company.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    # Plaintext by necessity: Hudu's REST API takes the password as a JSON string field.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'UserPrincipalName/Password are the record being written into the Hudu password vault, not an interactive logon; the API takes the value as a JSON string')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'See above')]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$Password,

        [string]$DisplayName,

        [string]$Notes,

        [string]$CompanyId
    )

    $Result = [PSCustomObject]@{
        Success       = $false
        Action        = 'none'
        PasswordId    = $null
        CompanyId     = $CompanyId
        CompanyName   = $null
        PersonAssetId = $null
        Url           = $null
        Message       = $null
    }

    try {
        $Table = Get-CIPPTable -TableName Extensionsconfig
        $ConfigEntity = Get-CIPPAzDataTableEntity @Table
        if (-not $ConfigEntity -or [string]::IsNullOrEmpty($ConfigEntity.config)) {
            $Result.Message = 'No extension configuration found.'
            return $Result
        }
        $Configuration = $ConfigEntity.config | ConvertFrom-Json -ErrorAction Stop

        if ($Configuration.Hudu.Enabled -ne $true) {
            $Result.Message = 'The Hudu integration is not enabled.'
            return $Result
        }

        if ([string]::IsNullOrWhiteSpace($CompanyId)) {
            $Company = Get-HuduCompanyId -TenantFilter $TenantFilter
            if (-not $Company) {
                $Result.Message = 'This tenant is not mapped to a Hudu company, so the password was not documented in Hudu. Map it under Settings > Integrations > Hudu.'
                Write-LogMessage -API 'Hudu' -message "No Hudu company mapping for tenant $TenantFilter - password for $UserPrincipalName was not documented." -Sev 'Warning' -tenant $TenantFilter
                return $Result
            }
            $CompanyId = $Company.CompanyId
            $Result.CompanyId = $CompanyId
            $Result.CompanyName = $Company.CompanyName
        }

        $RecordName = "M365 - $UserPrincipalName"

        if ([string]::IsNullOrWhiteSpace($Notes)) {
            $Notes = "Managed by CIPP. Last written $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC."
        }
        if (![string]::IsNullOrWhiteSpace($DisplayName)) {
            $Notes = "$DisplayName`n`n$Notes"
        }

        # --- existing record --------------------------------------------------------
        $Listed = Invoke-CippHuduRequest -Configuration $Configuration -Resource '/asset_passwords' -Params @{ company_id = $CompanyId; name = $RecordName; page_size = 100 }
        $Match = @($Listed.asset_passwords) |
            Where-Object { $_.name -eq $RecordName -and "$($_.company_id)" -eq "$CompanyId" -and $_.archived -ne $true } |
            Sort-Object { [datetime]$_.updated_at } -Descending |
            Select-Object -First 1

        # --- the person asset to attach it to ----------------------------------------
        $Person = Find-CippHuduPersonAsset -Configuration $Configuration -CompanyId $CompanyId -UserPrincipalName $UserPrincipalName
        if ($Person) { $Result.PersonAssetId = $Person.id }

        $Attributes = [ordered]@{
            company_id  = [int64]$CompanyId
            name        = $RecordName
            username    = $UserPrincipalName
            password    = $Password
            description = $Notes
        }
        # Attach when a person is found. Never detach: a record someone linked by hand
        # to an asset we cannot see (another layout, a renamed address) keeps its link.
        if ($Person) {
            $Attributes['passwordable_type'] = 'Asset'
            $Attributes['passwordable_id'] = [int64]$Person.id
        }

        if ($Match) {
            if ($PSCmdlet.ShouldProcess($RecordName, 'Update Hudu password')) {
                $Response = Invoke-CippHuduRequest -Configuration $Configuration -Method PUT -Resource "/asset_passwords/$($Match.id)" -Body @{ asset_password = $Attributes }
                $Result.Action = 'updated'
                $Result.PasswordId = $Match.id
                $Result.Url = if ($Response.asset_password.url) { $Response.asset_password.url } else { $Match.url }
            }
        } else {
            if ($PSCmdlet.ShouldProcess($RecordName, 'Create Hudu password')) {
                $Response = Invoke-CippHuduRequest -Configuration $Configuration -Method POST -Resource '/asset_passwords' -Body @{ asset_password = $Attributes }
                $Created = if ($Response.asset_password) { $Response.asset_password } else { $Response }
                $Result.Action = 'created'
                $Result.PasswordId = $Created.id
                $Result.Url = $Created.url
            }
        }

        $Result.Success = $true
        $Attached = if ($Person) { " (attached to person asset $($Person.id))" } else { ' (no matching People asset to attach to)' }
        Write-LogMessage -API 'Hudu' -message "$($Result.Action) the Hudu password record for $UserPrincipalName in company $CompanyId$Attached." -Sev 'Info' -tenant $TenantFilter
        return $Result
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        $Result.Message = "Failed to write the Hudu password record: $ErrorMessage"
        Write-LogMessage -API 'Hudu' -message "Failed to write the Hudu password record for $($UserPrincipalName): $ErrorMessage" -Sev 'Error' -tenant $TenantFilter
        return $Result
    }
}
