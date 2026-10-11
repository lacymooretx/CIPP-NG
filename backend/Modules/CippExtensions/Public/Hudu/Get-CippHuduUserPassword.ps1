function Get-CippHuduUserPassword {
    <#
    .SYNOPSIS
    Reads back the Hudu password record for an M365 user.

    .DESCRIPTION
    The Hudu counterpart of Get-ITGluePassword, used by the welcome packet. Same two
    lookups, in order of trust:

      1. The deterministic name 'M365 - <UPN>' in the tenant's mapped company. This is
         what Set-CippHuduUserPassword writes (and what the IT Glue import carried over),
         so a hit here is certainly our record.
      2. Any live record in the company whose username equals the UPN. Flagged
         IsPortalRecord = $false so the operator is told to check it before printing.

    Returns the same result shape as Get-ITGluePassword, so the caller can use either.
    Never throws.

    Aspendora fork addition (IT Glue -> Hudu migration, 2026-10).

    .PARAMETER TenantFilter
    Tenant to resolve to a Hudu company via the Hudu extension mapping.

    .PARAMETER UserPrincipalName
    The user's UPN.

    .PARAMETER CompanyId
    Skips the tenant lookup when the caller already resolved the company.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [string]$CompanyId
    )

    $Result = [PSCustomObject]@{
        Success          = $false
        Password         = $null
        PasswordId       = $null
        Name             = $null
        Url              = $null
        UpdatedAtUtc     = $null
        OrganizationId   = $CompanyId
        OrganizationName = $null
        IsPortalRecord   = $false
        OtherMatchCount  = 0
        Source           = 'Hudu'
        Message          = $null
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
                $Result.Message = 'This tenant is not mapped to a Hudu company. Map it under Settings > Integrations > Hudu.'
                return $Result
            }
            $CompanyId = $Company.CompanyId
            $Result.OrganizationId = $CompanyId
            $Result.OrganizationName = $Company.CompanyName
        }

        $RecordName = "M365 - $UserPrincipalName"
        $Listed = Invoke-CippHuduRequest -Configuration $Configuration -Resource '/asset_passwords' -Params @{ company_id = $CompanyId; name = $RecordName; page_size = 100 }
        $Live = { param($Rows) @($Rows | Where-Object { "$($_.company_id)" -eq "$CompanyId" -and $_.archived -ne $true }) }
        $ByName = @(& $Live @($Listed.asset_passwords) | Where-Object { $_.name -eq $RecordName })

        if ($ByName.Count -gt 0) {
            $Result.IsPortalRecord = $true
            $Candidates = $ByName
        } else {
            # No portal record: fall back to the username. Hudu has no username filter,
            # so page the company's passwords and compare here.
            $All = [System.Collections.Generic.List[object]]::new()
            $Page = 1
            do {
                $Response = Invoke-CippHuduRequest -Configuration $Configuration -Resource '/asset_passwords' -Params @{ company_id = $CompanyId; page = $Page; page_size = 1000 }
                $Batch = @($Response.asset_passwords)
                foreach ($Row in $Batch) { $All.Add($Row) }
                $Page++
            } while ($Batch.Count -eq 1000 -and $Page -le 20)

            $Candidates = @(& $Live $All | Where-Object { $_.username -eq $UserPrincipalName })
            if ($Candidates.Count -eq 0) {
                $Result.Message = "No Hudu password record found for $UserPrincipalName - neither `"$RecordName`" nor any record with that username. Reset the password to create one."
                return $Result
            }
        }

        # Most recently updated wins; several usually means a stale duplicate.
        $Match = $Candidates | Sort-Object { [datetime]$_.updated_at } -Descending | Select-Object -First 1
        $Result.OtherMatchCount = $Candidates.Count - 1

        # The list normally carries the value; show the single record if it did not.
        if ([string]::IsNullOrEmpty($Match.password)) {
            $Shown = Invoke-CippHuduRequest -Configuration $Configuration -Resource "/asset_passwords/$($Match.id)"
            $Match = if ($Shown.asset_password) { $Shown.asset_password } else { $Shown }
        }

        $Result.PasswordId = $Match.id
        $Result.Name = $Match.name
        $Result.Url = $Match.url
        if ($Match.updated_at) { $Result.UpdatedAtUtc = ([datetime]$Match.updated_at).ToUniversalTime() }

        if ([string]::IsNullOrEmpty($Match.password)) {
            $Result.Message = 'The Hudu record was found but returned no password value. Check that the Hudu API key is allowed to read passwords.'
            return $Result
        }

        $Result.Password = $Match.password
        $Result.Success = $true

        if ($Result.OtherMatchCount -gt 0) {
            $Result.Message = "$($Result.OtherMatchCount + 1) Hudu records match $UserPrincipalName. Using the most recently updated one - check it is the right record before printing."
        } elseif (-not $Result.IsPortalRecord) {
            $Result.Message = 'Matched on the username rather than the portal naming convention, so confirm it is the right record before printing.'
        }

        return $Result
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        $Result.Message = "Failed to read the Hudu password record: $ErrorMessage"
        Write-LogMessage -API 'Hudu' -message "Failed to read the Hudu password record for $($UserPrincipalName): $ErrorMessage" -Sev 'Error' -tenant $TenantFilter
        return $Result
    }
}
