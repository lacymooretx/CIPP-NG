function Get-ITGluePassword {
    <#
    .SYNOPSIS
    Reads back the IT Glue password record for an M365 user.

    .DESCRIPTION
    The counterpart to Set-ITGluePassword. Finds the record that function writes --
    'M365 - <UPN>' in the tenant's mapped organization -- and returns the stored
    password so the welcome packet can print a credential that is already live on
    the account, without resetting it.

    Two lookups, in order of trust:

      1. The deterministic portal name 'M365 - <UPN>'. This is what Set-ITGluePassword
         writes, so a hit here is certainly our record.
      2. Any record in the organization whose username equals the UPN. Catches
         accounts documented by hand or by another tool before CIPP took over. The
         result is flagged IsPortalRecord = $false so the caller can tell the operator
         to check it before printing.

    IT Glue omits the password value from list responses by design, so a match is
    followed by a show request for that single record. If the show comes back without
    a value, the API key is missing Password Access -- a configuration problem, not an
    empty password, and it is reported as such.

    Never throws. Callers get a result object whose Success and Message explain what
    happened, because every failure mode here has a different fix and 'something went
    wrong' would send an operator hunting.

    Aspendora fork addition.

    .PARAMETER TenantFilter
    Tenant to resolve to an IT Glue organization via the extension mapping.

    .PARAMETER UserPrincipalName
    The user's UPN. Both the record match key and the username fallback.

    .PARAMETER OrganizationId
    Skips the tenant lookup when the caller already resolved the organization.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [string]$OrganizationId
    )

    $Result = [PSCustomObject]@{
        Success          = $false
        Password         = $null
        PasswordId       = $null
        Name             = $null
        Url              = $null
        UpdatedAtUtc     = $null
        OrganizationId   = $OrganizationId
        OrganizationName = $null
        IsPortalRecord   = $false
        OtherMatchCount  = 0
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

        if ($Configuration.ITGlue.Enabled -ne $true) {
            $Result.Message = 'The IT Glue integration is not enabled.'
            return $Result
        }

        if ([string]::IsNullOrWhiteSpace($OrganizationId)) {
            $Org = Get-ITGlueOrganizationId -TenantFilter $TenantFilter
            if (-not $Org) {
                $Result.Message = 'This tenant is not mapped to an IT Glue organization. Map it under Settings > Integrations > IT Glue.'
                return $Result
            }
            $OrganizationId = $Org.OrganizationId
            $Result.OrganizationId = $OrganizationId
            $Result.OrganizationName = $Org.OrganizationName
        }

        Connect-ITGlueAPI -Configuration $Configuration

        $RecordName = "M365 - $UserPrincipalName"
        $EncodedName = [System.Uri]::EscapeDataString($RecordName)
        $Candidates = Invoke-ITGlueRequest -Path "/passwords?filter[organization_id]=$OrganizationId&filter[name]=$EncodedName" -AllPages
        $Match = $Candidates | Where-Object { $_.attributes.name -eq $RecordName } | Select-Object -First 1

        if ($Match) {
            $Result.IsPortalRecord = $true
        } else {
            # No portal record. Fall back to the username, which is not an exact-match
            # filter in IT Glue, so compare in PowerShell rather than trusting the API.
            $EncodedUpn = [System.Uri]::EscapeDataString($UserPrincipalName)
            $ByUsername = Invoke-ITGlueRequest -Path "/passwords?filter[organization_id]=$OrganizationId&filter[username]=$EncodedUpn" -AllPages
            $Matches = @($ByUsername | Where-Object { $_.attributes.username -eq $UserPrincipalName })

            if ($Matches.Count -eq 0) {
                $Result.Message = "No IT Glue password record found for $UserPrincipalName - neither `"$RecordName`" nor any record with that username. Reset the password to create one."
                return $Result
            }

            # Most recently updated wins. Several records with one username usually means
            # a stale duplicate, and the newest is the one someone last touched.
            $Match = $Matches | Sort-Object { [datetime]$_.attributes.'updated-at' } -Descending | Select-Object -First 1
            $Result.OtherMatchCount = $Matches.Count - 1
        }

        # The list response never carries the password; show the single record for it.
        $Record = Invoke-ITGlueRequest -Path "/passwords/$($Match.id)" -Raw
        $Attributes = $Record.data.attributes

        $Result.PasswordId = $Match.id
        $Result.Name = $Attributes.name
        $Result.Url = $Attributes.'resource-url'
        if ($Attributes.'updated-at') {
            $Result.UpdatedAtUtc = ([datetime]$Attributes.'updated-at').ToUniversalTime()
        }

        if ([string]::IsNullOrEmpty($Attributes.password)) {
            $Result.Message = 'The IT Glue record was found but returned no password value. This usually means the IT Glue API key does not have Password Access enabled.'
            return $Result
        }

        $Result.Password = $Attributes.password
        $Result.Success = $true

        if ($Result.OtherMatchCount -gt 0) {
            $Result.Message = "$($Result.OtherMatchCount + 1) IT Glue records have the username $UserPrincipalName. Using the most recently updated one - check it is the right record before printing."
        } elseif (-not $Result.IsPortalRecord) {
            $Result.Message = 'Matched on the username rather than the portal naming convention, so confirm it is the right record before printing.'
        }

        return $Result
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        $Result.Message = "Failed to read the IT Glue password record: $ErrorMessage"
        Write-LogMessage -API 'ITGlue' -message "Failed to read the IT Glue password record for $($UserPrincipalName): $ErrorMessage" -Sev 'Error' -tenant $TenantFilter
        return $Result
    }
}
