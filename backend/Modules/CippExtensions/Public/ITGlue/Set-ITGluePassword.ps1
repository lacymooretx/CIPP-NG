function Set-ITGluePassword {
    <#
    .SYNOPSIS
    Creates or updates a password record in IT Glue for an M365 user.

    .DESCRIPTION
    Writes one record per user and updates it in place on every subsequent reset, so
    IT Glue's own version history becomes the audit trail instead of the org filling
    with dated duplicates. Records are matched on the deterministic name 'M365 - <UPN>'
    within the mapped organization.

    Aspendora fork addition.

    .PARAMETER TenantFilter
    Tenant to resolve to an IT Glue organization via the extension mapping.

    .PARAMETER UserPrincipalName
    The user's UPN. Used as both the record username and the match key.

    .PARAMETER Password
    The password to store.

    .PARAMETER DisplayName
    The user's display name, recorded in the notes.

    .PARAMETER Notes
    Provenance text for the record. A default is generated when omitted.

    .PARAMETER OrganizationId
    Skips the tenant lookup when the caller already resolved the organization.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    # Plaintext by necessity: this writes the password into IT Glue's password vault via its
    # REST API, which takes it as a JSON string field. Converting to SecureString here would
    # only be undone before the request is built.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'UserPrincipalName/Password are the record being written into the IT Glue password vault, not an interactive logon; the API takes the value as a JSON string')]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$Password,

        [string]$DisplayName,

        [string]$Notes,

        [string]$OrganizationId
    )

    $Result = [PSCustomObject]@{
        Success          = $false
        Action           = 'none'
        PasswordId       = $null
        OrganizationId   = $OrganizationId
        OrganizationName = $null
        Url              = $null
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
                $Result.Message = "This tenant is not mapped to an IT Glue organization, so the password was not documented. Map it under Settings > Integrations > IT Glue."
                Write-LogMessage -API 'ITGlue' -message "No IT Glue organization mapping for tenant $TenantFilter - password for $UserPrincipalName was not documented." -Sev 'Warning' -tenant $TenantFilter
                return $Result
            }
            $OrganizationId = $Org.OrganizationId
            $Result.OrganizationId = $OrganizationId
            $Result.OrganizationName = $Org.OrganizationName
        }

        Connect-ITGlueAPI -Configuration $Configuration

        $RecordName = "M365 - $UserPrincipalName"

        if ([string]::IsNullOrWhiteSpace($Notes)) {
            $Notes = "Managed by CIPP. Last written $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC."
        }
        if (![string]::IsNullOrWhiteSpace($DisplayName)) {
            $Notes = "$DisplayName`n`n$Notes"
        }

        $Attributes = @{
            'name'     = $RecordName
            'username' = $UserPrincipalName
            'password' = $Password
            'notes'    = $Notes
        }

        $CategoryId = Get-ITGluePasswordCategoryId -Name 'Office 365'
        if ($CategoryId) { $Attributes['password-category-id'] = $CategoryId }

        # filter[name] is an exact match, which is why the record name is derived from the
        # UPN rather than the display name -- a renamed user must still match its record.
        $EncodedName = [System.Uri]::EscapeDataString($RecordName)
        $Existing = Invoke-ITGlueRequest -Path "/passwords?filter[organization_id]=$OrganizationId&filter[name]=$EncodedName" -AllPages
        $Match = $Existing | Where-Object { $_.attributes.name -eq $RecordName } | Select-Object -First 1

        if ($Match) {
            if ($PSCmdlet.ShouldProcess($RecordName, 'Update IT Glue password')) {
                $Body = @{ data = @{ type = 'passwords'; attributes = $Attributes } }
                $Response = Invoke-ITGlueRequest -Path "/passwords/$($Match.id)" -Method PATCH -Body $Body -Raw
                $Result.Action = 'updated'
                $Result.PasswordId = $Match.id
                $Result.Url = $Response.data.attributes.'resource-url'
            }
        } else {
            if ($PSCmdlet.ShouldProcess($RecordName, 'Create IT Glue password')) {
                $Body = @{ data = @{ type = 'passwords'; attributes = $Attributes } }
                $Response = Invoke-ITGlueRequest -Path "/organizations/$OrganizationId/relationships/passwords" -Method POST -Body $Body -Raw
                $Created = if ($Response.data -is [array]) { $Response.data[0] } else { $Response.data }
                $Result.Action = 'created'
                $Result.PasswordId = $Created.id
                $Result.Url = $Created.attributes.'resource-url'
            }
        }

        $Result.Success = $true
        Write-LogMessage -API 'ITGlue' -message "$($Result.Action) the IT Glue password record for $UserPrincipalName in organization $OrganizationId." -Sev 'Info' -tenant $TenantFilter
        return $Result
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        $Result.Message = "Failed to write the IT Glue password record: $ErrorMessage"
        Write-LogMessage -API 'ITGlue' -message "Failed to write the IT Glue password record for $($UserPrincipalName): $ErrorMessage" -Sev 'Error' -tenant $TenantFilter
        return $Result
    }
}
