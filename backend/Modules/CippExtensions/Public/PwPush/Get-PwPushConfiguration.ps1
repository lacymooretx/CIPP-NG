function Get-PwPushConfiguration {
    <#
    .SYNOPSIS
    Returns the PwPush extension configuration.

    .DESCRIPTION
    Reads the Extensionsconfig table and returns the PWPush block, or $null when the
    extension is missing, unparseable or disabled. The full parsed configuration is
    attached as a FullConfiguration property so callers can reach the CFZTNA settings
    without re-reading the table.

    Aspendora fork addition.
    #>
    [CmdletBinding()]
    param()

    try {
        $Table = Get-CIPPTable -TableName Extensionsconfig
        $ConfigEntity = Get-CIPPAzDataTableEntity @Table

        if (-not $ConfigEntity -or [string]::IsNullOrEmpty($ConfigEntity.config)) {
            return $null
        }

        $ParsedConfig = $ConfigEntity.config | ConvertFrom-Json -ErrorAction Stop
        $Configuration = $ParsedConfig.PWPush

        if (-not $Configuration -or $Configuration.Enabled -ne $true) {
            return $null
        }

        $Configuration | Add-Member -NotePropertyName 'FullConfiguration' -NotePropertyValue $ParsedConfig -Force
        return $Configuration
    } catch {
        Write-LogMessage -API 'PwPush' -message "Failed to read the PwPush configuration: $($_.Exception.Message)" -Sev 'Error'
        return $null
    }
}
