function Get-CIPPLeastPrivilegeRoles {
    <#
    .SYNOPSIS
        Loads the task-to-least-privileged-role lookup from Config\LeastPrivilegeRoles.json.
    .DESCRIPTION
        Returns the parsed object: roles (name -> role template id), tasks (task, role, notes) and auditRules
        (directoryAudits activity/service/category regex -> role). Sourced from Microsoft's "Least privileged roles by
        task in Microsoft Entra ID". Aspendora fork addition (Vikunja CIPP-15).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()
    # Separate Join-Path segments rather than 'Config\...': the backslash is not a separator on Linux.
    [System.IO.File]::ReadAllText((Join-Path (Join-Path $env:CIPPRootPath 'Config') 'LeastPrivilegeRoles.json')) | ConvertFrom-Json -ErrorAction Stop
}
