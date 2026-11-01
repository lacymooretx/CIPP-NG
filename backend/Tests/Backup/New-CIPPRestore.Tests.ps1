# Aspendora fork (Vikunja CIPP-23): the default restore path must be untouched; safe restore is opt-in only.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    function Write-LogMessage { param($headers, $API, $message, $Sev, $tenant, $LogData) }
    function New-CIPPRestoreTask { param($Task, $TenantFilter, $backup, $overwrite, $APINAME, $Headers) "restored $Task" }
    function New-CIPPSafeRestore { param($TenantFilter, $BackupName, $Types, $Headers, $APIName) 'safe' }
    . (Join-Path $BackendRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $BackendRoot 'Modules/CIPPCore/Public/New-CIPPRestore.ps1')

    # What the restore drawer has always sent.
    function New-ExistingRestoreValues {
        [pscustomobject]@{
            backup = 'contoso.com_2026-10-31-0100'; users = $true; groups = $false; ca = $true; intuneconfig = $true
            intunecompliance = $false; intuneprotection = $false; antispam = $false; antiphishing = $false; teamsvoice = $false
            CippWebhookAlerts = $false; CippScriptedAlerts = $false; CippCustomVariables = $true; overwrite = $true
        }
    }
}

Describe 'New-CIPPRestore default path' {
    BeforeEach {
        Mock -CommandName New-CIPPRestoreTask -MockWith { "restored $Task" }
        Mock -CommandName New-CIPPSafeRestore -MockWith { 'safe' }
    }

    It 'restores exactly the selected components with the caller''s overwrite flag, as before' {
        $Result = New-CIPPRestore -TenantFilter 'contoso.com' -RestoreValues (New-ExistingRestoreValues)
        $Result | Should -Be @('restored users', 'restored ca', 'restored intuneconfig', 'restored CippCustomVariables')
        Should -Invoke New-CIPPRestoreTask -Times 4 -Exactly
        Should -Invoke New-CIPPRestoreTask -Times 4 -Exactly -ParameterFilter { $TenantFilter -eq 'contoso.com' -and $backup -eq 'contoso.com_2026-10-31-0100' -and $overwrite -eq $true }
        Should -Invoke New-CIPPSafeRestore -Times 0 -Exactly
    }

    It 'treats safeRestore = false exactly like an absent flag and never restores it as a component' {
        $Values = New-ExistingRestoreValues
        $Values | Add-Member -NotePropertyName safeRestore -NotePropertyValue $false
        $Result = New-CIPPRestore -TenantFilter 'contoso.com' -RestoreValues $Values
        $Result | Should -Be @('restored users', 'restored ca', 'restored intuneconfig', 'restored CippCustomVariables')
        Should -Invoke New-CIPPSafeRestore -Times 0 -Exactly
        Should -Invoke New-CIPPRestoreTask -Times 0 -Exactly -ParameterFilter { $Task -eq 'safeRestore' }
    }

    It 'accepts the hashtable form the scheduler may pass' {
        $Values = @{ backup = 'b1'; users = $true; overwrite = $false }
        New-CIPPRestore -TenantFilter 'contoso.com' -RestoreValues $Values | Should -Be 'restored users'
    }
}

Describe 'New-CIPPRestore safe path' {
    BeforeEach {
        Mock -CommandName New-CIPPRestoreTask -MockWith { "restored $Task" }
        Mock -CommandName New-CIPPSafeRestore -MockWith { 'safe' }
    }

    It 'routes to New-CIPPSafeRestore with the selected components when safeRestore is true' {
        $Values = New-ExistingRestoreValues
        $Values | Add-Member -NotePropertyName safeRestore -NotePropertyValue $true
        New-CIPPRestore -TenantFilter 'contoso.com' -RestoreValues $Values | Should -Be 'safe'
        Should -Invoke New-CIPPRestoreTask -Times 0 -Exactly
        Should -Invoke New-CIPPSafeRestore -Times 1 -Exactly -ParameterFilter {
            $TenantFilter -eq 'contoso.com' -and $BackupName -eq 'contoso.com_2026-10-31-0100' -and
            (@($Types) -join ',') -eq 'users,ca,intuneconfig,CippCustomVariables'
        }
    }

    It 'reads a string "true" (form/JSON input) as on' {
        $Values = New-ExistingRestoreValues
        $Values | Add-Member -NotePropertyName safeRestore -NotePropertyValue 'true'
        New-CIPPRestore -TenantFilter 'contoso.com' -RestoreValues $Values | Should -Be 'safe'
    }
}
