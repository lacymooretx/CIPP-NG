# Aspendora fork (Vikunja CIPP-23): shared loader and fixtures for the backup integrity / diff / restore tests.
# Dot-source from a BeforeAll block.

$BackendRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path (Join-Path $BackendRoot 'Modules'))) { $BackendRoot = Split-Path -Parent $PSScriptRoot }
$IntegrityDir = Join-Path $BackendRoot 'Modules/CIPPCore/Public/BackupIntegrity'
foreach ($File in Get-ChildItem -Path $IntegrityDir -Filter '*.ps1') { . $File.FullName }
. (Join-Path $BackendRoot 'Modules/CIPPCore/Public/Get-CIPPIntunePolicyName.ps1')
. (Join-Path $BackendRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')

function New-TestCAPolicyJson {
    param([string]$Name, [string]$State = 'enabled', [string[]]$IncludeGroups = @('Finance'), [string]$Modified = '2026-10-01T10:00:00Z')
    [ordered]@{
        id               = [guid]::NewGuid().ToString()
        displayName      = $Name
        state            = $State
        createdDateTime  = '2025-01-01T00:00:00Z'
        modifiedDateTime = $Modified
        conditions       = [ordered]@{
            users              = [ordered]@{ includeUsers = @(); includeGroups = $IncludeGroups; excludeUsers = @('Break Glass') }
            applications       = [ordered]@{ includeApplications = @('All') }
            clientApplications = [ordered]@{ includeServicePrincipals = @('sp-1') }
        }
        grantControls    = [ordered]@{ operator = 'OR'; builtInControls = @('mfa') }
    } | ConvertTo-Json -Depth 20 -Compress
}

function New-TestIntuneRow {
    param([string]$Name, [string]$Type = 'Device', [hashtable]$Settings = @{ passwordRequired = $true }, [string]$Modified = '2026-10-01T10:00:00Z')
    $Template = [ordered]@{
        '@odata.type'        = '#microsoft.graph.windows10GeneralConfiguration'
        displayName          = $Name
        description          = 'test'
        lastModifiedDateTime = $Modified
        version              = 3
    }
    foreach ($K in $Settings.Keys) { $Template[$K] = $Settings[$K] }
    [pscustomobject]@{
        TemplateJson = ($Template | ConvertTo-Json -Depth 20 -Compress)
        DisplayName  = $Name
        Description  = 'test'
        Type         = $Type
    }
}

function New-TestCatalogRow {
    param([string]$Name, [string]$Value = 'on')
    $Template = [ordered]@{
        name              = $Name
        description       = 'catalog'
        platforms         = 'windows10'
        technologies      = 'mdm'
        settings          = @(@{ id = '0'; settingInstance = @{ settingDefinitionId = 'device_vendor_msft_x'; choiceSettingValue = @{ value = $Value } } })
        templateReference = @{ templateId = '' }
        assignments       = @(@{ target = @{ groupId = 'g-1' } })
    }
    [pscustomobject]@{
        TemplateJson = ($Template | ConvertTo-Json -Depth 20 -Compress)
        DisplayName  = $Name
        Description  = 'catalog'
        Type         = 'Catalog'
    }
}

function New-TestScheduledBackupJson {
    param(
        [object[]]$Ca = @((New-TestCAPolicyJson -Name 'Require MFA')),
        [object[]]$Intune = @((New-TestIntuneRow -Name 'Win - Baseline')),
        [object[]]$Users = @(
            [pscustomobject]@{ id = 'u1'; userPrincipalName = 'ann@contoso.com'; displayName = 'Ann'; jobTitle = 'CFO' },
            [pscustomobject]@{ id = 'u2'; userPrincipalName = 'bob@contoso.com'; displayName = 'Bob'; jobTitle = 'Clerk' }
        )
    )
    $AntiSpam = @{ policies = @(@{ Identity = 'Default'; Name = 'Default'; BulkThreshold = 7 }); rules = @() } | ConvertTo-Json -Depth 10
    [ordered]@{
        PartitionKey = 'ScheduledBackup'
        RowKey       = 'contoso.com_2026-10-31-0100'
        TenantFilter = 'contoso.com'
        users        = $Users
        ca           = $Ca
        intuneconfig = $Intune
        antispam     = $AntiSpam
    } | ConvertTo-Json -Depth 50 -Compress
}

function ConvertFrom-TestBackupJson {
    param([string]$Json)
    ConvertFrom-Json -InputObject $Json -Depth 100 -NoEnumerate
}
