# Shared harness for fork-alert tests that exercise the REAL AlertLifecycle (CIPP 11.0).
#
# Earlier tests stubbed Write-AlertTrace and asserted on what was handed to it, which cannot see
# the thing that matters after 11.0: what actually gets NOTIFIED across consecutive runs. Here the
# genuine Write-AlertTrace, Get-AlertContentHash, Get-CIPPAlertLifecycleKey and
# Initialize-CIPPAlertLifecycleBaseline run against an in-memory table store, so a test can run an
# alert several times and assert on each run's notifications and on the stored lifecycle state.
#
# Dot-source from a BeforeAll, then call Reset-AlertStore in BeforeEach.

$HarnessRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
. (Join-Path $HarnessRoot 'Modules/CIPPCore/Public/GraphHelper/Get-AlertContentHash.ps1')
. (Join-Path $HarnessRoot 'Modules/CIPPCore/Public/GraphHelper/Get-CIPPAlertLifecycleKey.ps1')
. (Join-Path $HarnessRoot 'Modules/CIPPCore/Public/GraphHelper/Write-AlertTrace.ps1')
. (Join-Path $HarnessRoot 'Modules/CIPPCore/Public/GraphHelper/Initialize-CIPPAlertLifecycleBaseline.ps1')

function Reset-AlertStore {
    $script:Store = @{}
    $script:Snoozes = @{}
    $script:Logs = @()
}

function ConvertTo-CIPPODataFilterValue { param($Value, $Type) [string]$Value -replace "'", "''" }
function Get-CIPPActiveAlertSnoozes { param($CmdletName, $TenantFilter) $script:Snoozes }
function Get-CIPPTable { param($tablename, $Table) @{ TableName = ($tablename ?? $Table) } }

function Get-CIPPAzDataTableEntity {
    param($TableName, $Filter, $Property, $First)
    $Rows = @($script:Store[$TableName].Values)
    # Just enough OData for the filters these alerts and the lifecycle issue: "X eq 'v'" joined by "and".
    foreach ($Clause in ([regex]::Matches([string]$Filter, "(\w+) eq '((?:[^']|'')*)'"))) {
        $Name = $Clause.Groups[1].Value
        $Value = $Clause.Groups[2].Value -replace "''", "'"
        $Rows = @($Rows | Where-Object { [string]$_.$Name -eq $Value })
    }
    $Rows
}

function Add-CIPPAzDataTableEntity {
    param($TableName, $Entity, [switch]$Force)
    if (-not $script:Store.ContainsKey($TableName)) { $script:Store[$TableName] = @{} }
    foreach ($E in @($Entity)) {
        $Row = [pscustomobject]@{}
        $Pairs = if ($E -is [hashtable]) { $E.GetEnumerator() } else { $E.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Key = $_.Name; Value = $_.Value } } }
        foreach ($P in $Pairs) { $Row | Add-Member -NotePropertyName $P.Key -NotePropertyValue $P.Value -Force }
        $script:Store[$TableName]["$($Row.PartitionKey)|$($Row.RowKey)"] = $Row
    }
}

function Remove-CIPPAzDataTableEntity {
    param($TableName, $Entity, [switch]$Force)
    $script:Store[$TableName].Remove("$($Entity.PartitionKey)|$($Entity.RowKey)")
}

function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) $script:Logs += @([pscustomobject]@{ Message = $message; Sev = $sev }) }
function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

# Lifecycle rows for one cmdlet, as { Id -> Status } using the item's stored Id.
function Get-LifecycleState {
    param([string]$CmdletName)
    $State = @{}
    foreach ($Row in @($script:Store['AlertLifecycle'].Values | Where-Object { $_.CmdletName -eq $CmdletName })) {
        $Item = $Row.AlertItem | ConvertFrom-Json
        $Key = if ($Item.Id) { $Item.Id } elseif ($Item.UserPrincipalName) { $Item.UserPrincipalName } else { $Row.ContentPreview }
        $State[[string]$Key] = [string]$Row.Status
    }
    $State
}

function Set-OldBaseline {
    param([string]$Partition, [string]$Tenant, [string[]]$Ids)
    Add-CIPPAzDataTableEntity -TableName 'DeltaCompare' -Entity @{
        PartitionKey = $Partition; RowKey = $Tenant; delta = (ConvertTo-Json -InputObject @($Ids) -Compress)
    }
}
