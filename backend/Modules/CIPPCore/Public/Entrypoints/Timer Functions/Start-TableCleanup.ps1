function Start-TableCleanup {
    <#
    .SYNOPSIS
    Start the Table Cleanup Timer
    #>
    param()

    $Batch = @(
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'webhookTable'
            DataTableProps = @{
                Property = @('PartitionKey', 'RowKey', 'ETag', 'Resource')
                First    = 1000
            }
            Where          = "`$_.Resource -match '^Audit'"
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'CippReportingDB'
            DataTableProps = @{
                Filter   = "Timestamp lt datetime'$((Get-Date).AddDays(-30).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'AuditLogSearches'
            DataTableProps = @{
                Filter   = "PartitionKey eq 'Search' and Timestamp lt datetime'$((Get-Date).AddHours(-12).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'CippFunctionStats'
            DataTableProps = @{
                Filter   = "PartitionKey eq 'Durable' and Timestamp lt datetime'$((Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'CippQueue'
            DataTableProps = @{
                Filter   = "PartitionKey eq 'CippQueue' and Timestamp lt datetime'$((Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'CippQueueTasks'
            DataTableProps = @{
                Filter   = "PartitionKey eq 'Task' and Timestamp lt datetime'$((Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'ScheduledTasks'
            DataTableProps = @{
                Filter   = "PartitionKey eq 'ScheduledTask' and Command eq 'Sync-CippExtensionData'"
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'CippStandardsReports'
            DataTableProps = @{
                Filter   = "Timestamp lt datetime'$((Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'cacheQuarantineMessages'
            DataTableProps = @{
                Filter   = "PartitionKey eq 'QuarantineMessage' and Timestamp lt datetime'$((Get-Date).AddDays(-1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'CippOrchestratorBatch'
            DataTableProps = @{
                Filter   = "Timestamp lt datetime'$((Get-Date).AddHours(-24).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'knownlocationdbv2'
            DataTableProps = @{
                Filter   = "PartitionKey eq 'ip' and Timestamp lt datetime'$((Get-Date).AddDays(-90).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            # Per-object storage detail only. CippStorageTrend is deliberately absent from
            # this list: it is one small row per tenant per day and it is the whole point of
            # the feature - purging it would delete history that cannot be re-fetched, since
            # Graph only serves the last 180 days.
            FunctionName   = 'TableCleanupTask'
            Type           = 'CleanupRule'
            TableName      = 'CippStorageSnapshot'
            DataTableProps = @{
                Filter   = "Timestamp lt datetime'$((Get-Date).AddDays(-91).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
                First    = 10000
                Property = @('PartitionKey', 'RowKey', 'ETag')
            }
        }
        @{
            FunctionName = 'TableCleanupTask'
            Type         = 'DeleteTable'
            Tables       = @('knownlocationdb', 'CacheExtensionSync', 'ExtensionSync')
        }
    )

    $InputObject = @{
        Batch            = @($Batch)
        OrchestratorName = 'TableCleanup'
        SkipLog          = $true
    }

    Start-CIPPOrchestrator -InputObject $InputObject
}
