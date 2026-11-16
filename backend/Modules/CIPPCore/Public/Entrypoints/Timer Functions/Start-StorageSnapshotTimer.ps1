function Start-StorageSnapshotTimer {
    <#
    .SYNOPSIS
    Daily Microsoft 365 storage collection for managed clients (Aspendora fork, CIPP-64)
    .DESCRIPTION
    Nothing scheduled Push-CIPPStorageSnapshot, so the Storage & Usage history and growth figures never collected
    data. This queues one StorageSnapshotCollect activity per Managed Client tenant (Test-CIPPTenantManaged, fails
    closed); unmanaged and unknown tenants are skipped here rather than inside each activity.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($PSCmdlet.ShouldProcess('Start-StorageSnapshotTimer', 'Queue storage collection for managed tenants')) {
        $PlaceholderPattern = '^(LongApplicationId|AppSecret|RefreshToken|tenantId)$'
        if (-not $env:ApplicationID -or $env:ApplicationID -match $PlaceholderPattern) { return }
        try {
            $Batch = foreach ($Tenant in @(Get-Tenants)) {
                $Managed = Test-CIPPTenantManaged -TenantFilter $Tenant.defaultDomainName
                if (-not $Managed.IsManaged) { continue }
                @{ FunctionName = 'StorageSnapshotCollect'; TenantFilter = $Tenant.defaultDomainName }
            }
            if (-not @($Batch).Count) {
                Write-LogMessage -API 'StorageSnapshot' -tenant 'Global' -message 'Storage collection: no managed tenants found (managed group empty or unreadable)' -Sev 'Warning'
                return
            }
            Start-CIPPOrchestrator -InputObject @{
                Batch            = @($Batch)
                OrchestratorName = 'StorageSnapshot'
                AllowCollision   = $false
                Priority         = 9
                SkipLog          = $true
            } | Out-Null
            Write-Information "Storage collection queued for $(@($Batch).Count) managed tenant(s)"
        } catch {
            Write-LogMessage -API 'StorageSnapshot' -tenant 'Global' -message "Storage collection timer failed: $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_)
        }
    }
}
