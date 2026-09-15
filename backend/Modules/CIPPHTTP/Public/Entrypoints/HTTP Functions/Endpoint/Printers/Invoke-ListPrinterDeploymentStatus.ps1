Function Invoke-ListPrinterDeploymentStatus {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.Read
    .DESCRIPTION
        Per-device install status for the printers CIPP deploys as Intune platform scripts. Shows which devices have the printer, which failed, and the failure message from the device.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        # Only CIPP's own printer scripts. The prefix is what Set-CIPPCatalogPrinter writes, and
        # is also what it converges on, so this stays in step with deployment.
        $Scripts = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' -tenantid $TenantFilter |
                Where-Object { $_.displayName -like 'CIPP: Printer - *' })

        $Results = foreach ($Script in $Scripts) {
            $PrinterName = $Script.displayName -replace '^CIPP: Printer - ', ''
            try {
                $States = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($Script.id)/deviceRunStates?`$expand=managedDevice(`$select=deviceName)" -tenantid $TenantFilter)
            } catch {
                $States = @()
            }

            foreach ($State in $States) {
                # resultMessage carries whatever the script wrote to stdout, which for a failure can
                # be a full stack trace. Truncate: this is a status table, not a log viewer.
                $Message = [string]$State.resultMessage
                if ($Message.Length -gt 500) { $Message = $Message.Substring(0, 500) + '...' }

                [PSCustomObject]@{
                    Printer         = $PrinterName
                    DeviceName      = $State.managedDevice.deviceName
                    RunState        = $State.runState
                    ErrorCode       = $State.errorCode
                    LastStateUpdate = $State.lastStateUpdateDateTime
                    Message         = $Message
                    ScriptId        = $Script.id
                }
            }
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Results = $ErrorMessage
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($Results)
        })
}
