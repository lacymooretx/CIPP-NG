Function Invoke-ExecDefenderIndicator {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .DESCRIPTION
        Creates or deletes a Microsoft Defender for Endpoint custom indicator (IOC).

        Typical use: block a specific URL/domain, IP, or file hash across a tenant, or
        across a subset of devices via RBAC device group names.

        Uses the Defender for Endpoint API — MDE custom indicators are not exposed through
        Microsoft Graph. Requires the SAM app to hold Ti.ReadWrite.All on WindowsDefenderATP
        (see SAMManifest.json).

        NOTE: URL/domain and IP indicators are enforced by Network Protection. The target
        devices must be MDE-onboarded with Network Protection in block mode, or the
        indicator will be created but will not actually block.

    .PARAMETER Action
        'Create' (default) or 'Delete'.

    .PARAMETER indicatorValue
        The value to act on, e.g. 'example.com', an IP, or a SHA256 hash.

    .PARAMETER indicatorType
        MDE indicator type: DomainName, Url, IpAddress, FileSha256, FileSha1, CertificateThumbprint.

    .PARAMETER indicatorAction
        MDE action: Allowed, Audit, Block, BlockAndRemediate, Warn.

    .PARAMETER rbacGroupNames
        Optional array of MDE device group names to scope to. Omit or leave empty to apply
        to ALL devices in the tenant.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -Headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'

    $TenantFilter = $Request.Body.tenantFilter
    $Action = $Request.Body.Action ?? 'Create'

    try {
        if (-not $TenantFilter) { throw 'tenantFilter is required.' }

        switch ($Action) {
            'Delete' {
                $IndicatorId = $Request.Body.indicatorId
                if (-not $IndicatorId) { throw 'indicatorId is required when Action is Delete.' }

                $null = New-GraphPOSTRequest -tenantid $TenantFilter `
                    -uri "https://api.securitycenter.microsoft.com/api/indicators/$IndicatorId" `
                    -scope 'https://api.securitycenter.microsoft.com/.default' `
                    -type 'DELETE'

                $Results = "Deleted Defender indicator $IndicatorId"
                Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message $Results -Sev 'Info'
                break
            }

            'Create' {
                $IndicatorValue = $Request.Body.indicatorValue
                if (-not $IndicatorValue) { throw 'indicatorValue is required when Action is Create.' }

                $IndicatorBody = [ordered]@{
                    indicatorValue = $IndicatorValue
                    indicatorType  = $Request.Body.indicatorType ?? 'DomainName'
                    action         = $Request.Body.indicatorAction ?? 'Block'
                    title          = $Request.Body.title ?? "Blocked by CIPP: $IndicatorValue"
                    description    = $Request.Body.description ?? 'Created via CIPP.'
                    severity       = $Request.Body.severity ?? 'Informational'
                    # MDE rejects generateAlert=false alongside some actions; default to no alert noise.
                    generateAlert  = [bool]($Request.Body.generateAlert ?? $false)
                }

                # Scope to specific MDE device groups when supplied; otherwise all devices.
                if ($Request.Body.rbacGroupNames) {
                    $IndicatorBody['rbacGroupNames'] = @($Request.Body.rbacGroupNames)
                }
                if ($Request.Body.expirationTime) {
                    $IndicatorBody['expirationTime'] = $Request.Body.expirationTime
                }
                if ($Request.Body.recommendedActions) {
                    $IndicatorBody['recommendedActions'] = $Request.Body.recommendedActions
                }

                $Created = New-GraphPOSTRequest -tenantid $TenantFilter `
                    -uri 'https://api.securitycenter.microsoft.com/api/indicators' `
                    -scope 'https://api.securitycenter.microsoft.com/.default' `
                    -body ($IndicatorBody | ConvertTo-Json -Depth 5 -Compress) `
                    -contentType 'application/json'

                $Scope = if ($IndicatorBody['rbacGroupNames']) {
                    "device groups: $($IndicatorBody['rbacGroupNames'] -join ', ')"
                } else {
                    'ALL devices'
                }
                $Results = "Created Defender indicator '$($IndicatorBody.indicatorValue)' ($($IndicatorBody.indicatorType), $($IndicatorBody.action)) applied to $Scope. Id: $($Created.id)"
                Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message $Results -Sev 'Info'
                break
            }

            default { throw "Unknown Action '$Action'. Expected 'Create' or 'Delete'." }
        }

        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Results = "Defender indicator $Action failed: $($ErrorMessage.NormalizedError)"
        Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message $Results -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Results }
        })
}
