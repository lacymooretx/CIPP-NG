Function Invoke-ExecWelcomePacketConfig {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.AppSettings.ReadWrite
    .DESCRIPTION
        Reads and writes the per-tenant welcome packet override -- the client's own
        brand, support contacts and app list, layered over the Aspendora defaults.

        Get returns the fully resolved packet branding (defaults plus any override), so
        the settings form shows what will actually print rather than a form full of
        blanks that happens to render correctly.

        Stored in the shared Config table under the 'WelcomePacketConfig' partition,
        RowKey = tenant customerId. ExecBrandingSettings could not be reused: it is
        scoped to a single Global row with one colour and one logo.

        Aspendora fork addition.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $StatusCode = [HttpStatusCode]::OK

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $Action = $Request.Query.Action ?? $Request.Body.Action ?? 'Get'

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{'Results' = 'tenantFilter is required.' }
                })
        }

        $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
        $CustomerId = if ($Tenant.customerId) { $Tenant.customerId } else { $TenantFilter }
        $Table = Get-CIPPTable -TableName Config

        $Results = switch ($Action) {
            'Get' {
                Get-CIPPWelcomePacketBranding -TenantFilter $TenantFilter -Tenant $Tenant
            }

            'Set' {
                $Logo = $Request.Body.brand.logoUrl
                if (![string]::IsNullOrWhiteSpace($Logo)) {
                    # The logo is inlined into a printed sheet, so a data URI is the only
                    # form guaranteed to render -- an external URL depends on whatever
                    # network the printing browser is on. Bound it well under the 1 MiB
                    # table entity limit; a 0.55in-tall lockup needs nothing like it.
                    if ($Logo -notmatch '^data:image\/') {
                        $StatusCode = [HttpStatusCode]::BadRequest
                        return ([HttpResponseContext]@{
                                StatusCode = $StatusCode
                                Body       = @{'Results' = 'The logo must be a data URI (data:image/...). An external URL will not render reliably when the sheet is printed.' }
                            })
                    }
                    $Base64 = $Logo -replace '^data:image\/[^;]+;base64,', ''
                    try {
                        $Bytes = [Convert]::FromBase64String($Base64)
                    } catch {
                        return ([HttpResponseContext]@{
                                StatusCode = [HttpStatusCode]::BadRequest
                                Body       = @{'Results' = "Invalid base64 image data: $($_.Exception.Message)" }
                            })
                    }
                    if ($Bytes.Length -gt 524288) {
                        return ([HttpResponseContext]@{
                                StatusCode = [HttpStatusCode]::BadRequest
                                Body       = @{'Results' = 'The logo must be under 512KB. An SVG or a trimmed PNG is plenty for a 0.55in lockup.' }
                            })
                    }
                }

                if ($Request.Body.apps -and @($Request.Body.apps).Count -gt 4) {
                    return ([HttpResponseContext]@{
                            StatusCode = [HttpStatusCode]::BadRequest
                            Body       = @{'Results' = 'At most four apps fit on page two. A fifth pushes the closing notice and footer onto a third sheet.' }
                        })
                }

                $Override = [ordered]@{
                    company   = [ordered]@{ name = $Request.Body.company.name }
                    brand     = [ordered]@{
                        name    = $Request.Body.brand.name
                        logoUrl = $Request.Body.brand.logoUrl
                    }
                    support   = [ordered]@{
                        email       = $Request.Body.support.email
                        phone       = $Request.Body.support.phone
                        portalUrl   = $Request.Body.support.portalUrl
                        trayAppName = $Request.Body.support.trayAppName
                    }
                    apps      = @($Request.Body.apps | ForEach-Object { [ordered]@{ name = $_.name; description = $_.description } })
                    signInUrl = $Request.Body.signInUrl
                }

                $Entity = @{
                    PartitionKey = 'WelcomePacketConfig'
                    RowKey       = [string]$CustomerId
                    JSON         = ($Override | ConvertTo-Json -Depth 5 -Compress)
                }
                Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force | Out-Null
                Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message 'Updated the welcome packet branding' -Sev 'Info'

                Get-CIPPWelcomePacketBranding -TenantFilter $TenantFilter -Tenant $Tenant
            }

            'Reset' {
                $Existing = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'WelcomePacketConfig' and RowKey eq '$($CustomerId -replace "'", "''")'" | Select-Object -First 1
                if ($Existing) {
                    Remove-AzDataTableEntity @Table -Entity $Existing -Force | Out-Null
                }
                Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message 'Reset the welcome packet branding to the Aspendora defaults' -Sev 'Info'

                Get-CIPPWelcomePacketBranding -TenantFilter $TenantFilter -Tenant $Tenant
            }

            default {
                $StatusCode = [HttpStatusCode]::BadRequest
                "Unknown action '$Action'. Expected Get, Set or Reset."
            }
        }
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message "Welcome packet config failed: $ErrorMessage" -Sev 'Error'
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Results = "Failed to process the welcome packet config: $ErrorMessage"
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{'Results' = $Results }
        })
}
