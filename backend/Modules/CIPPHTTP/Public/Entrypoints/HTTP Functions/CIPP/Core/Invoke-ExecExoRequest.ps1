function Invoke-ExecExoRequest {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.Core.ReadWrite
    .DESCRIPTION
        Generic Exchange Online cmdlet passthrough. Runs an arbitrary EXO/Compliance cmdlet
        against a single tenant via New-ExoRequest. The on-demand escape hatch for one-off
        EXO reads/writes (Set-* / Get-* / New-* / Remove-*) that lack a dedicated CIPP endpoint
        - e.g. ExternalInOutlook, connector Enhanced Filtering, transport tweaks. Every call is
        audited; the SAM/GDAP Exchange.ManageAsApp scope remains the real safety boundary.

        Body/query params:
          TenantFilter (required)
          Cmdlet       (required) - EXO cmdlet name, e.g. 'Set-InboundConnector'
          CmdParams    - object of cmdlet parameters, e.g. { Identity: 'x', EFSkipLastIP: true }
          UseSystemMailbox - bool, route via the system mailbox (needed by some Set-* cmdlets)
          Compliance   - bool, run against the Security & Compliance PowerShell endpoint
          Anchor       - optional UPN anchor mailbox
          Select       - optional comma-separated property projection for reads
          VerifyWrite  - bool, default true. After a Set-* cmdlet, read the object back with the
                         matching Get-* and report each requested property in `Verification`.

        Exchange returns NOTHING for a successful Set-/Remove-/Enable-* cmdlet, so a write used to come
        back as {"Results":null} - indistinguishable from a silent no-op. Non-Get cmdlets now return a
        completion message, and Set-* adds Verification = { Status: Confirmed | Mismatch | Skipped,
        Properties: [{ Name, Requested, Observed, Match }], Note }. A Mismatch is reported, NOT failed:
        EXO reads can lag a write by minutes, and some properties (e.g. Set-CASMailbox
        -ActiveSyncDebugLogging) never show up in Get-*. The authoritative record of a write is the
        unified audit log: Search-UnifiedAuditLog -RecordType ExchangeAdmin (ObjectIds must be an
        array, and it matches the object's display name, not the UPN). Search-AdminAuditLog is
        not usable through this API (403); use Search-UnifiedAuditLog instead.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.TenantFilter ?? $Request.Query.TenantFilter
    $Cmdlet = $Request.Body.Cmdlet ?? $Request.Query.Cmdlet
    $CmdParams = $Request.Body.CmdParams ?? $Request.Body.cmdParams
    $Anchor = $Request.Body.Anchor ?? $Request.Query.Anchor
    $Select = $Request.Body.Select ?? $Request.Query.Select

    $UseSystemMailbox = ConvertTo-CIPPBoolean -Value ($Request.Body.UseSystemMailbox ?? $Request.Query.UseSystemMailbox)
    $Compliance = ConvertTo-CIPPBoolean -Value ($Request.Body.Compliance ?? $Request.Query.Compliance)
    $VerifyWriteRaw = $Request.Body.VerifyWrite ?? $Request.Query.VerifyWrite
    $VerifyWrite = if ($null -eq $VerifyWriteRaw -or "$VerifyWriteRaw" -eq '') { $true } else { ConvertTo-CIPPBoolean -Value $VerifyWriteRaw }

    # Validation
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = [pscustomobject]@{ Results = 'TenantFilter is required.' } })
    }
    if (-not $Cmdlet) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = [pscustomobject]@{ Results = 'Cmdlet is required.' } })
    }

    # Normalize CmdParams (PSCustomObject from JSON body) to a hashtable for New-ExoRequest.
    $ParamHash = $null
    if ($null -ne $CmdParams) {
        if ($CmdParams -is [hashtable]) {
            $ParamHash = $CmdParams
        } else {
            $ParamHash = @{}
            foreach ($Prop in $CmdParams.PSObject.Properties) { $ParamHash[$Prop.Name] = $Prop.Value }
        }
    }

    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "EXO passthrough: $Cmdlet (Compliance: $Compliance)" -Sev 'Debug'

    try {
        $ExoParams = @{
            tenantid = $TenantFilter
            cmdlet   = $Cmdlet
        }
        if ($null -ne $ParamHash) { $ExoParams.cmdParams = $ParamHash }
        if ($UseSystemMailbox) { $ExoParams.useSystemMailbox = $true }
        if ($Compliance) { $ExoParams.Compliance = $true }
        if ($Anchor) { $ExoParams.Anchor = $Anchor }
        if ($Select) { $ExoParams.Select = $Select }

        $Results = New-ExoRequest @ExoParams

        # Audit mutating cmdlets (anything not a plain Get-) at Info.
        if ($Cmdlet -notmatch '^Get-') {
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Executed EXO cmdlet $Cmdlet" -Sev 'Info'
        }

        $Verification = $null
        if ($Cmdlet -notmatch '^Get-') {
            if ($null -eq $Results) {
                $Results = "$Cmdlet completed. Exchange returned no output, which is normal for a successful $(($Cmdlet -split '-')[0])- cmdlet."
            }
            if ($Cmdlet -match '^Set-' -and $VerifyWrite) {
                $Verification = Get-ExoWriteVerification -Cmdlet $Cmdlet -ParamHash $ParamHash -ReadParams @{
                    tenantid   = $TenantFilter
                    Compliance = $Compliance
                    Anchor     = $Anchor
                }
                if ($Verification.Status -eq 'Mismatch') {
                    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "EXO $Cmdlet read-back does not show the requested value(s) yet: $(($Verification.Properties | Where-Object { -not $_.Match }).Name -join ', ')" -Sev 'Warning'
                }
            }
        }

        $StatusCode = [HttpStatusCode]::OK
        $ResponseBody = if ($Verification) {
            [pscustomobject]@{ Results = $Results; Verification = $Verification }
        } else {
            [pscustomobject]@{ Results = $Results }
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "EXO passthrough failed: $Cmdlet - $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::BadRequest
        $Hint = if ($Cmdlet -in @('Search-AdminAuditLog', 'Search-MailboxAuditLog', 'New-AdminAuditLogSearch', 'New-MailboxAuditLogSearch')) {
            " - $Cmdlet is not usable through the Exchange admin API; use Search-UnifiedAuditLog (e.g. RecordType ExchangeAdmin, ObjectIds as an array matching the display name)."
        } else { '' }
        $ResponseBody = [pscustomobject]@{ Results = "EXO Error: $($ErrorMessage.NormalizedError) - Cmdlet: $Cmdlet$Hint" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $ResponseBody
        })
}
