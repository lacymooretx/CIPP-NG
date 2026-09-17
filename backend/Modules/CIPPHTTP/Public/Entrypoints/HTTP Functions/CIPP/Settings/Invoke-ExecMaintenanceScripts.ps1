Function Invoke-ExecMaintenanceScripts {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.AppSettings.Read
    .DESCRIPTION
        Returns the maintenance scripts shipped with CIPP. Called without ScriptFile it lists the available scripts; with one it returns that script with the deployment's own tenant, subscription and resource details substituted in. (The MakeLink parameter was removed: it returned a link to an endpoint that never existed, and serving these scripts anonymously would disclose deployment details to anyone holding the GUID.)
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    try {
        $GraphToken = Get-GraphToken -returnRefresh $true
        $AccessTokenDetails = Read-JwtAccessDetails -Token $GraphToken.access_token

        $ReplacementStrings = @{
            '##TENANTID##'      = $env:TenantID
            '##RESOURCEGROUP##' = $env:WEBSITE_RESOURCE_GROUP
            '##FUNCTIONAPP##'   = $env:WEBSITE_SITE_NAME
            '##SUBSCRIPTION##'  = Get-CIPPAzFunctionAppSubId
            '##TOKENIP##'       = $AccessTokenDetails.IPAddress
        }
    } catch { Write-Host $_.Exception.Message }
    #$ReplacementStrings | Format-Table

    try {
        $ScriptFile = $Request.Query.ScriptFile

        try {
            $Filename = Split-Path -Leaf $ScriptFile
        } catch {}

        if (!$ScriptFile -or [string]::IsNullOrEmpty($ScriptFile)) {
            $ScriptFiles = Get-ChildItem (Join-Path $env:CIPPRootPath 'ExecMaintenanceScripts\Scripts') | Select-Object -ExpandProperty PSChildName

            $ScriptOptions = foreach ($ScriptFile in $ScriptFiles) {
                @{label = $ScriptFile; value = $ScriptFile }
            }
            $Body = @{ ScriptFiles = @($ScriptOptions) }
        } elseif (!(Get-ChildItem (Join-Path $env:CIPPRootPath "ExecMaintenanceScripts\Scripts\$Filename") -ErrorAction SilentlyContinue)) {
            $Body = @{ Status = 'Script does not exist' }
        } else {
            $Script = Get-Content -Raw (Join-Path $env:CIPPRootPath "ExecMaintenanceScripts\Scripts\$Filename")
            foreach ($i in $ReplacementStrings.Keys) {
                $Script = $Script -replace $i, $ReplacementStrings.$i
            }

            $ScriptContent = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script))

            # MakeLink removed. It returned "/api/PublicScripts?guid=<guid>", but no
            # Invoke-PublicScripts exists in this fork OR upstream, so every link it produced was a
            # 404 on arrival. Nothing in the frontend called it.
            #
            # It was not reinstated by writing the missing endpoint, because that endpoint would
            # have to be ANONYMOUS to be useful, and these scripts carry the deployment's own
            # tenant, subscription and resource details substituted in. That is unauthenticated
            # disclosure of deployment detail to anyone holding a GUID - and GUIDs in URLs leak
            # through browser history, proxy logs and referrers.
            #
            # Removing the branch also stops the table write it performed: every call persisted a
            # substituted script to the MaintenanceScripts table, which nothing read and nothing
            # expired, accumulating that same detail at rest indefinitely.
            #
            # Callers get the script content directly, which is what the non-link path always did.
            $Body = @{ ScriptContent = $ScriptContent }
        }
    } catch {
        Write-LogMessage -headers $Request.Headers -API $APINAME -tenant $($tenantfilter) -message "Failed to retrieve maintenance scripts. Error: $($_.Exception.Message)" -Sev 'Error'
        $Body = @{Status = "Failed to retrieve maintenance scripts $($_.Exception.Message)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $Body
        })

}
