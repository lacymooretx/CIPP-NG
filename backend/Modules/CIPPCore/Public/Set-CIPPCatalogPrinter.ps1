function Set-CIPPCatalogPrinter {
    <#
    .SYNOPSIS
        Deploys one printer catalogue entry to a tenant through Intune.
    .DESCRIPTION
        Shared by the ExecDeployCatalogPrinter endpoint and the PrinterCatalog standard, so the
        button on the catalogue page and the scheduled standard take exactly the same path.

        Universal Print entries become a settings catalog policy. Direct IP and print-server
        entries become an Intune platform script, because Intune has no configuration service
        provider for either.
    .PARAMETER Printer
        The catalogue entity, as stored in the PrinterCatalog table.
    .PARAMETER TenantFilter
        Tenant to deploy into.
    .PARAMETER AssignTo
        Group name or object id. Pass an empty string to deploy without assigning.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Printer,
        [Parameter(Mandatory = $true)]$TenantFilter,
        $AssignTo,
        $Headers,
        $APIName = 'Set-CIPPCatalogPrinter'
    )

    if ($Printer.PrinterType -eq 'UniversalPrint') {
        # Build from the catalogue's real ShareId rather than the %upPrinterShareId% variable:
        # Get-CIPPTextReplacement passes an undefined token through verbatim, which would write
        # the literal token into Intune as the share id and fail silently on the device.
        if ([string]::IsNullOrWhiteSpace($Printer.ShareId)) { throw "Catalogue entry '$($Printer.Name)' has no ShareId" }

        $Root = 'user_vendor_msft_printerprovisioning_upprinterinstalls_{printersharedid}'
        $Policy = [ordered]@{
            name            = "CIPP: Universal Print - $($Printer.Name)"
            description     = 'Universal Print printer provisioned by CIPP. User-scoped policy - assign to users, not devices.'
            platforms       = 'windows10'
            technologies    = 'mdm'
            roleScopeTagIds = @('0')
            settings        = @(
                [ordered]@{
                    id              = '0'
                    '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
                    settingInstance = [ordered]@{
                        '@odata.type'               = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                        settingDefinitionId         = $Root
                        groupSettingCollectionValue = @(
                            @{
                                children = @(
                                    [ordered]@{
                                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                                        settingDefinitionId = "$($Root)_printersharedid"
                                        simpleSettingValue  = [ordered]@{
                                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                            value         = [string]$Printer.ShareId
                                        }
                                    },
                                    [ordered]@{
                                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                                        settingDefinitionId = "$($Root)_install"
                                        choiceSettingValue  = [ordered]@{
                                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                                            value         = "$($Root)_install_true"
                                            children      = @()
                                        }
                                    }
                                )
                            }
                        )
                    }
                }
            )
        }
        $RawJSON = ConvertTo-Json -InputObject $Policy -Depth 100 -Compress

        $null = Set-CIPPIntunePolicy -TemplateType 'Catalog' -RawJSON $RawJSON `
            -DisplayName "CIPP: Universal Print - $($Printer.Name)" `
            -Description 'Universal Print printer provisioned by CIPP' `
            -AssignTo $AssignTo -TenantFilter $TenantFilter -Headers $Headers -APIName $APIName

        return "Deployed Universal Print printer '$($Printer.Name)'"
    }

    $ScriptContent = New-CIPPPrinterScript -Printer $Printer
    $Encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ScriptContent))
    $DisplayName = "CIPP: Printer - $($Printer.Name)"

    # A mapped print-server queue lives in the user's profile, so it must run as the user; a
    # direct IP queue is machine-wide and must run as system.
    $RunAs = if ($Printer.PrinterType -eq 'ServerShare') { 'user' } else { 'system' }

    $Body = [ordered]@{
        '@odata.type'         = '#microsoft.graph.deviceManagementScript'
        displayName           = $DisplayName
        description           = "Printer '$($Printer.Name)' ($($Printer.PrinterType)) deployed by CIPP"
        scriptContent         = $Encoded
        runAsAccount          = $RunAs
        enforceSignatureCheck = $false
        fileName              = 'CIPP-Printer.ps1'
        runAs32Bit            = $false
    } | ConvertTo-Json -Depth 10 -Compress

    # Converge on displayName so redeploying a changed entry updates the same script rather than
    # piling up near-duplicates in the tenant.
    $Existing = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' -tenantid $TenantFilter |
        Where-Object { $_.displayName -eq $DisplayName } | Select-Object -First 1

    if ($Existing) {
        $null = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($Existing.id)" -tenantid $TenantFilter -type 'PATCH' -body $Body
        $ScriptId = $Existing.id
        $Verb = 'Updated'
    } else {
        $Created = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' -tenantid $TenantFilter -type 'POST' -body $Body
        $ScriptId = $Created.id
        $Verb = 'Created'
    }

    if ($AssignTo) {
        # deviceManagementScripts does NOT accept the generic {assignments:[...]} shape that
        # configurationPolicies uses - it needs deviceManagementScriptAssignments - so this
        # cannot go through Set-CIPPAssignedPolicy.
        $GroupId = $AssignTo
        if ($AssignTo -notmatch '^[0-9a-fA-F-]{36}$') {
            $Escaped = $AssignTo -replace "'", "''"
            $Group = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$Escaped'" -tenantid $TenantFilter | Select-Object -First 1
            if (!$Group) { throw "No group found named '$AssignTo'" }
            $GroupId = $Group.id
        }
        $AssignBody = @{
            deviceManagementScriptAssignments = @(
                @{
                    '@odata.type' = '#microsoft.graph.deviceManagementScriptAssignment'
                    target        = @{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId       = $GroupId
                    }
                }
            )
        } | ConvertTo-Json -Depth 10 -Compress
        $null = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$ScriptId/assign" -tenantid $TenantFilter -type 'POST' -body $AssignBody
    }

    return "$Verb platform script for printer '$($Printer.Name)' ($($Printer.PrinterType), runs as $RunAs)"
}
