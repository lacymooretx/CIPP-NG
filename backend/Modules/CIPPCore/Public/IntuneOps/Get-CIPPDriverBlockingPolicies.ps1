function Get-CIPPDriverBlockingPolicies {
    <#
    .SYNOPSIS
        Finds Intune policies that stop Windows Update from offering drivers.
    .DESCRIPTION
        Two places can block drivers, and either one silently defeats a driver update profile:
          - Update rings (deviceConfigurations of type windowsUpdateForBusinessConfiguration) with
            driversExcluded = true ("Windows drivers: Block" in the ring UI).
          - Settings Catalog policies setting "Exclude WU Drivers In Quality Update"
            (device_vendor_msft_policy_config_update_excludewudriversinqualityupdate) to
            ..._excludewudriversinqualityupdate_1 ("Exclude Windows Update drivers"). Both ids verified live
            2026-10-31 against deviceManagement/configurationSettings.
        Assignment counts are returned so an unassigned policy can be read as harmless; it is still reported,
        because assigning it later would start blocking.
        Returns @{ Findings = @(@{ Id; Kind; PolicyId; PolicyName; Assigned; AssignmentCount; Message }); Errors }.
        Group Policy (ADMX) profiles are not inspected. Read only. Aspendora fork addition (Vikunja CIPP-24).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $SettingId = 'device_vendor_msft_policy_config_update_excludewudriversinqualityupdate'
    $BlockValue = 'device_vendor_msft_policy_config_update_excludewudriversinqualityupdate_1'
    $Errors = [System.Collections.Generic.List[string]]::new()
    $Findings = [System.Collections.Generic.List[object]]::new()

    try {
        $Rings = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=assignments" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
        foreach ($Ring in $Rings) {
            if ($Ring.driversExcluded -eq $true) {
                $Count = @($Ring.assignments).Count
                $Findings.Add([pscustomobject]@{
                        Id              = "Ring|$($Ring.id)"
                        Kind            = 'UpdateRing'
                        PolicyId        = [string]$Ring.id
                        PolicyName      = [string]$Ring.displayName
                        Assigned        = $Count -gt 0
                        AssignmentCount = $Count
                        Message         = "Update ring '$($Ring.displayName)' blocks Windows drivers (driversExcluded = true)$(if ($Count -eq 0) { ', though it is not assigned' }). Devices it targets never receive drivers from a driver update profile; set 'Windows drivers' to Allow."
                    })
            }
        }
    } catch {
        $Errors.Add("Update rings: $((Get-CippException -Exception $_).NormalizedError)")
    }

    try {
        $Catalog = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=id,name,platforms,technologies&`$expand=assignments" -tenantid $TenantFilter -ErrorAction Stop |
                Where-Object { $_.id -and [string]$_.platforms -match 'windows10' -and [string]$_.technologies -match 'mdm' })
        if ($Catalog.Count -gt 0) {
            $Requests = @($Catalog | ForEach-Object { [pscustomobject]@{ id = [string]$_.id; method = 'GET'; url = "/deviceManagement/configurationPolicies/$($_.id)/settings?`$top=1000" } })
            $Results = @(New-GraphBulkRequest -Requests $Requests -tenantid $TenantFilter)
            foreach ($P in $Catalog) {
                $R = $Results | Where-Object { [string]$_.id -eq [string]$P.id } | Select-Object -First 1
                if (-not $R -or ($null -ne $R.status -and ($R.status -lt 200 -or $R.status -ge 300))) {
                    $Errors.Add("Settings for '$($P.name)' could not be read")
                    continue
                }
                $Hit = @($R.body.value | Where-Object {
                        $_.settingInstance.settingDefinitionId -eq $SettingId -and [string]$_.settingInstance.choiceSettingValue.value -eq $BlockValue
                    })
                if ($Hit.Count -gt 0) {
                    $Count = @($P.assignments).Count
                    $Findings.Add([pscustomobject]@{
                            Id              = "Catalog|$($P.id)"
                            Kind            = 'SettingsCatalog'
                            PolicyId        = [string]$P.id
                            PolicyName      = [string]$P.name
                            Assigned        = $Count -gt 0
                            AssignmentCount = $Count
                            Message         = "Settings Catalog policy '$($P.name)' sets 'Exclude WU Drivers In Quality Update' to Exclude$(if ($Count -eq 0) { ', though it is not assigned' }). Devices it targets never receive drivers from a driver update profile; remove the setting or set it to Allow."
                        })
                }
            }
        }
    } catch {
        $Errors.Add("Settings Catalog policies: $((Get-CippException -Exception $_).NormalizedError)")
    }

    [pscustomobject]@{
        Findings = @($Findings)
        Errors   = @($Errors)
    }
}
