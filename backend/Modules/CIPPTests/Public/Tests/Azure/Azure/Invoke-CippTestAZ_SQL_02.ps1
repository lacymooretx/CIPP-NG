function Invoke-CippTestAZ_SQL_02 {
    <#
    .SYNOPSIS
    Azure - Azure SQL firewall does not allow the whole internet
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_SQL_02' -Name 'Azure SQL firewall does not allow the whole internet' -Risk 'High' -Category 'Databases' -UserImpact 'Medium' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.sql/servers') -FailStatus 'Failed' -Requirement 'no firewall rule opens 0.0.0.0-255.255.255.255 or all Azure services' -Check {
            param($R)
            if ($R.properties.publicNetworkAccess -eq 'Disabled') { return $null }
            $C = $Ctx.Config[([string]$R.id).ToLower()]
            if (-not $C -or $C.errors.firewallRules) { return '#skip:firewall rules unavailable' }
            $Bad = foreach ($F in @($C.config.firewallRules)) {
                $S = $F.properties.startIpAddress; $E = $F.properties.endIpAddress
                if ($S -eq '0.0.0.0' -and $E -eq '255.255.255.255') { "$($F.name): all internet addresses" }
                elseif ($S -eq '0.0.0.0' -and $E -eq '0.0.0.0') { "$($F.name): all Azure services (any tenant)" }
            }
            if ($Bad) { $Bad -join '; ' }
        }
    }
}
