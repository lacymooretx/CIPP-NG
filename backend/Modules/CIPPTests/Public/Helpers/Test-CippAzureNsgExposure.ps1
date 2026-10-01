function Test-CippAzureNsgExposure {
    <#
    .SYNOPSIS
        Inbound Allow rules in an NSG that expose the given ports/protocol to the internet
    .DESCRIPTION
        Returns a short description per matching rule. "Internet" means a source of *, Any,
        Internet, 0.0.0.0/0, ::/0 or any /0 prefix. Ports match single values, ranges (3000-4000)
        and *. Protocol '*' in a rule matches every protocol asked for.
    .PARAMETER Ports
        Ports to look for; omit (or pass '*') to match only rules that open every port.
    .PARAMETER Protocol
        'Tcp', 'Udp' or '*' (any).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Nsg,
        [int[]]$Ports,
        [string]$Protocol = '*'
    )

    $InternetSources = @('*', 'any', 'internet', '0.0.0.0/0', '0.0.0.0', '::/0', '<nw>/0', '/0')
    foreach ($Rule in @($Nsg.properties.securityRules)) {
        $P = $Rule.properties
        if ($P.direction -ne 'Inbound' -or $P.access -ne 'Allow') { continue }

        $Sources = @($P.sourceAddressPrefix) + @($P.sourceAddressPrefixes) | Where-Object { $_ }
        $FromInternet = @($Sources | Where-Object { $InternetSources -contains ([string]$_).ToLower() -or ([string]$_).EndsWith('/0') })
        if ($FromInternet.Count -eq 0) { continue }

        if ($Protocol -ne '*' -and $P.protocol -ne '*' -and $P.protocol -ne $Protocol) { continue }

        $Ranges = @($P.destinationPortRange) + @($P.destinationPortRanges) | Where-Object { $_ }
        $AllPorts = [bool]($Ranges | Where-Object { $_ -eq '*' -or $_ -eq '0-65535' })
        $Hit = if (-not $Ports) { $AllPorts } else {
            $AllPorts -or [bool](@($Ports) | Where-Object {
                    $Port = $_
                    @($Ranges | Where-Object {
                            if ($_ -match '^(\d+)-(\d+)$') { $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2] }
                            elseif ($_ -match '^\d+$') { [int]$_ -eq $Port }
                            else { $false }
                        }).Count -gt 0
                })
        }
        if ($Hit) { "$($Rule.name) (prio $($P.priority), $($P.protocol) $($Ranges -join ',') from $($FromInternet -join ','))" }
    }
}
