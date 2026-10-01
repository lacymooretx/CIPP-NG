function Invoke-CippAzureResourceCheck {
    <#
    .SYNOPSIS
        The common AZ_ pattern: every resource of some type must satisfy a condition
    .DESCRIPTION
        Runs $Check against each resource of the given types. $Check returns $null (compliant),
        a string (non-compliant; the string is the finding), or '#skip:<reason>' to leave the
        resource out (for example when a sub-call failed and the setting is unknown).
        Returns @{Status; Markdown} for Invoke-CippAzureTest:
          - no resources of the type          → Skipped (not applicable)
          - every evaluated resource compliant → Passed
          - otherwise                          → $FailStatus with a findings table
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string[]]$Type,
        [Parameter(Mandatory = $true)][scriptblock]$Check,
        [Parameter(Mandatory = $true)][string]$Requirement,
        [ValidateSet('Failed', 'Investigate')][string]$FailStatus = 'Failed'
    )

    $Resources = @(Get-CippAzureResourcesOfType -Context $Context -Type $Type)
    if ($Resources.Count -eq 0) {
        return @{ Status = 'Skipped'; Markdown = "Not applicable: no $($Type -join ' / ') resources in the onboarded subscriptions." }
    }

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Skipped = [System.Collections.Generic.List[string]]::new()
    $Evaluated = 0
    foreach ($R in $Resources) {
        $Finding = & $Check $R
        if ($Finding -is [string] -and $Finding.StartsWith('#skip:')) {
            $Skipped.Add("$($R.name) ($($Finding.Substring(6)))")
            continue
        }
        $Evaluated++
        if ($Finding) {
            $Findings.Add([ordered]@{
                    Resource         = $R.name
                    'Resource group' = $R.resourceGroup
                    Subscription     = $Context.SubName[[string]$R.subscriptionId] ?? $R.subscriptionId
                    Finding          = [string]$Finding
                })
        }
    }

    $Notes = if ($Skipped.Count) { "`n`nNot evaluated ($($Skipped.Count)): $($Skipped -join '; ')" } else { '' }
    if ($Evaluated -eq 0) {
        return @{ Status = 'Skipped'; Markdown = "Could not evaluate any resource.$Notes" }
    }
    if ($Findings.Count -eq 0) {
        return @{ Status = 'Passed'; Markdown = "All $Evaluated resource(s) meet the requirement: $Requirement$Notes" }
    }
    @{
        Status   = $FailStatus
        Markdown = "$($Findings.Count) of $Evaluated resource(s) do not meet the requirement: $Requirement`n`n$(Format-CippAzureFindingTable -Rows $Findings)$Notes"
    }
}
