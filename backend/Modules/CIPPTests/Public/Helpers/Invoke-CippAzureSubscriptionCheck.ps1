function Invoke-CippAzureSubscriptionCheck {
    <#
    .SYNOPSIS
        The per-subscription AZ_ pattern: every onboarded subscription must satisfy a condition
    .DESCRIPTION
        $Check receives the subscription id and returns $null (compliant), a finding string, or
        '#skip:<reason>' (not applicable / unknown). Returns @{Status; Markdown}.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][scriptblock]$Check,
        [Parameter(Mandatory = $true)][string]$Requirement,
        [ValidateSet('Failed', 'Investigate')][string]$FailStatus = 'Failed'
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Skipped = [System.Collections.Generic.List[string]]::new()
    $Evaluated = 0
    foreach ($Sub in $Context.Subscriptions) {
        $SubId = [string]$Sub.subscriptionId
        $Finding = & $Check $SubId
        if ($Finding -is [string] -and $Finding.StartsWith('#skip:')) {
            $Skipped.Add("$($Sub.displayName) ($($Finding.Substring(6)))")
            continue
        }
        $Evaluated++
        if ($Finding) { $Findings.Add([ordered]@{ Subscription = $Sub.displayName; 'Subscription id' = $SubId; Finding = [string]$Finding }) }
    }

    $Notes = if ($Skipped.Count) { "`n`nNot evaluated ($($Skipped.Count)): $($Skipped -join '; ')" } else { '' }
    if ($Evaluated -eq 0) { return @{ Status = 'Skipped'; Markdown = "Not applicable to any onboarded subscription.$Notes" } }
    if ($Findings.Count -eq 0) { return @{ Status = 'Passed'; Markdown = "All $Evaluated subscription(s) meet the requirement: $Requirement$Notes" } }
    @{
        Status   = $FailStatus
        Markdown = "$($Findings.Count) of $Evaluated subscription(s) do not meet the requirement: $Requirement`n`n$(Format-CippAzureFindingTable -Rows $Findings)$Notes"
    }
}
