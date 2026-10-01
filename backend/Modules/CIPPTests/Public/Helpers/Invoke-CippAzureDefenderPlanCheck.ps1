function Invoke-CippAzureDefenderPlanCheck {
    <#
    .SYNOPSIS
        Is a Defender for Cloud plan on (Standard tier) in every subscription that needs it?
    .DESCRIPTION
        A subscription needs the plan when it holds at least one resource of $AppliesToTypes (or
        always, when no types are given). A subscription where Defender for Cloud was never activated
        fails outright; one whose pricing call failed for another reason is skipped.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string[]]$PlanNames,
        [Parameter(Mandatory = $true)][string]$PlanLabel,
        [string[]]$AppliesToTypes
    )

    Invoke-CippAzureSubscriptionCheck -Context $Context -Requirement "$PlanLabel is enabled (Standard tier)" -Check {
        param($SubId)
        if ($AppliesToTypes) {
            $InSub = @(Get-CippAzureResourcesOfType -Context $Context -Type $AppliesToTypes | Where-Object { $_.subscriptionId -eq $SubId })
            if ($InSub.Count -eq 0) { return '#skip:no applicable resources' }
        }
        $D = $Context.Defender[$SubId.ToLower()]
        if (-not $D) { return '#skip:no Defender data collected' }
        if ($D.securityProviderRegistered -eq $false) { return 'Defender for Cloud has never been activated (Microsoft.Security provider not registered)' }
        if ($null -eq $D.pricings) { return "#skip:pricing unavailable ($($D.errors.pricings))" }
        $On = @($D.pricings | Where-Object { $PlanNames -contains $_.name -and $_.properties.pricingTier -eq 'Standard' })
        if ($On.Count -eq 0) { "$PlanLabel is on the Free tier (off)" }
    }
}
