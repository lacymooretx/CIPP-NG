function Invoke-CippAzureTest {
    <#
    .SYNOPSIS
        Shared runner for the AZ_ (Azure subscription) tests
    .DESCRIPTION
        Builds the tenant's Azure context, runs the test's evaluator and wraps the outcome in a
        TestType 'Azure' result. Emits nothing when the tenant has no readable Azure subscription.
        An evaluator throw becomes a Failed result carrying the error, like the other suites.
    .PARAMETER Evaluate
        Receives the context; returns @{ Status = 'Passed'|'Failed'|'Investigate'|'Skipped'|'Informational'; Markdown = '...' }.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Tenant,
        [Parameter(Mandatory = $true)][string]$TestId,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('High', 'Medium', 'Low', 'Informational')][string]$Risk,
        [Parameter(Mandatory = $true)][string]$Category,
        [string]$UserImpact = 'Low',
        [string]$ImplementationEffort = 'Low',
        [Parameter(Mandatory = $true)][scriptblock]$Evaluate
    )

    $Common = @{
        TenantFilter         = $Tenant
        TestId               = $TestId
        TestType             = 'Azure'
        Name                 = $Name
        Risk                 = $Risk
        Category             = $Category
        UserImpact           = $UserImpact
        ImplementationEffort = $ImplementationEffort
    }

    try {
        $Context = Get-CippAzureTestContext -Tenant $Tenant
        if ($null -eq $Context) { return }
        $Outcome = & $Evaluate $Context
        $Scope = "Scope: $($Context.Subscriptions.Count) subscription(s): $(@($Context.Subscriptions.displayName) -join ', ')"
        Add-CippTestResult @Common -Status $Outcome.Status -ResultMarkdown "$($Outcome.Markdown)`n`n$Scope"
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Add-CippTestResult @Common -Status 'Failed' -ResultMarkdown "Test failed: $($ErrorMessage.NormalizedError)"
    }
}
