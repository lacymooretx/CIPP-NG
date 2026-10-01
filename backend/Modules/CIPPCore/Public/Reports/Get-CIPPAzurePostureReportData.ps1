function Get-CIPPAzurePostureReportData {
    <#
    .SYNOPSIS
        Gather the Azure Posture Report model for a single tenant.
    .DESCRIPTION
        Builds the Aspendora / CIPP "Azure Posture Report" from the tenant's latest AZ_ test
        results (CippTestResults, written by the nightly test run) and the Azure cache:
          - one executive finding per check category (drives the grade, so a tenant with many
            resources isn't scored down once per check)
          - subscriptions in scope
          - results per category, and a remediation worklist parsed from each failing check
          - coverage per framework, from Tests/Azure/frameworks.json (indicative mapping)
        A tenant with no readable Azure subscription gets a short report explaining how to onboard.
        Every section is gathered defensively - one failure never kills the report.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()

    function Add-Finding($Title, $Status, $Detail) {
        $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail })
    }
    # $Rows must be a List[object] whose elements are per-row cell arrays (no flattening).
    function Add-Section($Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    function Invoke-Section($Name, [scriptblock]$Builder) {
        try { & $Builder } catch {
            $r = New-RowList; $r.Add(@("$($_.Exception.Message)"))
            Add-Section $Name 'warn' 'This section could not be retrieved.' @('Error') $r 'Data unavailable.'
        }
    }
    function Get-FirstLine($Markdown) { (("$Markdown" -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1) -replace '[:]\s*$', '' }

    # ---- tenant + data ------------------------------------------------------------
    $Tenant = Get-Tenants -TenantFilter $TenantFilter -IncludeErrors | Select-Object -First 1
    $TenantName = $Tenant.displayName ?? $TenantFilter
    $Domain = $Tenant.defaultDomainName ?? $TenantFilter

    $ResultsTable = Get-CippTable -tablename 'CippTestResults'
    $Results = @(Get-CIPPAzDataTableEntity @ResultsTable -Filter "PartitionKey eq '$Domain' and RowKey ge 'AZ_' and RowKey lt 'AZ``'")
    $Subscriptions = @(New-CIPPDbRequest -TenantFilter $Domain -Type 'AzureSubscriptions')

    $Model = @{
        Title         = 'Azure Posture Report'
        TenantName    = $TenantName
        TenantDomain  = $Domain
        GeneratedDate = (Get-Date).ToString('dd MMMM yyyy')
        Findings      = $Findings
        Sections      = $Sections
    }

    if ($Results.Count -eq 0) {
        $Detail = if ($Subscriptions.Count -gt 0) {
            "CIPP can read $($Subscriptions.Count) subscription(s), but the Azure checks have not run yet. They run nightly after the Azure data collection; run them now from the Tests page."
        } else {
            'CIPP cannot read any Azure subscription in this tenant. Grant the CIPP-SAM application the Reader role on each subscription (see /api/ListAzureAccess for the exact commands), then wait for the next nightly collection.'
        }
        Add-Finding 'Azure access' 'info' $Detail
        return $Model
    }

    $AsOf = ($Results | Where-Object { $_.Timestamp } | ForEach-Object { [datetimeoffset]$_.Timestamp } | Sort-Object -Descending | Select-Object -First 1)
    $Valid = @('Passed', 'Failed', 'Investigate', 'Skipped', 'Informational')
    $Results = @($Results | Where-Object { $Valid -contains $_.Status } | Sort-Object RowKey)

    $StatusOf = {
        param($Rows)
        $Bad = @($Rows | Where-Object { $_.Status -eq 'Failed' })
        if (@($Bad | Where-Object { $_.Risk -in @('High', 'Medium') }).Count) { 'fail' }
        elseif ($Bad.Count -or @($Rows | Where-Object { $_.Status -eq 'Investigate' }).Count) { 'warn' }
        else { 'pass' }
    }

    # ---- executive findings: one per category ---------------------------------------
    Invoke-Section 'Summary' {
        foreach ($Group in ($Results | Group-Object Category | Sort-Object Name)) {
            $Rows = @($Group.Group)
            $Applicable = @($Rows | Where-Object { $_.Status -ne 'Skipped' })
            if ($Applicable.Count -eq 0) { continue }
            $St = & $StatusOf $Applicable
            $Failing = @($Applicable | Where-Object { $_.Status -in @('Failed', 'Investigate') })
            $Detail = if ($Failing.Count) {
                "$($Failing.Count) of $($Applicable.Count) applicable check(s) need attention: " + (($Failing | ForEach-Object { $_.Name }) -join '; ') + '.'
            } else { "All $($Applicable.Count) applicable check(s) pass." }
            Add-Finding $Group.Name $St $Detail
        }
    }

    # ---- scope ---------------------------------------------------------------------
    Invoke-Section 'Subscriptions in scope' {
        $Defender = @{}
        foreach ($D in @(New-CIPPDbRequest -TenantFilter $Domain -Type 'AzureDefender')) { $Defender[[string]$D.subscriptionId] = $D }
        $r = New-RowList
        foreach ($S in $Subscriptions) {
            $D = $Defender[[string]$S.subscriptionId]
            $Dfc = if (-not $D) { 'Unknown' } elseif ($D.securityProviderRegistered -eq $false) { 'Never activated' } else {
                $On = @($D.pricings | Where-Object { $_.properties.pricingTier -eq 'Standard' } | ForEach-Object { $_.name })
                if ($On.Count) { "Paid plans: $($On -join ', ')" } else { 'Free tier only' }
            }
            $r.Add(@($S.displayName, $S.subscriptionId, $S.state, $Dfc))
        }
        $AsOfText = if ($AsOf) { " Results as of $($AsOf.ToString('yyyy-MM-dd HH:mm')) UTC." } else { '' }
        Add-Section 'Subscriptions in scope' 'info' "Subscriptions the CIPP-SAM application can read (Reader role).$AsOfText" @('Subscription', 'Id', 'State', 'Defender for Cloud') $r 'No subscriptions.'
    }

    # ---- results per category ------------------------------------------------------
    foreach ($Group in ($Results | Group-Object Category | Sort-Object Name)) {
        Invoke-Section $Group.Name {
            $r = New-RowList
            $Order = @{ Failed = 0; Investigate = 1; Passed = 2; Informational = 3; Skipped = 4 }
            foreach ($T in ($Group.Group | Sort-Object { $Order[$_.Status] }, RowKey)) {
                $r.Add(@($T.RowKey, $T.Name, $T.Risk, $T.Status, (Get-FirstLine $T.ResultMarkdown)))
            }
            $Applicable = @($Group.Group | Where-Object { $_.Status -ne 'Skipped' })
            $St = if ($Applicable.Count) { & $StatusOf $Applicable } else { 'info' }
            Add-Section "$($Group.Name) checks" $St "$(@($Group.Group | Where-Object { $_.Status -eq 'Passed' }).Count) passed, $(@($Group.Group | Where-Object { $_.Status -eq 'Failed' }).Count) failed, $(@($Group.Group | Where-Object { $_.Status -eq 'Investigate' }).Count) to investigate, $(@($Group.Group | Where-Object { $_.Status -eq 'Skipped' }).Count) not applicable." @('Check', 'Requirement', 'Risk', 'Status', 'Result') $r 'No checks.'
        }
    }

    # ---- remediation worklist --------------------------------------------------------
    Invoke-Section 'Remediation worklist' {
        $r = New-RowList
        $RiskOrder = @{ High = 0; Medium = 1; Low = 2; Informational = 3 }
        foreach ($T in ($Results | Where-Object { $_.Status -in @('Failed', 'Investigate') } | Sort-Object { $RiskOrder[$_.Risk] }, RowKey)) {
            $Table = ConvertFrom-CippMarkdownTable -Markdown $T.ResultMarkdown
            if (-not $Table) {
                $r.Add(@($T.RowKey, $T.Risk, $T.Status, '', (Get-FirstLine $T.ResultMarkdown)))
                continue
            }
            $FindingIdx = [array]::IndexOf($Table.Columns, 'Finding')
            $SubIdx = [array]::IndexOf($Table.Columns, 'Subscription')
            foreach ($Row in $Table.Rows) {
                $Item = $Row[0]
                if ($SubIdx -gt 0) { $Item = "$Item ($($Row[$SubIdx]))" }
                $Detail = if ($FindingIdx -ge 0) { $Row[$FindingIdx] } else {
                    (@(for ($i = 1; $i -lt $Row.Count; $i++) { "$($Table.Columns[$i]): $($Row[$i])" }) -join '; ')
                }
                $r.Add(@($T.RowKey, $T.Risk, $T.Status, $Item, $Detail))
                if ($r.Count -ge 400) { break }
            }
            if ($r.Count -ge 400) { break }
        }
        $St = if ($r.Count) { 'warn' } else { 'pass' }
        Add-Section 'Remediation worklist' $St "Every resource or subscription that failed a check, highest risk first. Remediation steps for each check are on the CIPP Tests → Azure tab." @('Check', 'Risk', 'Status', 'Item', 'Finding') $r 'Nothing to remediate.'
    }

    # ---- framework coverage --------------------------------------------------------
    Invoke-Section 'Framework coverage' {
        $Path = Join-Path $env:CIPPRootPath 'Modules' 'CIPPTests' 'Public' 'Tests' 'Azure' 'frameworks.json'
        if (-not (Test-Path $Path)) {
            $Module = Get-Module -Name CIPPTests -ListAvailable | Select-Object -First 1
            if ($Module) { $Path = Join-Path $Module.ModuleBase 'Public' 'Tests' 'Azure' 'frameworks.json' }
        }
        $Fw = Get-Content -Path $Path -Raw | ConvertFrom-Json -AsHashtable
        $ByTest = @{}
        foreach ($T in $Results) { $ByTest[$T.RowKey] = $T }

        foreach ($Key in $Fw.frameworks.Keys) {
            # control → the tests (via their themes) that provide evidence for it
            $Controls = [ordered]@{}
            foreach ($TestId in $Fw.tests.Keys) {
                foreach ($Theme in $Fw.tests[$TestId]) {
                    foreach ($Control in @($Fw.themes[$Theme][$Key])) {
                        if (-not $Control) { continue }
                        if (-not $Controls.Contains($Control)) { $Controls[$Control] = [System.Collections.Generic.HashSet[string]]::new() }
                        [void]$Controls[$Control].Add($TestId)
                    }
                }
            }
            $r = New-RowList
            $AnyFail = $false; $AnyWarn = $false
            foreach ($Control in ($Controls.Keys | Sort-Object { [regex]::Replace($_, '\d+', { param($m) $m.Value.PadLeft(4, '0') }) })) {
                $Ts = @($Controls[$Control] | ForEach-Object { $ByTest[$_] } | Where-Object { $_ -and $_.Status -ne 'Skipped' })
                if ($Ts.Count -eq 0) { continue }
                $P = @($Ts | Where-Object { $_.Status -in @('Passed', 'Informational') }).Count
                $F = @($Ts | Where-Object { $_.Status -eq 'Failed' }).Count
                $I = @($Ts | Where-Object { $_.Status -eq 'Investigate' }).Count
                if ($F) { $AnyFail = $true } elseif ($I) { $AnyWarn = $true }
                $State = if ($F) { 'Gaps found' } elseif ($I) { 'Review' } else { 'No gaps found' }
                $r.Add(@($Control, $State, $P, $F, $I, ((@($Ts | Where-Object { $_.Status -in @('Failed', 'Investigate') } | ForEach-Object { $_.RowKey }) | Sort-Object) -join ', ')))
            }
            $St = if ($AnyFail) { 'fail' } elseif ($AnyWarn) { 'warn' } else { 'pass' }
            Add-Section "Framework: $($Fw.frameworks[$Key])" $St "$($Fw.note) Only controls with at least one applicable check are listed." @('Control', 'Technical evidence', 'Checks passing', 'Failing', 'To investigate', 'Checks needing attention') $r 'No applicable controls.'
        }
    }

    return $Model
}
