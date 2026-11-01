# Pester tests for Invoke-ExecEditCAPolicyFull
# The save is a PATCH, so what the body leaves out keeps whatever the tenant policy already had.
# These pin the two halves of that: emptied collections go out as [], and a condition block the
# editor emptied goes out as null rather than being dropped or sent half-populated.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-ExecEditCAPolicyFull.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-ExecEditCAPolicyFull.ps1 under Modules/' }

    # The Functions worker exposes [HttpStatusCode] as an accelerator; register it for tests.
    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))

    class HttpResponseContext {
        [object]$StatusCode
        [object]$Body
    }

    # The canonicalizer is the real one - that is the behaviour under test.
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Functions/Format-CIPPCAPolicy.ps1')

    function New-GraphPOSTRequest {
        [CmdletBinding()] param($uri, $tenantid, $type, $body, $asApp)
        $script:LastPatch = @{ Uri = $uri; Type = $type; Body = $body }
    }
    function Write-LogMessage { [CmdletBinding()] param($API, $tenant, $headers, $message, $sev, $LogData) }
    function Get-CippException { [CmdletBinding()] param($Exception) $Exception }
    # Aspendora fork (Vikunja CIPP-5): the pre-flight gate. The tenant policy is disabled unless a test says otherwise.
    $script:ExistingState = 'disabled'
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid) [pscustomobject]@{ id = 'policy-guid'; state = $script:ExistingState } }
    function Invoke-CIPPCAPreflight { [CmdletBinding()] param($TenantFilter, $PolicyId, $Policy, $ExistingPolicy, $Headers) $script:PreflightCalls++; $script:PreflightResult }
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPreflight/Resolve-CIPPCAPreflightGate.ps1')

    . $FunctionPath

    function Invoke-Edit ($PolicyBody, $Override) {
        $script:LastPatch = $null
        $Request = @{
            Params  = @{ CIPPEndpoint = 'ExecEditCAPolicyFull' }
            Headers = @{}
            Query   = @{}
            Body    = [pscustomobject]@{
                tenantFilter = 'contoso.onmicrosoft.com'
                PolicyId     = 'policy-guid'
                PolicyBody   = ($PolicyBody | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
            }
        }
        if ($null -ne $Override) { $Request.Body | Add-Member -NotePropertyName PreflightOverride -NotePropertyValue $Override }
        $Response = Invoke-ExecEditCAPolicyFull -Request $Request
        return @{ Response = $Response; Sent = $(if ($script:LastPatch.Body) { $script:LastPatch.Body | ConvertFrom-Json }) }
    }
}

Describe 'Invoke-ExecEditCAPolicyFull' {

    Context 'a policy whose blocks the editor emptied' {
        BeforeAll {
            $script:Result = Invoke-Edit @{
                displayName     = 'CA201'
                state           = 'disabled'
                conditions      = @{
                    clientAppTypes = @('all')
                    applications   = @{ includeApplications = @('All'); excludeApplications = @() }
                    users          = @{ includeUsers = @('All'); includeGroups = @(); excludeGroups = @() }
                    platforms      = $null
                    devices        = $null
                }
                grantControls   = @{ operator = 'OR'; builtInControls = @('mfa') }
                sessionControls = $null
            }
            $script:Sent = $script:Result.Sent
        }

        It 'returns OK' {
            $script:Result.Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        }

        It 'PATCHes the policy by id' {
            $script:LastPatch.Type | Should -Be 'PATCH'
            $script:LastPatch.Uri | Should -Be 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies/policy-guid'
        }

        It 'sends the emptied collections as [] so Graph clears them' {
            $script:LastPatch.Body | Should -Match '"includeGroups":\[\]'
            $script:LastPatch.Body | Should -Match '"excludeApplications":\[\]'
        }

        It 'restores collections the body omitted as [] - a partial body must still clear them' {
            # The form never sent excludeUsers at all; the canonicalizer says its absence out loud.
            $script:LastPatch.Body | Should -Match '"excludeUsers":\[\]'
            $script:Sent.conditions.users.PSObject.Properties.Name | Should -Contain 'excludeRoles'
        }

        It 'sends the emptied <Block> block as null rather than dropping it' -ForEach @(
            @{ Block = 'platforms' }
            @{ Block = 'devices' }
        ) {
            $script:Sent.conditions.PSObject.Properties.Name | Should -Contain $Block
            $script:Sent.conditions.$Block | Should -BeNullOrEmpty
        }

        It 'sends sessionControls as null rather than dropping it' {
            $script:Sent.PSObject.Properties.Name | Should -Contain 'sessionControls'
            $script:Sent.sessionControls | Should -BeNullOrEmpty
        }

        It 'leaves the assignments the user kept alone' {
            $script:Sent.conditions.users.includeUsers | Should -Be @('All')
            $script:Sent.grantControls.builtInControls | Should -Be @('mfa')
            $script:Sent.displayName | Should -Be 'CA201'
        }
    }

    Context 'a half-populated block that Graph would reject' {
        It 'collapses platforms with no includePlatforms to null' {
            $Result = Invoke-Edit @{
                displayName = 'CA201'
                conditions  = @{
                    users     = @{ includeUsers = @('All') }
                    platforms = @{ includePlatforms = @(); excludePlatforms = @() }
                }
            }
            $Result.Sent.conditions.platforms | Should -BeNullOrEmpty
        }

        It 'keeps a platforms block that names a platform' {
            $Result = Invoke-Edit @{
                displayName = 'CA201'
                conditions  = @{
                    users     = @{ includeUsers = @('All') }
                    platforms = @{ includePlatforms = @('android'); excludePlatforms = @() }
                }
            }
            $Result.Sent.conditions.platforms.includePlatforms | Should -Be @('android')
        }
    }

    Context 'read-only properties' {
        It 'never PATCHes id or createdDateTime back to Graph' {
            $Result = Invoke-Edit @{
                displayName     = 'CA201'
                id              = 'policy-guid'
                createdDateTime = '2026-01-01T00:00:00Z'
                templateId      = 'template-guid'
                conditions      = @{ users = @{ includeUsers = @('All') } }
            }
            $Names = $Result.Sent.PSObject.Properties.Name
            $Names | Should -Not -Contain 'id'
            $Names | Should -Not -Contain 'createdDateTime'
            $Names | Should -Not -Contain 'templateId'
        }
    }

    Context 'CA pre-flight gate (Aspendora fork, Vikunja CIPP-5)' {
        BeforeEach {
            $script:PreflightCalls = 0
            $script:ExistingState = 'disabled'
            $script:PreflightResult = [pscustomobject]@{
                Passed = $false; Status = 'Fail'; PolicyName = 'CA201'
                Checks = @([pscustomobject]@{ Key = 'BreakGlassExcluded'; Check = 'Break-glass accounts excluded'; Status = 'Fail'; Message = 'bg@contoso.onmicrosoft.com in scope'; Fix = '' })
            }
            $script:Body = @{ displayName = 'CA201'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') } }; grantControls = @{ operator = 'OR'; builtInControls = @('block') } }
        }

        It 'blocks enabling when the pre-flight fails, without PATCHing' {
            $Result = Invoke-Edit $script:Body
            $Result.Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
            $Result.Response.Body.Results | Should -Match 'pre-flight'
            $Result.Response.Body.Preflight.Status | Should -Be 'Fail'
            $script:LastPatch | Should -BeNullOrEmpty
        }

        It 'saves when PreflightOverride is true' {
            $Result = Invoke-Edit $script:Body $true
            $Result.Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
            $script:LastPatch.Type | Should -Be 'PATCH'
        }

        It 'treats the string "false" as no override' {
            $Result = Invoke-Edit $script:Body 'false'
            $Result.Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
        }

        It 'saves when the pre-flight passes' {
            $script:PreflightResult = [pscustomobject]@{ Passed = $true; Status = 'Pass'; PolicyName = 'CA201'; Checks = @() }
            (Invoke-Edit $script:Body).Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        }

        It 'checks an edit that omits state on an already-enabled policy' {
            $script:ExistingState = 'enabled'
            $B = $script:Body.Clone(); $B.Remove('state')
            (Invoke-Edit $B).Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
            $script:PreflightCalls | Should -Be 1
        }

        It 'does not run for report-only or disabled saves' {
            $B = $script:Body.Clone(); $B.state = 'enabledForReportingButNotEnforced'
            (Invoke-Edit $B).Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
            $script:PreflightCalls | Should -Be 0
        }
    }

    Context 'validation' {
        It 'rejects a request with no PolicyBody' {
            $Request = @{
                Params  = @{ CIPPEndpoint = 'ExecEditCAPolicyFull' }
                Headers = @{}
                Query   = @{}
                Body    = [pscustomobject]@{ tenantFilter = 'contoso.onmicrosoft.com'; PolicyId = 'policy-guid' }
            }
            (Invoke-ExecEditCAPolicyFull -Request $Request).StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }

        It 'rejects a request with no PolicyId' {
            $Request = @{
                Params  = @{ CIPPEndpoint = 'ExecEditCAPolicyFull' }
                Headers = @{}
                Query   = @{}
                Body    = [pscustomobject]@{ tenantFilter = 'contoso.onmicrosoft.com'; PolicyBody = [pscustomobject]@{ displayName = 'CA201' } }
            }
            (Invoke-ExecEditCAPolicyFull -Request $Request).StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }
    }
}
