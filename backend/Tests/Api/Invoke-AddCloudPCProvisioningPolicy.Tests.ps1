# Creating a provisioning policy is where a Windows 365 rollout is actually configured, and the
# two domain-join shapes are mutually exclusive in ways Graph only reports as a schema error:
# hybridAzureADJoin needs an on-premises network connection, Entra-only join needs a region (or a
# connection, if you bring your own vNet). Validating here turns a confusing Graph rejection into
# a sentence that says which field is missing.
#
# The other thing pinned below: creating a policy assigns it to nothing. No Cloud PC is built, and
# no licence is consumed, until it is deliberately assigned. That separation is intentional.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs += $message }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }
    function New-GraphPOSTRequest {
        param($uri, $tenantid, $body, $AsApp, $ErrorAction)
        $script:PostedUri = $uri
        $script:PostedBody = $body
        $script:PostAsApp = $AsApp
        return [pscustomobject]@{ id = 'new-policy-id'; displayName = 'created' }
    }

    # The entrypoint calls ConvertTo-CIPPBoolean; the compiled module has it, a dot-sourced test does not.
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/CloudPC/Invoke-AddCloudPCProvisioningPolicy.ps1')

    function New-AddRequest {
        param([hashtable]$Overrides = @{})
        $BodyObj = @{
            tenantFilter = 'contoso.com'
            DisplayName  = 'Finance Cloud PCs'
            ImageId      = 'microsoftwindowsdesktop_windows-ent-cpc_win11-25h2-ent-cpc-m365'
            RegionName   = 'centralus'
        }
        foreach ($k in $Overrides.Keys) {
            if ($null -eq $Overrides[$k]) { $BodyObj.Remove($k) } else { $BodyObj[$k] = $Overrides[$k] }
        }
        [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'AddCloudPCProvisioningPolicy' }
            Headers = @{}
            Query   = [pscustomobject]@{}
            Body    = [pscustomobject]$BodyObj
        }
    }
    function Get-PostedPolicy { $script:PostedBody | ConvertFrom-Json }
}

Describe 'AddCloudPCProvisioningPolicy' {
    BeforeEach {
        $script:Logs = @()
        $script:PostedBody = $null
        $script:PostedUri = $null
    }

    It 'creates an Entra-join policy against a region' {
        $Response = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest)
        $Policy = Get-PostedPolicy

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $Response.Body.PolicyId | Should -Be 'new-policy-id'
        $Policy.displayName | Should -Be 'Finance Cloud PCs'
        $Policy.domainJoinConfigurations[0].domainJoinType | Should -Be 'azureADJoin'
        $Policy.domainJoinConfigurations[0].regionName | Should -Be 'centralus'
        $script:PostAsApp | Should -BeTrue
    }

    It 'says plainly that nothing is provisioned until the policy is assigned' {
        $Response = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest)
        $Response.Body.Results | Should -Match 'not assigned to any group'
    }

    It 'uses the on-premises connection when one is supplied, instead of a region' {
        $Response = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest @{ OnPremisesConnectionId = 'conn-1'; RegionName = $null })
        $Policy = Get-PostedPolicy

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $Policy.domainJoinConfigurations[0].onPremisesConnectionId | Should -Be 'conn-1'
        $Policy.domainJoinConfigurations[0].PSObject.Properties.Name | Should -Not -Contain 'regionName'
    }

    It 'refuses hybrid join with no network connection, naming the field' {
        $Response = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest @{ DomainJoinType = 'hybridAzureADJoin' })

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'OnPremisesConnectionId'
        $Response.Body.Results | Should -Match 'healthCheckStatus'
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'refuses Entra join with neither a region nor a connection' {
        $Response = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest @{ RegionName = $null })

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'RegionName'
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'requires an ImageId and points at how to get one' {
        $Response = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest @{ ImageId = $null })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match 'ListCloudPCGalleryImages'
    }

    It 'requires a DisplayName' {
        $Response = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest @{ DisplayName = $null })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'rejects an unknown <Field> rather than letting Graph guess' -ForEach @(
        @{ Field = 'ImageType'; Value = 'homemade' }
        @{ Field = 'ProvisioningType'; Value = 'borrowed' }
        @{ Field = 'DomainJoinType'; Value = 'workgroup' }
    ) {
        $Response = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest @{ $Field = $Value })
        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match "Invalid $Field"
        $script:PostedBody | Should -BeNullOrEmpty
    }

    It 'defaults single sign-on on, and honours an explicit false' {
        $null = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest)
        (Get-PostedPolicy).enableSingleSignOn | Should -BeTrue

        $script:PostedBody = $null
        $null = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest @{ EnableSingleSignOn = 'false' })
        (Get-PostedPolicy).enableSingleSignOn | Should -BeFalse
    }

    It 'omits the naming template entirely when none is given' {
        $null = Invoke-AddCloudPCProvisioningPolicy -Request (New-AddRequest)
        (Get-PostedPolicy).PSObject.Properties.Name | Should -Not -Contain 'cloudPcNamingTemplate'
    }
}
