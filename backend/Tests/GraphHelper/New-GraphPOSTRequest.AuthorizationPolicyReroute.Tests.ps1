# A bare beta `policies/authorizationPolicy` PATCH has to be rerouted, because beta exposes the
# resource as a collection and rejects PATCH on the bare singleton. It used to be rerouted to the
# *v1.0* singleton, which was silently wrong: beta and v1.0 do not share a schema here. beta has
# `permissionGrantPolicyIdsAssignedToDefaultUserRole` at the top level; v1.0 has the same data as
# `defaultUserRolePermissions.permissionGrantPoliciesAssigned`. Moving the URL without translating
# the body handed v1.0 a property it does not know - and v1.0 ignores unknown properties rather
# than rejecting them, so Graph answered 204, CIPP logged success, and nothing changed.
#
# The reroute must therefore stay on beta, using the child form the standards already PATCH.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper/New-GraphPOSTRequest.ps1'

    function Get-AuthorisedRequest { param($Uri, $TenantID) $true }
    function Get-GraphToken { param($tenantid, $scope, $AsApp, $SkipCache, [switch]$UseCertificate) @{ Authorization = 'Bearer stub' } }
    # The real one substitutes %tokens%; a body with none must come back byte-identical.
    function Get-CIPPTextReplacement { param($TenantFilter, $Text, [switch]$EscapeForJson) return $Text }
    function Get-CippUserAgent { 'CIPP-Test' }
    function Get-NormalizedError { param($Message) $Message }

    function Invoke-CIPPRestMethod {
        param($Uri, $Method, $Body, $Headers, $ContentType, [switch]$SkipHttpErrorCheck, $ResponseHeadersVariable)
        $script:LastCall = @{ Uri = [string]$Uri; Method = $Method; Body = $Body }
        return $null
    }

    . $FunctionPath
}

Describe 'New-GraphPOSTRequest authorizationPolicy reroute' {
    BeforeEach { $script:LastCall = $null }

    It 'reroutes a bare beta PATCH to the beta child form, not to v1.0' {
        New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/policies/authorizationPolicy' `
            -tenantid 'contoso.com' -type 'PATCH' -body '{"description":"x"}'

        $script:LastCall.Uri | Should -Be 'https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy'
        $script:LastCall.Uri | Should -Not -Match '/v1\.0/'
    }

    It 'passes a beta-shaped consent body through untouched' {
        # This is the exact payload that silently no-opped against v1.0 (CW #58402).
        $Body = '{"permissionGrantPolicyIdsAssignedToDefaultUserRole":["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}'
        New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/policies/authorizationPolicy' `
            -tenantid 'contoso.com' -type 'PATCH' -body $Body

        $script:LastCall.Uri | Should -Be 'https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy'
        # The body must reach a URL whose schema actually defines this property.
        $script:LastCall.Body | Should -Be $Body
    }

    It 'preserves a query string across the reroute' {
        New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/policies/authorizationPolicy?$select=description' `
            -tenantid 'contoso.com' -type 'PATCH' -body '{"description":"x"}'

        $script:LastCall.Uri | Should -Be 'https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy?$select=description'
    }

    It 'leaves the child form alone - it is already correct' {
        $Uri = 'https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy'
        New-GraphPOSTRequest -uri $Uri -tenantid 'contoso.com' -type 'PATCH' -body '{"description":"x"}'

        $script:LastCall.Uri | Should -Be $Uri
    }

    It 'leaves a v1.0 bare PATCH alone - DisableSelfServiceLicenses depends on it' {
        $Uri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        New-GraphPOSTRequest -uri $Uri -tenantid 'contoso.com' -type 'PATCH' -body '{"allowedToUseSSPR":true}'

        $script:LastCall.Uri | Should -Be $Uri
    }

    It 'only reroutes PATCH, not other verbs' {
        $Uri = 'https://graph.microsoft.com/beta/policies/authorizationPolicy'
        New-GraphPOSTRequest -uri $Uri -tenantid 'contoso.com' -type 'POST' -body '{"description":"x"}'

        $script:LastCall.Uri | Should -Be $Uri
    }
}
