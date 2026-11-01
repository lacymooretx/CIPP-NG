function Get-CIPPEnrollmentDiscovery {
    <#
    .SYNOPSIS
        Reads a tenant's Intune enrollment discovery state: CNAMEs per verified domain, MDM user scope, Windows devices.
    .DESCRIPTION
        - Verified domains (v1.0 /domains); *.onmicrosoft.com and *.mail.onmicrosoft.com are skipped (nobody can add a
          CNAME there), and so are domains with no supportedServices: third-party relay domains such as
          <id>.smtp.exclaimer.cloud, seen verified in both aspendora.com and 3endt.com.
        - enterpriseenrollment.<domain> and enterpriseregistration.<domain> CNAMEs via Resolve-DnsHttpsQuery (DoH,
          same resolver the Domain Analyser uses).
        - MDM user scope: beta policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000 with
          includedGroups expanded (appliesTo none / all / selected).
        - Windows managed devices (beta managedDevices, retired/wiped excluded) and the hybrid-joined ones enrolled by
          GPO or co-management (joinType hybridAzureADJoined with deviceEnrollmentType windowsCoManagement,
          windowsAutoEnrollment or userEnrollment).
        Findings come from Test-CIPPEnrollmentDiscovery. A read that fails is listed in Errors; it never fails the
        whole report. Report only. Aspendora fork addition (Vikunja CIPP-22).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $Errors = [System.Collections.Generic.List[string]]::new()

    $MdmScope = $null
    try {
        $Policy = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000?$expand=includedGroups' -tenantid $TenantFilter -ErrorAction Stop
        $MdmScope = [pscustomobject]@{
            AppliesTo = [string]$Policy.appliesTo
            Groups    = @($Policy.includedGroups | ForEach-Object { [string]($_.displayName ?? $_.id) })
            GroupIds  = @($Policy.includedGroups | ForEach-Object { [string]$_.id })
        }
    } catch {
        $Errors.Add("MDM user scope: $((Get-CippException -Exception $_).NormalizedError)")
    }

    $WindowsDevices = @()
    try {
        $WindowsDevices = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,joinType,deviceEnrollmentType,managementState&`$top=999" -tenantid $TenantFilter -ErrorAction Stop |
                Where-Object { $_.id -and (Test-CIPPManagedDeviceActive -Device $_) })
    } catch {
        $Errors.Add("Windows managed devices: $((Get-CippException -Exception $_).NormalizedError)")
    }
    $HybridDevices = @($WindowsDevices | Where-Object {
            $_.joinType -eq 'hybridAzureADJoined' -and $_.deviceEnrollmentType -in @('windowsCoManagement', 'windowsAutoEnrollment', 'userEnrollment')
        } | ForEach-Object { [pscustomobject]@{ DeviceName = [string]$_.deviceName; EnrollmentType = [string]$_.deviceEnrollmentType } })

    $DomainRows = [System.Collections.Generic.List[object]]::new()
    try {
        # A verified domain with no supportedServices is a third-party relay domain (e.g. <id>.smtp.exclaimer.cloud)
        # nobody signs in with; DNS for it is not ours to fix, so it is skipped.
        $Verified = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isVerified,isInitial,supportedServices' -tenantid $TenantFilter -ErrorAction Stop |
                Where-Object { $_.isVerified -eq $true -and $_.id -notmatch '\.onmicrosoft\.com$' -and @($_.supportedServices).Count -gt 0 })
    } catch {
        $Verified = @()
        $Errors.Add("Verified domains: $((Get-CippException -Exception $_).NormalizedError)")
    }
    $Cname = {
        param($Name)
        $R = Resolve-DnsHttpsQuery -Domain $Name -RecordType CNAME -ErrorAction Stop
        [string](@($R.Answer | Where-Object { $_.type -eq 5 } | Select-Object -First 1).data) -replace '\.$'
    }
    foreach ($D in $Verified) {
        $Row = [pscustomobject]@{ Domain = [string]$D.id; EnrollmentTarget = ''; RegistrationTarget = ''; LookupError = $false }
        try {
            $Row.EnrollmentTarget = & $Cname "enterpriseenrollment.$($D.id)"
            $Row.RegistrationTarget = & $Cname "enterpriseregistration.$($D.id)"
        } catch {
            $Row.LookupError = $true
            $Errors.Add("DNS lookup for $($D.id): $($_.Exception.Message)")
        }
        $DomainRows.Add($Row)
    }

    $Findings = @(Test-CIPPEnrollmentDiscovery -Domains @($DomainRows) -MdmScope $MdmScope -WindowsDeviceCount $WindowsDevices.Count -HybridDevices $HybridDevices)

    [pscustomobject]@{
        Tenant             = $TenantFilter
        MdmScope           = if ($MdmScope) { $MdmScope.AppliesTo } else { 'unknown' }
        MdmScopeGroups     = if ($MdmScope) { @($MdmScope.Groups) } else { @() }
        WindowsDeviceCount = $WindowsDevices.Count
        HybridDeviceCount  = $HybridDevices.Count
        Domains            = @($DomainRows)
        Findings           = $Findings
        Errors             = @($Errors)
    }
}
