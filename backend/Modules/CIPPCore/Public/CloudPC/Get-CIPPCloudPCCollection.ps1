function Get-CIPPCloudPCCollection {
    <#
    .FUNCTIONALITY
    Internal
    .DESCRIPTION
        Reads a collection from the Windows 365 / Cloud PC tree
        (deviceManagement/virtualEndpoint/*) and classifies the failure that matters.

        Two things about this API that the caller cannot work out from the response:

        1. It is APP-ONLY. A delegated token is always denied, so every call here passes
           -AsApp $true. ListGraphRequest (delegated) can never read this tree.

        2. A tenant with NO Windows 365 licence returns
           "Access is denied to the requested resource" - NOT an empty collection - and does so
           even for servicePlans, which is a static global catalogue that returns 60+ rows on a
           licensed tenant. That is byte-identical to the denial you get with no permission, so
           the error alone cannot tell "this customer doesn't buy Windows 365" from
           "CIPP's consent is broken". Operators chasing the second when it was the first is
           exactly how this went wrong before the endpoint existed.

        So on a denial we ask the tenant what it owns and answer the question properly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        # Collection under virtualEndpoint, e.g. 'cloudPCs' or 'provisioningPolicies'.
        [Parameter(Mandatory = $true)][string]$Collection,
        [string]$QueryString
    )

    $Uri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/$Collection$QueryString"

    try {
        $Result = New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -AsApp $true -ErrorAction Stop
        return [PSCustomObject]@{
            State    = 'Ok'
            Licensed = $true
            Items    = @($Result)
            Message  = $null
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Normalized = "$($ErrorMessage.NormalizedError)"

        # Only a denial is ambiguous. A malformed request, a throttle or a 5xx means what it says.
        if ($Normalized -notmatch 'Access is denied|Forbidden|403|Insufficient privileges') {
            throw $_
        }

        $Licensed = Test-CIPPCloudPCLicensed -TenantFilter $TenantFilter

        if ($Licensed -eq $false) {
            return [PSCustomObject]@{
                State    = 'NotLicensed'
                Licensed = $false
                Items    = @()
                Message  = 'This tenant has no Windows 365 licence, so it has no Cloud PC service to query. This is not a permission problem and nothing needs repairing.'
            }
        }

        # Licensed and still denied - now a denial really does mean access, and it is worth
        # naming the two causes that are actually fixable rather than a bare 403.
        return [PSCustomObject]@{
            State    = 'AccessDenied'
            Licensed = $Licensed
            Items    = @()
            Message  = "Access denied reading $Collection even though this tenant holds Windows 365 licences. Check that CloudPC.ReadWrite.All is granted (Tenants -> Refresh CPV Permissions); if it was granted recently, CIPP's cached Graph token predates the grant and the app needs a restart."
        }
    }
}
