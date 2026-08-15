function Get-CIPPWelcomePacketBranding {
    <#
    .SYNOPSIS
    Resolves the brand, support and app details printed on a welcome packet.

    .DESCRIPTION
    The welcome packet is Aspendora-branded by default and per-client overridable.
    That decision is implemented here: built-in Aspendora defaults, overlaid with a
    tenant-specific row when one exists, so an unconfigured tenant still produces a
    correct sheet on the first try rather than an empty template.

    Why the defaults are Aspendora rather than the client's own brand: every action
    on the sheet is ours. The new hire emails our service desk, clicks our tray icon,
    and signs in to our portal. A client big enough to want its own logo on the sheet
    sets an override; a twelve-person tenant with no brand kit needs nothing.

    'company' and 'brand' are deliberately separate. company.name is the EMPLOYER,
    whose account the new hire is getting, and defaults to the tenant display name.
    brand is WHOSE SHEET IT IS -- the logo at the top and the name in the footer.
    They are usually different, and conflating them is what makes a packet read as
    though the MSP employs the client's staff.

    Storage is the shared Config table under the 'WelcomePacketConfig' partition,
    RowKey = tenant customerId. Invoke-ExecBrandingSettings could not be reused: it
    is partition-scoped to a single Global row holding one colour and one logo, so it
    has nowhere to put per-tenant values.

    Aspendora fork addition.

    .PARAMETER TenantFilter
    Tenant to resolve. Its display name becomes the default company name.

    .PARAMETER Tenant
    An already-resolved tenant object, to avoid a second Get-Tenants call.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        $Tenant
    )

    # Keep these in step with aspendora-branding/docs/welcome-packet.md. That file is
    # the contract; this is one implementation of it.
    $Defaults = [ordered]@{
        brand   = [ordered]@{
            name = 'Aspendora Technologies'
            # Same-origin path, shipped in the frontend's public/ folder. A client
            # override must be a data URI because it could point anywhere; this one
            # is served by the container rendering the page, so it resolves both on
            # screen and in print. Without it the default sheet falls back to the
            # name set as a wordmark, which is not the Aspendora lockup.
            logoUrl = '/aspendora-logo.svg'
        }
        support = [ordered]@{
            email       = 'help@aspendora.com'
            phone       = '281-941-4028'
            portalUrl   = $null
            trayAppName = 'Aspendora Control'
        }
        apps      = @(
            [ordered]@{ name = 'Outlook'; description = 'Email and calendar' }
            [ordered]@{ name = 'Teams'; description = 'Chat, calls and meetings' }
            [ordered]@{ name = 'OneDrive'; description = 'Your files and shared folders' }
            [ordered]@{ name = 'Word and Excel'; description = 'Documents and spreadsheets' }
        )
        signInUrl = 'microsoft365.com'
    }

    $CompanyName = $null
    $CustomerId = $null
    try {
        if (-not $Tenant) {
            $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
        }
        if ($Tenant) {
            $CompanyName = $Tenant.displayName
            $CustomerId = $Tenant.customerId
        }
    } catch {
        Write-Warning "Welcome packet branding could not resolve tenant $($TenantFilter): $($_.Exception.Message)"
    }
    if ([string]::IsNullOrWhiteSpace($CustomerId)) { $CustomerId = $TenantFilter }
    if ([string]::IsNullOrWhiteSpace($CompanyName)) { $CompanyName = $TenantFilter }

    $Override = $null
    try {
        $Table = Get-CIPPTable -TableName Config
        $SafeRowKey = $CustomerId -replace "'", "''"
        $Entity = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'WelcomePacketConfig' and RowKey eq '$SafeRowKey'" | Select-Object -First 1
        if ($Entity -and -not [string]::IsNullOrWhiteSpace($Entity.JSON)) {
            $Override = $Entity.JSON | ConvertFrom-Json -ErrorAction Stop
        }
    } catch {
        # A malformed or unreadable override must not cost the operator their sheet.
        Write-Warning "Welcome packet branding override for $($CustomerId) could not be read, using defaults: $($_.Exception.Message)"
    }

    $Packet = [ordered]@{
        company   = [ordered]@{ name = $CompanyName }
        brand     = [ordered]@{
            name    = $Defaults.brand.name
            logoUrl = $Defaults.brand.logoUrl
        }
        support   = [ordered]@{
            email       = $Defaults.support.email
            phone       = $Defaults.support.phone
            portalUrl   = $Defaults.support.portalUrl
            trayAppName = $Defaults.support.trayAppName
        }
        apps      = $Defaults.apps
        signInUrl = $Defaults.signInUrl
    }

    if ($Override) {
        # Field-by-field, so a partial override -- the common case, usually just a logo
        # and a company name -- keeps every default it did not mention.
        if (![string]::IsNullOrWhiteSpace($Override.company.name)) { $Packet.company.name = $Override.company.name }
        if (![string]::IsNullOrWhiteSpace($Override.brand.name)) { $Packet.brand.name = $Override.brand.name }
        if (![string]::IsNullOrWhiteSpace($Override.brand.logoUrl)) { $Packet.brand.logoUrl = $Override.brand.logoUrl }
        if (![string]::IsNullOrWhiteSpace($Override.support.email)) { $Packet.support.email = $Override.support.email }
        if (![string]::IsNullOrWhiteSpace($Override.support.phone)) { $Packet.support.phone = $Override.support.phone }
        if (![string]::IsNullOrWhiteSpace($Override.support.portalUrl)) { $Packet.support.portalUrl = $Override.support.portalUrl }
        if (![string]::IsNullOrWhiteSpace($Override.signInUrl)) { $Packet.signInUrl = $Override.signInUrl }

        # Explicit empty string clears the tray instructions for a client we do not
        # deploy ControlR to. $null means 'not overridden' and keeps the default.
        if ($null -ne $Override.support.trayAppName) {
            $Packet.support.trayAppName = if ([string]::IsNullOrWhiteSpace($Override.support.trayAppName)) { $null } else { $Override.support.trayAppName }
        }

        # Page 2 fits four app tiles. A fifth pushes the closing notice and the footer
        # onto a third sheet, which turns a two-sided handout into a stapled packet.
        if ($Override.apps -and @($Override.apps).Count -gt 0) {
            $Packet.apps = @($Override.apps | Select-Object -First 4 | ForEach-Object {
                    [ordered]@{ name = $_.name; description = $_.description }
                })
        }
    }

    return [PSCustomObject]$Packet
}
