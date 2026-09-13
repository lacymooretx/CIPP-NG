function ConvertTo-CIPPTeamsPolicyTemplate {
    <#
    .SYNOPSIS
        Strips a Teams ConfigAPI policy object down to the settable properties.

    .DESCRIPTION
        A ConfigAPI GET returns the policy's settings alongside a scope/identity envelope
        (Key, Identity, ConfigId, ConfigMetadata, DefaultXml, ETag...). Those describe
        WHERE the object lives, not what it configures, and PUTting them back at another
        tenant is meaningless at best and rejected at worst - Key carries the source
        tenant's AuthorityId GUID.

        This returns only the settable properties, so a captured template is portable
        across tenants.

        Read-only computed fields are dropped too (Statistics, DistributionListsLastExpanded,
        ThreadId and friends on voice objects) since they are server-derived.

    .PARAMETER Policy
        The object returned by New-TeamsRequestV2 -Action Get.

    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Policy
    )

    begin {
        # Scope/identity envelope - describes where the object lives, not what it sets.
        $EnvelopeProperties = @(
            'Key', 'Identity', 'ConfigId', 'ConfigMetadata', 'DefaultXml', 'XmlRoot',
            'SchemaId', 'AuthorityId', 'ScopeClass', 'ETag', 'Signature', 'IsModified',
            'odata.type', '@odata.type'
        )
        # Server-computed, never settable.
        $ComputedProperties = @(
            'Statistics', 'StatusRecords', 'DistributionListsLastExpanded',
            'AgentsInSyncWithDistributionLists', 'ThreadId', 'MissedCallsThread',
            'AnsweredCallsThread', 'AutoRecordingThread', 'TenantId', 'Diagnostics',
            'WelcomeMusicFileDownloadUri', 'MusicOnHoldFileDownloadUri'
        )
        $Drop = $EnvelopeProperties + $ComputedProperties
    }

    process {
        if ($null -eq $Policy) { return }
        $Keep = $Policy.PSObject.Properties |
            Where-Object { $_.Name -notin $Drop } |
            Select-Object -ExpandProperty Name
        if (-not $Keep) { return }
        $Policy | Select-Object -Property $Keep
    }
}
