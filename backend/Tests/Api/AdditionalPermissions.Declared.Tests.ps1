# AdditionalPermissions.json is the only place these Graph roles are declared - they are not in
# SAMManifest.json. Anything dropped from here stops being re-granted on the next CPV refresh, and
# the loss is invisible: the endpoint that needed it starts answering "Access is denied to the
# requested resource", which reads like a GDAP problem rather than a manifest one.
#
# GUIDs are Microsoft's own appRole ids on the Graph service principal
# (00000003-0000-0000-c000-000000000000) and were read back from Graph, not copied from a doc.
# A wrong GUID here is silently dropped rather than rejected, so the values are pinned by name.
#
# CloudPC.ReadWrite.All is deliberately the write role: CIPP provisions Windows 365 Cloud PCs, and
# creating a provisioning policy or an on-premises network connection is a write. It also brings
# aspendora.com's pre-existing but undeclared grant of the same role under management, so a
# permission reset can no longer drop it unnoticed.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Config = Get-Content (Join-Path $RepoRoot 'Config/AdditionalPermissions.json') -Raw | ConvertFrom-Json
    $script:GraphRoles = @(
        $Config |
            Where-Object { $_.resourceAppId -eq '00000003-0000-0000-c000-000000000000' } |
            Select-Object -ExpandProperty resourceAccess |
            Where-Object { $_.type -eq 'Role' } |
            Select-Object -ExpandProperty id
    )
}

Describe 'AdditionalPermissions.json Graph application roles' {
    It 'declares <Name>' -ForEach @(
        @{ Name = 'SharePointTenantSettings.ReadWrite.All'; Id = '19b94e34-907c-4f43-bde9-38b1909ed408' }
        @{ Name = 'Mail.ReadWrite'; Id = 'e2a3a72e-5f79-4c64-b1b1-878b674786c9' }
        @{ Name = 'ThreatHunting.Read.All'; Id = 'dd98c7f5-2d42-42d3-a0e4-633161547251' }
        @{ Name = 'CloudPC.ReadWrite.All'; Id = '3b4349e1-8cf5-45a3-95b7-69d1751d3e6a' }
    ) {
        $script:GraphRoles | Should -Contain $Id
    }

    It 'does not also declare the redundant CloudPC.Read.All' {
        # CloudPC.ReadWrite.All is a superset - aspendora.com's Cloud PC reads have always run on
        # it alone. Declaring Read.All as well grants nothing extra and just adds a second thing
        # to keep in sync.
        $script:GraphRoles | Should -Not -Contain 'a9e09520-8ed4-4cde-838e-4fdea192c227'
    }

    It 'has no duplicate role ids' {
        ($script:GraphRoles | Group-Object | Where-Object Count -GT 1) | Should -BeNullOrEmpty
    }
}
