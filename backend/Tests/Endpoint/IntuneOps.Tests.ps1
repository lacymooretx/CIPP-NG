# Aspendora fork (Vikunja CIPP-22 / CIPP-24 / CIPP-27): pure rules behind enrollment discovery, the driver update
# standard, duplicate serial detection and the Intune reports-table parser.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Ops = Join-Path $RepoRoot 'Modules/CIPPCore/Public/IntuneOps'
    foreach ($Name in 'Test-CIPPManagedDeviceActive', 'ConvertFrom-CIPPIntuneReportTable', 'Test-CIPPEnrollmentDiscovery', 'Find-CIPPDuplicateDeviceSerials', 'Test-CIPPDriverUpdateProfileState', 'Format-CIPPCentralTime') {
        . (Join-Path $Ops "$Name.ps1")
    }
    function New-Domain { param($Domain, $Enroll = '', $Reg = '', [switch]$Failed) [pscustomobject]@{ Domain = $Domain; EnrollmentTarget = $Enroll; RegistrationTarget = $Reg; LookupError = [bool]$Failed } }
    $script:Good = 'enterpriseenrollment-s.manage.microsoft.com'
    $script:Reg = 'enterpriseregistration.windows.net'
}

Describe 'Test-CIPPManagedDeviceActive' {
    It 'treats <State> as active=<Active>' -ForEach @(
        @{ State = 'managed'; Active = $true }
        @{ State = ''; Active = $true }
        @{ State = 'retirePending'; Active = $false }
        @{ State = 'wipeIssued'; Active = $false }
        @{ State = 'deletePending'; Active = $false }
        @{ State = 'retireCanceled'; Active = $true }
    ) {
        Test-CIPPManagedDeviceActive -Device ([pscustomobject]@{ managementState = $State }) | Should -Be $Active
    }
}

Describe 'ConvertFrom-CIPPIntuneReportTable' {
    It 'maps columns onto each row' {
        $Report = [pscustomobject]@{ Schema = @(@{ Column = 'DeviceName' }, @{ Column = 'AlertMessage_loc' }); Values = @(, @('PC1', 'Failed')) + @(, @('PC2', 'Pending reboot')) }
        $Rows = @(ConvertFrom-CIPPIntuneReportTable -Report $Report)
        $Rows.Count | Should -Be 2
        $Rows[1].DeviceName | Should -Be 'PC2'
        $Rows[1].AlertMessage_loc | Should -Be 'Pending reboot'
    }

    It 'does not flatten a single row into its cells' {
        $Report = [pscustomobject]@{ Schema = @(@{ Column = 'DeviceName' }, @{ Column = 'UPN' }); Values = @(, @('PC1', 'a@b.com')) }
        $Rows = @(ConvertFrom-CIPPIntuneReportTable -Report $Report)
        $Rows.Count | Should -Be 1
        $Rows[0].UPN | Should -Be 'a@b.com'
    }

    It 'handles a single row that arrives already unwrapped' {
        $Report = [pscustomobject]@{ Schema = @(@{ Column = 'DeviceName' }, @{ Column = 'UPN' }); Values = @('PC1', 'a@b.com') }
        $Rows = @(ConvertFrom-CIPPIntuneReportTable -Report $Report)
        $Rows.Count | Should -Be 1
        $Rows[0].DeviceName | Should -Be 'PC1'
    }

    It 'returns nothing for an empty report' {
        @(ConvertFrom-CIPPIntuneReportTable -Report ([pscustomobject]@{ Schema = @(@{ Column = 'A' }); Values = @() })).Count | Should -Be 0
        @(ConvertFrom-CIPPIntuneReportTable -Report $null).Count | Should -Be 0
    }
}

Describe 'Test-CIPPEnrollmentDiscovery' {
    It 'flags a published CNAME while the MDM scope is None' {
        $F = @(Test-CIPPEnrollmentDiscovery -Domains @(New-Domain 'contoso.com' $script:Good $script:Reg) -MdmScope @{ AppliesTo = 'none' } -WindowsDeviceCount 5)
        $F.Category | Should -Contain 'CnameWithScopeNone'
        ($F | Where-Object Category -EQ 'CnameWithScopeNone').Severity | Should -Be 'Warning'
        ($F | Where-Object Category -EQ 'CnameWithScopeNone').Id | Should -Be 'CnameWithScopeNone'
    }

    It 'flags a published CNAME with a narrow scope and names the groups' {
        $F = @(Test-CIPPEnrollmentDiscovery -Domains @(New-Domain 'contoso.com' $script:Good $script:Reg) -MdmScope @{ AppliesTo = 'selected'; Groups = @('Intune Pilot') } -WindowsDeviceCount 5)
        ($F | Where-Object Category -EQ 'CnameWithNarrowScope').Message | Should -Match 'Intune Pilot'
    }

    It 'is quiet for scope All with a correct CNAME pair' {
        @(Test-CIPPEnrollmentDiscovery -Domains @(New-Domain 'contoso.com' "$($script:Good)." $script:Reg) -MdmScope @{ AppliesTo = 'all' } -WindowsDeviceCount 5).Count | Should -Be 0
    }

    It 'grades a missing CNAME Warning when scope is not All and Info when it is' {
        $Narrow = @(Test-CIPPEnrollmentDiscovery -Domains @(New-Domain 'contoso.com') -MdmScope @{ AppliesTo = 'selected'; Groups = @('g') } -WindowsDeviceCount 3)
        ($Narrow | Where-Object Category -EQ 'CnameMissing').Severity | Should -Be 'Warning'
        ($Narrow | Where-Object Category -EQ 'CnameMissing').Id | Should -Be 'CnameMissing|contoso.com'
        $All = @(Test-CIPPEnrollmentDiscovery -Domains @(New-Domain 'contoso.com') -MdmScope @{ AppliesTo = 'all' } -WindowsDeviceCount 3)
        ($All | Where-Object Category -EQ 'CnameMissing').Severity | Should -Be 'Info'
    }

    It 'does not flag a missing CNAME when no Windows devices are enrolled' {
        @(Test-CIPPEnrollmentDiscovery -Domains @(New-Domain 'contoso.com') -MdmScope @{ AppliesTo = 'all' } -WindowsDeviceCount 0).Count | Should -Be 0
    }

    It 'reports no enrollment path for scope None, Windows devices and no CNAME anywhere' {
        $F = @(Test-CIPPEnrollmentDiscovery -Domains @(New-Domain 'contoso.com') -MdmScope @{ AppliesTo = 'none' } -WindowsDeviceCount 2)
        $F.Category | Should -Contain 'NoEnrollmentPath'
    }

    It 'separates legacy, unexpected and registration targets' {
        $F = @(Test-CIPPEnrollmentDiscovery -Domains @(
                New-Domain 'legacy.com' 'enterpriseenrollment.manage.microsoft.com' $script:Reg
                New-Domain 'odd.com' 'mdm.example.net' 'reg.example.net'
                New-Domain 'noreg.com' $script:Good ''
            ) -MdmScope @{ AppliesTo = 'all' } -WindowsDeviceCount 1)
        ($F | Where-Object Domain -EQ 'legacy.com').Category | Should -Be 'CnameLegacyTarget'
        @($F | Where-Object Domain -EQ 'odd.com').Category | Should -Be @('CnameUnexpectedTarget', 'RegistrationUnexpected')
        ($F | Where-Object Domain -EQ 'noreg.com').Category | Should -Be 'RegistrationMissing'
    }

    It 'treats a failed lookup as unknown, never as missing' {
        $F = @(Test-CIPPEnrollmentDiscovery -Domains @(New-Domain 'contoso.com' -Failed) -MdmScope @{ AppliesTo = 'none' } -WindowsDeviceCount 2)
        $F.Category | Should -Be @('DnsLookupFailed')
    }

    It 'warns about hybrid GPO-enrolled devices unless the scope is All' {
        $Hybrid = @([pscustomobject]@{ DeviceName = 'PC1'; EnrollmentType = 'windowsCoManagement' })
        (@(Test-CIPPEnrollmentDiscovery -MdmScope @{ AppliesTo = 'selected'; Groups = @('g') } -WindowsDeviceCount 1 -HybridDevices $Hybrid) | Where-Object Category -EQ 'HybridDependsOnScope').Severity | Should -Be 'Warning'
        (@(Test-CIPPEnrollmentDiscovery -MdmScope @{ AppliesTo = 'all' } -WindowsDeviceCount 1 -HybridDevices $Hybrid) | Where-Object Category -EQ 'HybridDependsOnScope').Severity | Should -Be 'Info'
    }
}

Describe 'Find-CIPPDuplicateDeviceSerials' {
    It 'keeps the most recently synced record and lists the rest' {
        $D = @(
            [pscustomobject]@{ id = 'a'; deviceName = 'OLD'; serialNumber = 'abc123'; lastSyncDateTime = '2026-01-01T00:00:00Z'; managementState = 'managed' }
            [pscustomobject]@{ id = 'b'; deviceName = 'NEW'; serialNumber = 'ABC123 '; lastSyncDateTime = '2026-10-01T00:00:00Z'; managementState = 'managed' }
            [pscustomobject]@{ id = 'c'; deviceName = 'SOLO'; serialNumber = 'XYZ'; lastSyncDateTime = '2026-10-01T00:00:00Z'; managementState = 'managed' }
        )
        $R = @(Find-CIPPDuplicateDeviceSerials -Devices $D)
        $R.Count | Should -Be 1
        $R[0].Id | Should -Be 'DupSerial|ABC123'
        $R[0].Keep.DeviceName | Should -Be 'NEW'
        @($R[0].Remove.DeviceName) | Should -Be @('OLD')
    }

    It 'ignores placeholder serials and retired devices' {
        $D = @(
            [pscustomobject]@{ id = 'a'; deviceName = 'A'; serialNumber = 'Default string'; managementState = 'managed' }
            [pscustomobject]@{ id = 'b'; deviceName = 'B'; serialNumber = 'Defaultstring'; managementState = 'managed' }
            [pscustomobject]@{ id = 'c'; deviceName = 'C'; serialNumber = 'Defaultstring'; managementState = 'managed' }
            [pscustomobject]@{ id = 'd'; deviceName = 'D'; serialNumber = 'S1'; managementState = 'managed' }
            [pscustomobject]@{ id = 'e'; deviceName = 'E'; serialNumber = 'S1'; managementState = 'retireIssued' }
            [pscustomobject]@{ id = 'f'; deviceName = 'F'; serialNumber = '0000'; managementState = 'managed' }
            [pscustomobject]@{ id = 'g'; deviceName = 'G'; serialNumber = '0000'; managementState = 'managed' }
        )
        @(Find-CIPPDuplicateDeviceSerials -Devices $D).Count | Should -Be 0
    }

    It 'accepts lastSyncDateTime already parsed to [datetime]' {
        $D = @(
            [pscustomobject]@{ id = 'a'; deviceName = 'OLD'; serialNumber = 'S'; lastSyncDateTime = [datetime]'2026-01-01'; managementState = 'managed' }
            [pscustomobject]@{ id = 'b'; deviceName = 'NEW'; serialNumber = 'S'; lastSyncDateTime = [datetime]'2026-06-01'; managementState = 'managed' }
        )
        @(Find-CIPPDuplicateDeviceSerials -Devices $D)[0].Keep.DeviceName | Should -Be 'NEW'
    }
}

Describe 'Test-CIPPDriverUpdateProfileState' {
    BeforeAll {
        $script:Autopatch = [pscustomobject]@{ id = 'ap1'; displayName = 'Windows Autopatch Driver Update Policy - Group - Last'; description = 'Driver update policy, created by Windows Autopatch'; approvalType = 'automatic'; deploymentDeferralInDays = 11 }
        $script:Managed = [pscustomobject]@{ id = 'm1'; displayName = 'CIPP - Windows Driver Updates'; description = ''; approvalType = 'automatic'; deploymentDeferralInDays = 7 }
    }

    It 'is compliant when the named profile matches' {
        $S = Test-CIPPDriverUpdateProfileState -Profiles @($script:Managed) -ProfileName 'cipp - windows driver updates' -ApprovalType automatic -DeferralDays 7
        $S.Compliant | Should -BeTrue
        $S.Action | Should -Be 'None'
        $S.ProfileId | Should -Be 'm1'
    }

    It 'asks to update the deferral of an automatic profile' {
        (Test-CIPPDriverUpdateProfileState -Profiles @($script:Managed) -ProfileName 'CIPP - Windows Driver Updates' -ApprovalType automatic -DeferralDays 3).Action | Should -Be 'UpdateDeferral'
    }

    It 'never asks to change the approval type of an existing profile' {
        $S = Test-CIPPDriverUpdateProfileState -Profiles @($script:Managed) -ProfileName 'CIPP - Windows Driver Updates' -ApprovalType manual
        $S.Action | Should -Be 'ApprovalTypeMismatch'
        $S.Compliant | Should -BeFalse
        $S.ExpectedDeferral | Should -BeNullOrEmpty
    }

    It 'accepts an Autopatch-managed tenant only when allowed' {
        (Test-CIPPDriverUpdateProfileState -Profiles @($script:Autopatch) -ProfileName 'CIPP - Windows Driver Updates').Action | Should -Be 'AutopatchManaged'
        (Test-CIPPDriverUpdateProfileState -Profiles @($script:Autopatch) -ProfileName 'CIPP - Windows Driver Updates' -AcceptAutopatch $false).Action | Should -Be 'Create'
    }

    It 'asks to create the profile in a tenant with none' {
        $S = Test-CIPPDriverUpdateProfileState -Profiles @() -ProfileName 'CIPP - Windows Driver Updates'
        $S.Action | Should -Be 'Create'
        $S.Compliant | Should -BeFalse
    }
}

Describe 'Format-CIPPCentralTime' {
    It 'renders CDT in summer and CST in winter with the UTC time' {
        Format-CIPPCentralTime '2026-10-31T17:00:00Z' | Should -Be '2026-10-31 12:00 CDT (17:00 UTC)'
        Format-CIPPCentralTime '2026-12-15T18:30:00Z' | Should -Be '2026-12-15 12:30 CST (18:30 UTC)'
    }

    It 'returns empty for empty or year-1 values' {
        Format-CIPPCentralTime $null | Should -Be ''
        Format-CIPPCentralTime '0001-01-01T00:00:00Z' | Should -Be ''
    }
}
