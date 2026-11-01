# Aspendora fork (Vikunja CIPP-30): TLD exposure counting and the paged message-trace reader.
BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $BackendRoot 'Modules/CIPPCore/Public/MailTriage/Measure-CIPPTldExposure.ps1')
    . (Join-Path $BackendRoot 'Modules/CIPPCore/Public/MailTriage/ConvertTo-CIPPCentralTime.ps1')
    . (Join-Path $BackendRoot 'Modules/CIPPCore/Public/MailTriage/Get-CIPPMessageTraceRange.ps1')
    function New-ExoRequest { param($tenantid, $cmdlet, $cmdParams, $Anchor) }

    function New-Row { param($From, $To, $Status = 'Delivered', $Id = ([guid]::NewGuid().Guid)) [pscustomobject]@{ SenderAddress = $From; RecipientAddress = $To; Status = $Status; MessageTraceId = $Id; Received = '2026-10-30T12:00:00Z' } }
}

Describe 'Measure-CIPPTldExposure' {
    BeforeAll {
        $script:Rows = @(
            New-Row 'bad@evil.xyz' 'amy@contoso.com'
            New-Row 'bad@evil.xyz' 'bob@contoso.com' -Status 'Quarantined'
            New-Row 'x@promo.top' 'amy@contoso.com' -Status 'FilteredAsSpam'
            New-Row 'amy@contoso.com' 'partner@vendor.xyz'
            New-Row 'amy@contoso.com' 'friend@gmail.com'
            New-Row 'news@shop.com' 'amy@contoso.com'
            New-Row 'MicrosoftExchange329e71ec88ae4615bbc36ab6ce41109e@contoso.com' 'journal@archive.xyz'
            New-Row 'bad@evil.xyz' 'someone@other.org'
        )
        $script:R = Measure-CIPPTldExposure -Rows $script:Rows -Tlds @('xyz', '*.top', '.zip') -AcceptedDomains @('contoso.com')
    }

    It 'counts inbound from listed TLDs to the tenant only' {
        $Xyz = $script:R.ByTld | Where-Object Tld -EQ 'xyz'
        $Xyz.InboundRows | Should -Be 2
        $Xyz.InboundDelivered | Should -Be 1
        $Xyz.InboundFiltered | Should -Be 1
        ($script:R.ByTld | Where-Object Tld -EQ 'top').InboundFiltered | Should -Be 1
    }

    It 'counts outbound mail to listed TLDs from the tenant (what a sender block would break)' {
        $Xyz = $script:R.ByTld | Where-Object Tld -EQ 'xyz'
        $Xyz.OutboundRows | Should -Be 1
        $Xyz.InternalSenders | Should -Be 1
        $script:R.TopOutboundDomains[0].Domain | Should -Be 'vendor.xyz'
    }

    It 'ignores Exchange journal reports' {
        $script:R.TopOutboundDomains.Domain | Should -Not -Contain 'archive.xyz'
    }

    It 'normalises *.tld and .tld input and keeps zero rows for quiet TLDs' {
        $script:R.ByTld.Tld | Should -Contain 'zip'
        ($script:R.ByTld | Where-Object Tld -EQ 'zip').InboundRows | Should -Be 0
        $script:R.TldsWithTraffic | Should -Be @('xyz', 'top')
    }

    It 'ranks top sender domains' {
        $script:R.TopSenderDomains[0].Domain | Should -Be 'evil.xyz'
        $script:R.TopSenderDomains[0].Count | Should -Be 2
        $script:R.RowsScanned | Should -Be 8
    }

    It 'treats subdomains of accepted domains as internal' {
        $R2 = Measure-CIPPTldExposure -Rows @(New-Row 'a@mail.contoso.com' 'b@x.top') -Tlds @('top') -AcceptedDomains @('contoso.com')
        ($R2.ByTld | Where-Object Tld -EQ 'top').OutboundRows | Should -Be 1
    }
}

Describe 'Get-CIPPMessageTraceRange' {
    It 'pages with StartingRecipientAddress + EndDate while pages come back full' {
        $script:Calls = [System.Collections.Generic.List[hashtable]]::new()
        Mock New-ExoRequest {
            $script:Calls.Add($cmdParams)
            if ($script:Calls.Count -eq 1) {
                @(
                    [pscustomobject]@{ MessageTraceId = '1'; RecipientAddress = 'a@contoso.com'; Received = [datetime]'2026-10-30T12:00:00Z' }
                    [pscustomobject]@{ MessageTraceId = '2'; RecipientAddress = 'b@contoso.com'; Received = [datetime]'2026-10-30T11:00:00Z' }
                )
            } else {
                @([pscustomobject]@{ MessageTraceId = '3'; RecipientAddress = 'c@contoso.com'; Received = [datetime]'2026-10-30T10:00:00Z' })
            }
        }
        $End = [DateTime]::UtcNow
        $R = Get-CIPPMessageTraceRange -TenantFilter 'contoso.com' -StartUtc $End.AddDays(-2) -EndUtc $End -PageSize 2
        $R.Rows.Count | Should -Be 3
        $R.Truncated | Should -BeFalse
        $script:Calls.Count | Should -Be 2
        $script:Calls[1].StartingRecipientAddress | Should -Be 'b@contoso.com'
        $script:Calls[1].EndDate | Should -Match '^\d{4}-\d{2}-\d{2}T11:00:00'
    }

    It 'splits a long range into 10-day windows' {
        $script:Calls = [System.Collections.Generic.List[hashtable]]::new()
        Mock New-ExoRequest { $script:Calls.Add($cmdParams); @() }
        $End = [DateTime]::UtcNow
        $null = Get-CIPPMessageTraceRange -TenantFilter 'contoso.com' -StartUtc $End.AddDays(-25) -EndUtc $End
        $script:Calls.Count | Should -Be 3
    }

    It 'stops at MaxPages and reports Truncated with how far back it got' {
        Mock New-ExoRequest { @([pscustomobject]@{ MessageTraceId = [guid]::NewGuid().Guid; RecipientAddress = 'a@contoso.com'; Received = [datetime]'2026-10-30T09:00:00Z' }) }
        $End = [DateTime]::UtcNow
        $R = Get-CIPPMessageTraceRange -TenantFilter 'contoso.com' -StartUtc $End.AddDays(-5) -EndUtc $End -PageSize 1 -MaxPages 3
        $R.Truncated | Should -BeTrue
        $R.Pages | Should -Be 3
        $R.OldestUtc.ToString('yyyy-MM-ddTHH:mm') | Should -Be '2026-10-30T09:00'
    }

    It 'never reads further back than the 90 days Microsoft keeps' {
        Mock New-ExoRequest { @() }
        $End = [DateTime]::UtcNow
        $R = Get-CIPPMessageTraceRange -TenantFilter 'contoso.com' -StartUtc $End.AddDays(-200) -EndUtc $End
        ($End - $R.StartUtc).TotalDays | Should -BeLessOrEqual 90.01
    }
}
