# Aspendora fork: GraphEndpointBlocklist.Exemptions.json - mailbox reads are allowed through the Graph proxies
# (operator decision 2026-09-28), every other customer-content rule still applies.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $env:CIPPRootPath = $RepoRoot
    Remove-Item Env:CIPP_GRAPH_BLOCKLIST_EXEMPTIONS_DISABLED -ErrorAction SilentlyContinue
    $script:CippGraphEndpointBlocklist = $null

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper/Test-CIPPGraphEndpointBlocked.ps1')
}

AfterAll {
    Remove-Item Env:CIPP_GRAPH_BLOCKLIST_EXEMPTIONS_DISABLED -ErrorAction SilentlyContinue
}

Describe 'Test-CIPPGraphEndpointBlocked mailbox-read exemption' {
    BeforeEach {
        Remove-Item Env:CIPP_GRAPH_BLOCKLIST_EXEMPTIONS_DISABLED -ErrorAction SilentlyContinue
        $script:CippGraphEndpointBlocklist = $null
    }

    It 'allows mailbox read <Uri>' -ForEach @(
        @{ Uri = 'users/raul@3endt.com/messages' }
        @{ Uri = "users/raul@3endt.com/messages?`$filter=receivedDateTime ge 2026-09-27T00:00:00Z&`$select=subject,receivedDateTime,parentFolderId,isRead&`$top=50" }
        @{ Uri = 'users/5c94440f-fa8b-431e-a0d8-5110128f8d02/messages/AAMkAG=' }
        @{ Uri = "users/x/messages('m1')" }
        @{ Uri = "users('x')/messages" }
        @{ Uri = 'me/messages' }
        @{ Uri = 'users/x/messages/delta' }
        @{ Uri = 'users/x/mailFolders/inbox/messages' }
        @{ Uri = "users/x/mailFolders('junkemail')/messages" }
        @{ Uri = 'users/x/mailFolders/inbox/childFolders/f1/childFolders/f2/messages/m' }
        @{ Uri = 'users/x/mailFolders/inbox?$expand=messages' }
        @{ Uri = 'users/x/messages/m/attachments' }
        @{ Uri = 'users/x/messages/m/attachments/a' }
        @{ Uri = 'users/x/messages/m?$expand=attachments' }
        @{ Uri = 'users/x/mailFolders/inbox/messages/m/attachments' }
        @{ Uri = 'https://graph.microsoft.com/v1.0/users/x/messages?$skiptoken=abc' }
        @{ Uri = 'https://graph.microsoft.com/beta/users/x/mailFolders/inbox/messages' }
    ) {
        Test-CIPPGraphEndpointBlocked -Uri $Uri | Should -BeFalse
    }

    It 'still blocks non-mailbox content <Uri>' -ForEach @(
        @{ Uri = 'teams/t/channels/getAllMessages' }
        @{ Uri = 'teams/t/channels/c/messages' }
        @{ Uri = 'users/u/chats/getAllMessages' }
        @{ Uri = 'users/u/chats/c/messages' }
        @{ Uri = 'chats/c/messages' }
        @{ Uri = 'groups/g/conversations/c/threads/t/posts' }
        @{ Uri = 'users/x/events' }
        @{ Uri = 'users/x/contacts' }
        @{ Uri = 'users/x/drive/root/children' }
        @{ Uri = 'users/x/messages?$expand=attachments,drive' }
    ) {
        Test-CIPPGraphEndpointBlocked -Uri $Uri | Should -BeTrue
    }

    It 'still blocks raw content downloads under a mailbox <Uri>' -ForEach @(
        @{ Uri = 'users/x/messages/m/$value'; Id = 'media-value' }
        @{ Uri = 'users/x/messages/m/attachments/a/$value'; Id = 'media-value' }
        @{ Uri = "users/x/messages('m')/attachments('a')/content"; Id = 'file-content' }
        @{ Uri = 'users/x/messages/m/attachments/a/content'; Id = 'file-content' }
    ) {
        { Test-CIPPGraphEndpointBlocked -Uri $Uri -Throw } | Should -Throw "*($Id)*"
    }

    It 'does not let a mailbox-looking prefix hide a different resource <Uri>' -ForEach @(
        @{ Uri = 'users/x/messages/m/attachments/a/extra/messages/../../../../drive' }
        @{ Uri = 'users/x/messages%2F..%2F..%2Fchats' }
        @{ Uri = 'users/x/chats/messages' }
        @{ Uri = 'users/x/xmailFolders/inbox/drive' }
    ) {
        Test-CIPPGraphEndpointBlocked -Uri $Uri | Should -BeTrue
    }

    It 'kill switch restores the upstream block' {
        $env:CIPP_GRAPH_BLOCKLIST_EXEMPTIONS_DISABLED = 'true'
        $script:CippGraphEndpointBlocklist = $null
        { Test-CIPPGraphEndpointBlocked -Uri 'users/x/messages' -Throw } | Should -Throw '*(mail-messages)*'
    }
}
