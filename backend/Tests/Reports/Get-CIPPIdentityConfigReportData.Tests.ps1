# PowerShell's -replace is case-INSENSITIVE by default, so a camelCase splitter written with
# it matches lowercase letters as [A-Z] and shreds the string: "microsoftAuthenticator"
# rendered as "M ic ro so ft Au th en ti ca to r" in a live client report. -creplace is the
# fix, and this pins it, because the broken form looks correct on inspection.

BeforeAll {
    # The expression under test, lifted verbatim from the Authentication Methods section.
    function Format-AuthMethodName([string]$Id) {
        $Method = ($Id -creplace '([a-z0-9])([A-Z])', '$1 $2')
        if ($Method) { $Method = $Method.Substring(0, 1).ToUpper() + $Method.Substring(1) }
        return $Method
    }
}

Describe 'Authentication method name rendering' {

    It 'splits camelCase into words without shredding the string' {
        Format-AuthMethodName 'microsoftAuthenticator' | Should -Be 'Microsoft Authenticator'
        Format-AuthMethodName 'temporaryAccessPass' | Should -Be 'Temporary Access Pass'
        Format-AuthMethodName 'federatedIdentityCredential' | Should -Be 'Federated Identity Credential'
    }

    It 'leaves single-word ids alone apart from capitalising them' {
        Format-AuthMethodName 'sms' | Should -Be 'Sms'
        Format-AuthMethodName 'voice' | Should -Be 'Voice'
        Format-AuthMethodName 'email' | Should -Be 'Email'
    }

    It 'handles ids that mix digits and capitals' {
        Format-AuthMethodName 'fido2' | Should -Be 'Fido2'
        Format-AuthMethodName 'x509Certificate' | Should -Be 'X509 Certificate'
    }

    It 'never inserts a space between two lowercase letters' {
        # The exact signature of the case-insensitivity bug. Asserted with a case-sensitive
        # -cmatch rather than Pester's -Match, which is itself case-insensitive and would
        # flag the legitimate capital in "Software Oath", failing a correct implementation.
        foreach ($Id in 'fido2', 'sms', 'voice', 'email', 'softwareOath', 'qrCodePin') {
            $Rendered = Format-AuthMethodName $Id
            ($Rendered -cmatch '[a-z] [a-z]') | Should -BeFalse -Because "'$Rendered' must not be split between lowercase letters"
        }
    }
}
