# Pester tests for New-CIPPPrinterScript
#
# Intune has no CSP for TCP/IP port printers or mapped print-server queues, so those two
# printer types deploy as generated PowerShell. That makes this function a code generator
# fed by operator-supplied free text, and these tests pin the two properties that matter:
#   - the script is idempotent, because Intune re-runs platform scripts on every check-in;
#   - catalogue values cannot break out of the string literal or the comment they land in.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Modules = Join-Path $RepoRoot 'Modules'
    # Resolve by name under Modules/ so the test survives the function moving between modules.
    $FunctionPath = Get-ChildItem -Path $Modules -Recurse -Filter 'New-CIPPPrinterScript.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate New-CIPPPrinterScript.ps1 under Modules/' }
    . $FunctionPath
}

Describe 'New-CIPPPrinterScript' {

    Context 'DirectIP' {
        BeforeAll {
            $script:Result = New-CIPPPrinterScript -Printer @{
                Name        = 'Reception HP'
                PrinterType = 'DirectIP'
                HostAddress = '10.0.0.20'
                DriverName  = 'HP Universal Printing PCL 6'
            }
        }

        It 'creates the port only when it is absent' {
            $script:Result | Should -Match 'if \(-not \(Get-PrinterPort -Name \$PortName'
            $script:Result | Should -Match "Add-PrinterPort -Name \`$PortName -PrinterHostAddress '10\.0\.0\.20' -PortNumber 9100"
        }

        It 'defaults to the RAW printing port when none is supplied' {
            $script:Result | Should -Match '-PortNumber 9100'
        }

        It 'honours an explicit port instead of the default' {
            $Custom = New-CIPPPrinterScript -Printer @{
                Name = 'Odd'; PrinterType = 'DirectIP'; HostAddress = '10.0.0.21'
                DriverName = 'Generic / Text Only'; PortNumber = 9101
            }
            $Custom | Should -Match '-PortNumber 9101'
            $Custom | Should -Not -Match '-PortNumber 9100'
        }

        It 're-points an existing queue rather than recreating it' {
            # Recreating would drop the queue and any per-queue state; converging is the point.
            $script:Result | Should -Match "Set-Printer -Name 'Reception HP'"
            $script:Result | Should -Match "Add-Printer -Name 'Reception HP'"
        }

        It 'refuses an entry with no host address' {
            { New-CIPPPrinterScript -Printer @{ Name = 'X'; PrinterType = 'DirectIP'; DriverName = 'D' } } |
                Should -Throw '*HostAddress*'
        }

        It 'refuses an entry with no driver' {
            { New-CIPPPrinterScript -Printer @{ Name = 'X'; PrinterType = 'DirectIP'; HostAddress = '1.2.3.4' } } |
                Should -Throw '*DriverName*'
        }
    }

    Context 'DirectIP driver sources' {
        It 'defaults to an inbox driver and stages nothing' {
            $Result = New-CIPPPrinterScript -Printer @{
                Name = 'X'; PrinterType = 'DirectIP'; HostAddress = '1.2.3.4'; DriverName = 'D'
            }
            $Result | Should -Not -Match 'pnputil'
            $Result | Should -Match "Add-PrinterDriver -Name 'D'"
        }

        It 'stages the INF with pnputil when DriverSource is InfPath' {
            $Result = New-CIPPPrinterScript -Printer @{
                Name = 'X'; PrinterType = 'DirectIP'; HostAddress = '1.2.3.4'; DriverName = 'D'
                DriverSource = 'InfPath'; DriverInfPath = 'C:\Drivers\hp\hpcu255u.inf'
            }
            $Result | Should -Match 'pnputil\.exe /add-driver'
            # Missing INF must fail loudly rather than build a queue on a missing driver.
            $Result | Should -Match 'Driver INF not found'
        }

        It 'refuses InfPath with no path' {
            { New-CIPPPrinterScript -Printer @{
                    Name = 'X'; PrinterType = 'DirectIP'; HostAddress = '1.2.3.4'; DriverName = 'D'
                    DriverSource = 'InfPath'
                } } | Should -Throw '*DriverInfPath*'
        }

        It 'notes the Win32 app prerequisite without staging anything itself' {
            $Result = New-CIPPPrinterScript -Printer @{
                Name = 'X'; PrinterType = 'DirectIP'; HostAddress = '1.2.3.4'; DriverName = 'D'
                DriverSource = 'Win32App'
            }
            $Result | Should -Not -Match 'pnputil'
            $Result | Should -Match 'Win32 app'
        }

        It 'refuses an unknown driver source' {
            { New-CIPPPrinterScript -Printer @{
                    Name = 'X'; PrinterType = 'DirectIP'; HostAddress = '1.2.3.4'; DriverName = 'D'
                    DriverSource = 'CarrierPigeon'
                } } | Should -Throw '*CarrierPigeon*'
        }

        It 'escapes an apostrophe in the INF path' {
            $Result = New-CIPPPrinterScript -Printer @{
                Name = 'X'; PrinterType = 'DirectIP'; HostAddress = '1.2.3.4'; DriverName = 'D'
                DriverSource = 'InfPath'; DriverInfPath = "C:\Bob's\d.inf"
            }
            $Result | Should -Match "Bob''s"
        }
    }

    Context 'ServerShare' {
        It 'maps the queue only when it is absent' {
            $Result = New-CIPPPrinterScript -Printer @{
                Name = 'Accounts'; PrinterType = 'ServerShare'; UNCPath = '\\PRINTSRV01\Accounts'
            }
            $Result | Should -Match "Add-Printer -ConnectionName '\\\\PRINTSRV01\\Accounts'"
            $Result | Should -Match 'if \(-not \(Get-Printer'
        }

        It 'records that it must run in the user context' {
            # A mapped queue lives in the user profile; assigning this as system silently no-ops.
            $Result = New-CIPPPrinterScript -Printer @{
                Name = 'Accounts'; PrinterType = 'ServerShare'; UNCPath = '\\SRV\q'
            }
            $Result | Should -Match "runAsAccount 'user'"
        }

        It 'refuses an entry with no UNC path' {
            { New-CIPPPrinterScript -Printer @{ Name = 'X'; PrinterType = 'ServerShare' } } |
                Should -Throw '*UNCPath*'
        }
    }

    Context 'Universal Print is not a script' {
        It 'directs the caller to the settings catalog template instead' {
            { New-CIPPPrinterScript -Printer @{ Name = 'UP'; PrinterType = 'UniversalPrint' } } |
                Should -Throw '*settings catalog*'
        }
    }

    Context 'injection hardening' {
        It 'escapes an apostrophe so it cannot close the string literal' {
            $Result = New-CIPPPrinterScript -Printer @{
                Name        = "Bob's Printer'; Remove-Item C:\ -Recurse; '"
                PrinterType = 'ServerShare'
                UNCPath     = '\\SRV\q'
            }
            # No line may begin with the injected command - it must stay inside a literal.
            $Lines = $Result -split "`r?`n"
            ($Lines | Where-Object { $_ -match '^\s*Remove-Item' }) | Should -BeNullOrEmpty
        }

        It 'flattens a newline so it cannot escape the comment line' {
            # The name is echoed into a '# Printer:' comment. A raw line break there would end
            # the comment and put the rest of the value on an executable line.
            $Evil = "Reception" + [char]10 + "Remove-Item C:\ -Recurse -Force"
            $Result = New-CIPPPrinterScript -Printer @{
                Name = $Evil; PrinterType = 'ServerShare'; UNCPath = '\\SRV\q'
            }
            $Lines = $Result -split "`r?`n"
            ($Lines | Where-Object { $_ -match '^\s*Remove-Item' }) | Should -BeNullOrEmpty
        }

        It 'escapes a UNC path containing an apostrophe' {
            $Result = New-CIPPPrinterScript -Printer @{
                Name = 'X'; PrinterType = 'ServerShare'; UNCPath = "\\SRV\Bob's"
            }
            $Result | Should -Match "Bob''s"
        }
    }

    Context 'always' {
        It 'stops on the first error rather than limping on' {
            $Result = New-CIPPPrinterScript -Printer @{
                Name = 'X'; PrinterType = 'ServerShare'; UNCPath = '\\SRV\q'
            }
            $Result | Should -Match "ErrorActionPreference = 'Stop'"
        }

        It 'refuses an entry with no name' {
            { New-CIPPPrinterScript -Printer @{ PrinterType = 'ServerShare'; UNCPath = '\\SRV\q' } } |
                Should -Throw '*Name*'
        }

        It 'refuses an unknown printer type' {
            { New-CIPPPrinterScript -Printer @{ Name = 'X'; PrinterType = 'Telepathy' } } |
                Should -Throw '*Telepathy*'
        }
    }
}
