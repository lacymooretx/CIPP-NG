function Get-CIPPAsrRuleCatalog {
    <#
    .SYNOPSIS
        The Attack Surface Reduction rules: GUID, display name, Settings Catalog setting name and hunting ActionType stem.
    .DESCRIPTION
        SettingName is the suffix after 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_' in the
        Settings Catalog / endpoint security ASR policy (confirmed against a live policy 2026-10-31). HuntingStem is the
        DeviceEvents ActionType without its 'Audited' / 'Blocked' / 'Warned' suffix; best effort, because Microsoft
        does not publish one complete list and our tenants cannot query the device tables to confirm it.
        Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()
    @(
        [pscustomobject]@{ RuleId = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Name = 'Block executable content from email client and webmail'; SettingName = 'blockexecutablecontentfromemailclientandwebmail'; HuntingStem = 'AsrExecutableEmailContent' }
        [pscustomobject]@{ RuleId = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Name = 'Block all Office applications from creating child processes'; SettingName = 'blockallofficeapplicationsfromcreatingchildprocesses'; HuntingStem = 'AsrOfficeChildProcess' }
        [pscustomobject]@{ RuleId = '3B576869-A4EC-4529-8536-B80A7769E899'; Name = 'Block Office applications from creating executable content'; SettingName = 'blockofficeapplicationsfromcreatingexecutablecontent'; HuntingStem = 'AsrExecutableOfficeContent' }
        [pscustomobject]@{ RuleId = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Name = 'Block Office applications from injecting code into other processes'; SettingName = 'blockofficeapplicationsfrominjectingcodeintootherprocesses'; HuntingStem = 'AsrOfficeProcessInjection' }
        [pscustomobject]@{ RuleId = 'D3E037E1-3EB8-44C8-A917-57927947596D'; Name = 'Block JavaScript or VBScript from launching downloaded executable content'; SettingName = 'blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent'; HuntingStem = 'AsrScriptExecutableDownload' }
        [pscustomobject]@{ RuleId = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Name = 'Block execution of potentially obfuscated scripts'; SettingName = 'blockexecutionofpotentiallyobfuscatedscripts'; HuntingStem = 'AsrObfuscatedScript' }
        [pscustomobject]@{ RuleId = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Name = 'Block Win32 API calls from Office macros'; SettingName = 'blockwin32apicallsfromofficemacros'; HuntingStem = 'AsrOfficeMacroWin32ApiCalls' }
        [pscustomobject]@{ RuleId = '01443614-CD74-433A-B99E-2ECDC07BFC25'; Name = 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion'; SettingName = 'blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion'; HuntingStem = 'AsrUntrustedExecutable' }
        [pscustomobject]@{ RuleId = 'C1DB55AB-C21A-4637-BB3F-A12568109D35'; Name = 'Use advanced protection against ransomware'; SettingName = 'useadvancedprotectionagainstransomware'; HuntingStem = 'AsrRansomware' }
        [pscustomobject]@{ RuleId = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Name = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)'; SettingName = 'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem'; HuntingStem = 'AsrLsassCredentialTheft' }
        [pscustomobject]@{ RuleId = 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'; Name = 'Block process creations originating from PSExec and WMI commands'; SettingName = 'blockprocesscreationsfrompsexecandwmicommands'; HuntingStem = 'AsrPsexecWmiChildProcess' }
        [pscustomobject]@{ RuleId = 'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'; Name = 'Block untrusted and unsigned processes that run from USB'; SettingName = 'blockuntrustedunsignedprocessesthatrunfromusb'; HuntingStem = 'AsrUntrustedUsbProcess' }
        [pscustomobject]@{ RuleId = '26190899-1602-49E8-8B27-EB1D0A1CE869'; Name = 'Block Office communication application from creating child processes'; SettingName = 'blockofficecommunicationappfromcreatingchildprocesses'; HuntingStem = 'AsrOfficeCommAppChildProcess' }
        [pscustomobject]@{ RuleId = '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'; Name = 'Block Adobe Reader from creating child processes'; SettingName = 'blockadobereaderfromcreatingchildprocesses'; HuntingStem = 'AsrAdobeReaderChildProcess' }
        [pscustomobject]@{ RuleId = 'E6DB77E5-3DF2-4CF1-B95A-636979351E5B'; Name = 'Block persistence through WMI event subscription'; SettingName = 'blockpersistencethroughwmieventsubscription'; HuntingStem = 'AsrPersistenceThroughWmi' }
        [pscustomobject]@{ RuleId = '56A863A9-875E-4185-98A7-B882C64B5CE5'; Name = 'Block abuse of exploited vulnerable signed drivers'; SettingName = 'blockabuseofexploitedvulnerablesigneddrivers'; HuntingStem = 'AsrVulnerableSignedDriver' }
        [pscustomobject]@{ RuleId = 'C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB'; Name = 'Block use of copied or impersonated system tools'; SettingName = 'blockuseofcopiedorimpersonatedsystemtools'; HuntingStem = 'AsrAbusedSystemTool' }
        [pscustomobject]@{ RuleId = 'A8F5898E-1DC8-49A9-9878-85004B8A61E6'; Name = 'Block Webshell creation for Servers'; SettingName = 'blockwebshellcreationforservers'; HuntingStem = 'AsrServerWebshell' }
        [pscustomobject]@{ RuleId = '33DDEDF1-C6E0-47CB-833E-DE6133960387'; Name = 'Block rebooting machine in Safe Mode'; SettingName = 'blockrebootingmachineinsafemode'; HuntingStem = 'AsrSafeModeReboot' }
    )
}
