# Upstream deleted Add-CIPPBPAField on 2026-09-24 ("remove BPA"). Fork standards still calling it failed in every
# tenant every night with "The term 'Add-CIPPBPAField' is not recognized" (found 2026-11-01). Guard against
# re-introducing calls to helpers upstream has removed.
Describe 'Removed upstream helpers' {
    It 'no module calls <Name>' -ForEach @(@{ Name = 'Add-CIPPBPAField' }) {
        $Root = Join-Path $PSScriptRoot '../../Modules'
        $Hits = @(Get-ChildItem -Path $Root -Recurse -Filter '*.ps1' | Select-String -SimpleMatch $Name | ForEach-Object { "$($_.Path):$($_.LineNumber)" })
        $Hits | Should -BeNullOrEmpty
    }
}
