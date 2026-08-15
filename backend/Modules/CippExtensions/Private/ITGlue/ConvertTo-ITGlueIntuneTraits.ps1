function ConvertTo-ITGlueIntuneTraits {
    <#
    .SYNOPSIS
        Map report-model sections onto IT Glue flexible-asset traits.
    .DESCRIPTION
        Turns the sections of an Intune Configuration Document model into the trait
        hashtable IT Glue expects, rendering each through ConvertTo-ITGlueSectionHtml and
        spilling oversized sections into their continuation fields.

        This lives in its own function because the mapping is where the sharp edges are,
        and they are only reachable at runtime otherwise. In PowerShell
        `@($Hashtable['MissingKey'])` is a one-element array containing $null, not an empty
        array - which turned every section without continuation fields into
        `$Traits[$null] = ...` and failed the whole tenant with
        "Index operation failed; the array index evaluated to null". Every section but one
        has no continuation fields, so that was all of them.
    .PARAMETER Sections
        The report model's Sections collection. Sections with no entry in TraitMap are
        skipped.
    .PARAMETER TraitMap
        Section Key -> IT Glue trait name-key.
    .PARAMETER OverflowMap
        Section Key -> ordered list of continuation trait name-keys. Sections absent from
        this map simply get one field.
    .PARAMETER Truncated
        List that receives a note for any section that still did not fit.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Sections,

        [Parameter(Mandatory = $true)]
        [hashtable]$TraitMap,

        [hashtable]$OverflowMap = @{},

        [System.Collections.Generic.List[object]]$Truncated
    )

    $Traits = @{}

    foreach ($Section in @($Sections)) {
        if ($null -eq $Section) { continue }
        $Key = [string]$Section.Key
        if (-not $Key -or -not $TraitMap.ContainsKey($Key)) { continue }

        # ContainsKey, not @($OverflowMap[$Key]) - see the note above.
        $ContinuationFields = if ($OverflowMap.ContainsKey($Key)) { @($OverflowMap[$Key]) } else { @() }

        $Overflow = [System.Collections.Generic.List[string]]::new()
        $Traits[$TraitMap[$Key]] = ConvertTo-ITGlueSectionHtml -Section $Section `
            -Truncated $Truncated -Overflow $Overflow -MaxParts (1 + $ContinuationFields.Count)

        for ($i = 0; $i -lt $ContinuationFields.Count; $i++) {
            # Blank unused continuation fields rather than leaving last run's content in
            # place - a tenant that shrinks must not keep stale rows in a trailing field.
            $Traits[$ContinuationFields[$i]] = if ($i -lt $Overflow.Count) { $Overflow[$i] } else { '' }
        }
    }

    return $Traits
}
