function ConvertTo-CIPPSafeRestorePayload {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Rewrites one backed-up Intune or Conditional Access policy so it can only be created as a new, inert copy.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23). Pure.

        Conditional Access (Type 'ca'): returns the policy JSON with displayName set to NewName,
        state 'disabled', and every tenant-specific target removed - conditions.users becomes
        includeUsers ['None'] only, and conditions.clientApplications (workload identities) is dropped.

        Intune (Type 'intune*'): returns @{ Type; DisplayName; Description; TemplateJson } with the
        name set to NewName both on the row and inside the payload (Settings Catalog and the Windows
        update profile types take their name from the payload) and any 'assignments' removed.
    .PARAMETER Item
        A Get-CIPPBackupItemList entry.
    .PARAMETER NewName
        The name for the restored copy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Item,
        [Parameter(Mandatory = $true)][string]$NewName
    )

    $SetProperty = {
        param($Object, [string]$Name, $Value)
        if ($Object -is [System.Collections.IDictionary]) { $Object[$Name] = $Value }
        else { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force }
    }
    $RemoveProperty = {
        param($Object, [string]$Name)
        if ($null -eq $Object) { return }
        if ($Object -is [System.Collections.IDictionary]) { $Object.Remove($Name) }
        elseif ($Object.PSObject.Properties[$Name]) { $Object.PSObject.Properties.Remove($Name) }
    }
    $HasProperty = {
        param($Object, [string]$Name)
        if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
        return $null -ne $Object.PSObject.Properties[$Name]
    }

    if ($Item.Type -eq 'ca') {
        # Work on a deep copy so the item list used for the plan is not mutated.
        $Policy = (ConvertTo-Json -InputObject $Item.Content -Depth 100 -Compress) | ConvertFrom-Json -Depth 100
        & $SetProperty $Policy 'displayName' $NewName
        & $SetProperty $Policy 'state' 'disabled'
        & $RemoveProperty $Policy 'assignments'
        if (-not (& $HasProperty $Policy 'conditions') -or $null -eq $Policy.conditions) {
            & $SetProperty $Policy 'conditions' ([pscustomobject]@{})
        }
        & $SetProperty $Policy.conditions 'users' ([pscustomobject]@{ includeUsers = @('None') })
        & $RemoveProperty $Policy.conditions 'clientApplications'
        return (ConvertTo-Json -InputObject $Policy -Depth 100 -Compress)
    }

    if ($Item.Type -like 'intune*') {
        $Raw = $Item.Raw
        $TemplateType = [string]$Raw.Type
        $Template = $Item.Content.Template
        if ($Template -is [string]) {
            throw "The backed-up template for '$($Item.Name)' is not valid JSON and cannot be restored safely."
        }
        $Template = (ConvertTo-Json -InputObject $Template -Depth 100 -Compress) | ConvertFrom-Json -Depth 100
        & $RemoveProperty $Template 'assignments'
        $PayloadNamedByName = $TemplateType -eq 'Catalog'
        $PayloadNamedByDisplayName = $TemplateType -in @('windowsDriverUpdateProfiles', 'windowsFeatureUpdateProfiles', 'windowsQualityUpdatePolicies', 'windowsQualityUpdateProfiles')
        if ((& $HasProperty $Template 'name') -or $PayloadNamedByName) { & $SetProperty $Template 'name' $NewName }
        if ((& $HasProperty $Template 'displayName') -or $PayloadNamedByDisplayName) { & $SetProperty $Template 'displayName' $NewName }
        return [pscustomobject][ordered]@{
            Type         = $TemplateType
            DisplayName  = $NewName
            Description  = $Raw.Description
            TemplateJson = (ConvertTo-Json -InputObject $Template -Depth 100 -Compress)
        }
    }

    throw "Safe restore-as-new does not support component type '$($Item.Type)'."
}
