function ConvertTo-CIPPSharingEvent {
    <#
    .SYNOPSIS
        Turns Search-CIPPBecAuditLog sharing records into the SharingChanges shape the BEC check stores.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-13). The same projection Push-BECRun applies to its user-scoped
        search, so Get-CIPPSharingBurstFindings reads tenant-wide and per-user events alike.
    .PARAMETER Records
        Search-CIPPBecAuditLog .Records (each with a parsed AuditData).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([object[]]$Records = @())

    foreach ($Record in @($Records | Where-Object { $_ -and $_.AuditData })) {
        $A = $Record.AuditData
        [pscustomobject]@{
            Operation  = [string]($A.Operation ?? $Record.Operation)
            UserKey    = [string]($A.UserId ?? $Record.UserId)
            Date       = $A.CreationTime ?? $Record.CreationDate
            Workload   = $A.Workload
            FileName   = $A.SourceFileName
            ItemUrl    = $A.ObjectId
            Target     = $A.TargetUserOrGroupName
            TargetType = $A.TargetUserOrGroupType
            ClientIP   = ConvertTo-CIPPBecHostAddress -Address ($A.ClientIP ?? $A.ClientIPAddress)
            AuditData  = $A
        }
    }
}
