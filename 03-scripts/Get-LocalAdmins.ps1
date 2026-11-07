<#
.SYNOPSIS  List members of the local Administrators group, with source and type.
#>
param([string]$OutCsv = "..\output\local_admins.csv")

try {
    $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
} catch {
    # Fallback for machines where Get-LocalGroupMember chokes on orphaned SIDs
    Write-Warning "Get-LocalGroupMember failed; falling back to 'net localgroup'."
    $members = net localgroup Administrators |
        Select-Object -Skip 6 |
        Where-Object { $_ -and $_ -notmatch 'completed successfully' } |
        ForEach-Object { [pscustomobject]@{ Name=$_; PrincipalSource='(net)'; ObjectClass='' } }
}

$members |
    Select-Object Name, PrincipalSource, ObjectClass |
    Tee-Object -Variable out | Format-Table -AutoSize
$out | Export-Csv $OutCsv -NoTypeInformation
Write-Host "Wrote $($out.Count) admin members to $OutCsv"