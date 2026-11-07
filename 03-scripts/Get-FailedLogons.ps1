<#
.SYNOPSIS  Summarise Windows failed logons (event 4625) by user, with logon type.
.USAGE     .\Get-FailedLogons.ps1 [-Days 7] [-OutCsv ..\output\failed_logons.csv]
#>
param(
    [int]$Days = 7,
    [string]$OutCsv = "..\output\failed_logons.csv"
)

$filter = @{ LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-$Days) }
$events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue

if (-not $events) { Write-Host "No 4625 events in the last $Days days."; return }

$rows = foreach ($e in $events) {
    $x = [xml]$e.ToXml()
    $data = $x.Event.EventData.Data
    [pscustomobject]@{
        Time      = $e.TimeCreated
        User      = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        Domain    = ($data | Where-Object Name -eq 'TargetDomainName').'#text'
        LogonType = ($data | Where-Object Name -eq 'LogonType').'#text'
        Source    = ($data | Where-Object Name -eq 'IpAddress').'#text'
    }
}

# Per-user summary (the headline)
$rows | Group-Object User |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize

# Full detail to CSV
$rows | Sort-Object Time | Export-Csv $OutCsv -NoTypeInformation
Write-Host "Wrote $($rows.Count) failed-logon records to $OutCsv"