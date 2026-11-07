<#
.SYNOPSIS  List running services with their account, path and start mode.
#>
param([string]$OutCsv = "..\output\services.csv")

$svcs = Get-CimInstance Win32_Service |
    Where-Object State -eq 'Running' |
    Select-Object Name, DisplayName, StartName, StartMode,
        @{N='Path'; E={ $_.PathName }} |
    Sort-Object Name

$svcs | Format-Table -AutoSize
$svcs | Export-Csv $OutCsv -NoTypeInformation

# Flag anything running from a suspicious location (a tiny hunting touch)
$suspicious = $svcs | Where-Object { $_.Path -match 'Temp|AppData|Users\\Public' }
if ($suspicious) {
    Write-Warning "Services running from unusual paths:"
    $suspicious | Format-Table Name, Path -AutoSize
}
Write-Host "Wrote $($svcs.Count) running services to $OutCsv"