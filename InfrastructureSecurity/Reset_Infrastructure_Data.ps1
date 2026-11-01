<#
  Clears every agent's data and logs and the dashboard's history, so the next runs start from nothing.
  Removed items go to the Recycle Bin. Run Reset_All_Data.cmd (suite folder) rather than this file directly.
  Kept: settings (.env, config), the sign-in accounts, the GUIDE practice dataset and the triage inbox.
  -DryRun lists what would be removed and changes nothing.
#>
param([switch]$DryRun)

Add-Type -AssemblyName Microsoft.VisualBasic
$root = $PSScriptRoot
$keep = @("$root\agents\alert_triage\data\guide.duckdb", "$root\agents\alert_triage\data\inbox")

$targets = @()
foreach ($agent in 'vulnerability', 'threat_intel', 'attack_detection', 'alert_triage') {
    $dir = Join-Path $root "agents\$agent"
    foreach ($sub in 'data', 'logs') {
        if (Test-Path "$dir\$sub") { $targets += Get-ChildItem "$dir\$sub" -Force | Where-Object { $keep -notcontains $_.FullName } }
    }
    if (Test-Path "$dir\data.before-restore") { $targets += Get-Item "$dir\data.before-restore" -Force }
}
if (Test-Path "$root\dashboard\data") { $targets += Get-ChildItem "$root\dashboard\data" -Force }
if (Test-Path "$root\dashboard\data.before-restore") { $targets += Get-Item "$root\dashboard\data.before-restore" -Force }
$signins = Join-Path (Split-Path $root) 'login\data\auth\signins.jsonl'
if (Test-Path $signins) { $targets += Get-Item $signins }

if (-not $targets) { Write-Host 'Nothing to clear: the data folders are already empty.' -ForegroundColor Green; exit 0 }

$failed = 0
foreach ($t in $targets) {
    $shown = $t.FullName.Substring((Split-Path $root).Length + 1)
    if ($DryRun) { Write-Host "  would remove  $shown"; continue }
    try {
        if ($t.PSIsContainer) { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($t.FullName, 'OnlyErrorDialogs', 'SendToRecycleBin') }
        else { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($t.FullName, 'OnlyErrorDialogs', 'SendToRecycleBin') }
        Write-Host "  removed  $shown"
    } catch {
        $failed++
        Write-Host "  could not remove  $shown  ($($_.Exception.Message))" -ForegroundColor Yellow
    }
}
if ($DryRun) { Write-Host "`n$($targets.Count) items would go to the Recycle Bin (dry run, nothing changed)."; exit 0 }
if ($failed) { Write-Host "`n$failed items are still in use. Close any open report or Excel file and run the reset again." -ForegroundColor Yellow; exit 1 }
Write-Host "`nDone: $($targets.Count) items are in the Recycle Bin." -ForegroundColor Green
