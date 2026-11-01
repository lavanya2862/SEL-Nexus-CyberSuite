param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 4, "Switching off the security guard". Run in Azure PowerShell (Cloud Shell),
# signed in to the subscription that holds the lab VMs. It runs inside the VM through Azure Run Command (as SYSTEM)
# in about 2 minutes, and leaves Defender and the firewall on, as they were.
#
#   ./Test-04-DefenderTamper.ps1           "ignore" rule for an empty folder; a test log written and cleared;
#                                          attempt to switch off real-time protection (tamper protection should refuse);
#                                          firewall off for 1 minute.   Searches 1, 2, 3, 4 and 7 should hit.
#   ./Test-04-DefenderTamper.ps1 -Cleanup  removes the "ignore" rule, the test log and its folder.
#
# Defender cmdlets are started through powershell.exe -Command, so their command line is in Defender's records.

$ErrorActionPreference = 'Stop'

function Invoke-OnVm([string]$Vm, [string]$Script) {
    $file = Join-Path ([IO.Path]::GetTempPath()) "attacklab-$([guid]::NewGuid().ToString('N')).ps1"
    Set-Content -Path $file -Value $Script -Encoding UTF8
    try {
        Write-Host "Running on $Vm through Azure Run Command (a minute or two)..." -ForegroundColor Cyan
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroup -VMName $Vm -CommandId RunPowerShellScript -ScriptPath $file
        foreach ($v in $result.Value) { if ($v.Message) { Write-Host $v.Message } }
    } finally { Remove-Item $file -ErrorAction SilentlyContinue }
}

$test = @'
$ErrorActionPreference = 'Continue'
$folder = 'C:\ProgramData\SysHealth\cache'
$log = 'SysHealth'
$tp = (Get-MpComputerStatus).IsTamperProtected
Write-Output "Tamper protection is $(if ($tp) { 'on' } else { 'OFF: search 3 will not hit, and the switch-off works for 5 seconds' })"

New-Item $folder -ItemType Directory -Force | Out-Null
& powershell.exe -NoProfile -Command "Add-MpPreference -ExclusionPath '$folder'"
Write-Output "[done] Defender told to ignore $folder"

if (-not [Diagnostics.EventLog]::Exists($log)) { New-EventLog -LogName $log -Source SysHealthSvc }
Write-EventLog -LogName $log -Source SysHealthSvc -EventId 1000 -Message 'Lab test entry'
& wevtutil.exe cl $log
Write-Output "[done] test log $log written and cleared (real Windows logs are not touched)"

& powershell.exe -NoProfile -Command 'Set-MpPreference -DisableRealtimeMonitoring $true' 2>$null
Start-Sleep 5
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
$on = (Get-MpComputerStatus).RealTimeProtectionEnabled
Write-Output "[done] real-time switch-off attempted (real-time protection is $(if ($on) { 'on' } else { 'STILL OFF: switch it on' }))"

try {
    & netsh.exe advfirewall set allprofiles state off | Out-Null
    Start-Sleep 60
} finally {
    & netsh.exe advfirewall set allprofiles state on | Out-Null
}
Write-Output '[done] firewall off for 1 minute, then back on'
'@

$cleanup = @'
Remove-MpPreference -ExclusionPath 'C:\ProgramData\SysHealth\cache' -ErrorAction SilentlyContinue
Remove-EventLog -LogName SysHealth -ErrorAction SilentlyContinue
Remove-Item 'C:\ProgramData\SysHealth\cache' -Recurse -Force -ErrorAction SilentlyContinue
Write-Output '[done] ignore rule, test log SysHealth and its folder removed'
'@

if ($Cleanup) { Invoke-OnVm $MainVm $cleanup; return }
Invoke-OnVm $MainVm $test
Write-Host "`nWait 15-60 minutes, then run the Attack Detection Agent: one story on $MainVm."
