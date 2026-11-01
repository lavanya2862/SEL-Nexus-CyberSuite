param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [string]$Url = 'https://example.com/',
    [int]$Hours = 24,
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 11, "Calling home" (1 day). Run in Azure PowerShell (Cloud Shell), signed in to
# the subscription that holds the lab VMs. It runs inside the VM through Azure Run Command (as SYSTEM).
# -Url is the harmless page it visits; the agent's fix blocks it on the VM, so example.com is the default.
#
#   ./Test-11-CallingHome.ps1           a hidden PowerShell task visits -Url every 5 minutes, with a few seconds of
#                                       wobble, for -Hours hours; a named pipe msagent_4f (Cobalt Strike's default
#                                       style) is open for one minute.   Searches 1, 3 and 4 should hit after a few hours.
#   ./Test-11-CallingHome.ps1 -Cleanup  stops and removes the task and its script.

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

# the visiting loop; it travels as base64, so the VM stores it exactly as written
$beacon = @'
$end = (Get-Date).AddHours(__HOURS__)
while ((Get-Date) -lt $end) {
    try { Invoke-WebRequest '__URL__' -UseBasicParsing -TimeoutSec 30 | Out-Null } catch { }
    Start-Sleep (300 + (Get-Random -Maximum 10))
}
'@

$test = @'
$ErrorActionPreference = 'Continue'
New-Item C:\ProgramData\SysHealth -ItemType Directory -Force | Out-Null
Set-Content C:\ProgramData\SysHealth\health.ps1 ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__BEACON__')))
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\SysHealth\health.ps1'
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 25)
Register-ScheduledTask SysHealthBeacon -Action $action -Settings $settings -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask SysHealthBeacon
Write-Output '[done] hidden task SysHealthBeacon visits __URL__ every 5 minutes for __HOURS__ hours'

$pipe = New-Object System.IO.Pipes.NamedPipeServerStream('msagent_4f')
Start-Sleep 60
$pipe.Dispose()
Write-Output '[done] named pipe msagent_4f open for one minute'
'@

$cleanup = @'
Stop-ScheduledTask SysHealthBeacon -ErrorAction SilentlyContinue
Unregister-ScheduledTask SysHealthBeacon -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\SysHealth\health.ps1 -Force -ErrorAction SilentlyContinue
Write-Output '[done] task SysHealthBeacon and health.ps1 removed'
'@

if ($Cleanup) { Invoke-OnVm $MainVm $cleanup; return }
$beaconB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($beacon.Replace('__HOURS__', [string]$Hours).Replace('__URL__', $Url)))
Invoke-OnVm $MainVm $test.Replace('__BEACON__', $beaconB64).Replace('__URL__', $Url).Replace('__HOURS__', [string]$Hours)
Write-Host "`nAfter 3 hours or more, wait 15-60 minutes, then run the Attack Detection Agent: one calling-home story on $MainVm."
