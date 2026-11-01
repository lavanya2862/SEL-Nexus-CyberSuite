param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [string]$SecondVm = 'opcc-wks-01',
    [int]$Days = 5,
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 9, "Quiet scouting" (5 days). Run in Azure PowerShell (Cloud Shell), signed in
# to the subscription that holds the lab VMs. It runs inside the VM through Azure Run Command (as SYSTEM).
#
#   ./Test-09-QuietScouting.ps1           test account it.support; a daily task, as it.support, at a random time between
#                                         08:00 and 16:00 (VM time) for -Days days, runs 3 harmless scouting commands
#                                         picked from: whoami /groups, net localgroup administrators, net view of
#                                         opcc-wks-01, systeminfo, ipconfig /all, a port-445 check of 20 addresses.
#                                         The first day runs straight away.
#                                         Search 2 should hit by day 3; 5 or 6 on days with the address check or net view.
#                                         The domain searches stay skipped without a domain controller.
#   ./Test-09-QuietScouting.ps1 -Cleanup  removes the task, its script and it.support.

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

function Get-VmIp([string]$Vm) {
    $nicId = (Get-AzVM -ResourceGroupName $ResourceGroup -Name $Vm).NetworkProfile.NetworkInterfaces[0].Id
    (Get-AzNetworkInterface -ResourceId $nicId).IpConfigurations[0].PrivateIpAddress
}

function New-LabPassword { (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ })) + '-7a!' }

# the daily scouting script; it travels as base64, so the VM stores it exactly as written
$scout = @'
$picks = @(
    { whoami.exe /groups },
    { net.exe localgroup administrators },
    { net.exe view \\__SECONDIP__ },
    { systeminfo.exe },
    { ipconfig.exe /all },
    { 1..20 | ForEach-Object { Test-NetConnection "__SUBNET__.$_" -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue } }
)
$picks | Get-Random -Count 3 | ForEach-Object { & $_ 2>&1 | Out-Null }
'@

$test = @'
$ErrorActionPreference = 'Continue'
New-Item C:\ProgramData\SysHealth -ItemType Directory -Force | Out-Null
Set-Content C:\ProgramData\SysHealth\scout.ps1 ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SCOUT__')))
$pw = '__PASSWORD__'
$secure = ConvertTo-SecureString $pw -AsPlainText -Force
if (Get-LocalUser it.support -ErrorAction SilentlyContinue) { Set-LocalUser it.support -Password $secure }
else { New-LocalUser it.support -Password $secure -Description 'Lab test account' | Out-Null }
# Performance Log Users may sign in as a batch job, which is how the daily task runs as it.support
Add-LocalGroupMember -SID 'S-1-5-32-559' -Member it.support -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\SysHealth\scout.ps1'
$trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddDays(1).AddHours(8)) -RandomDelay (New-TimeSpan -Hours 8)
$trigger.EndBoundary = [datetime]::Today.AddDays(__DAYS__).ToString('s')
Register-ScheduledTask SysHealthScout -Action $action -Trigger $trigger -User it.support -Password $pw -Force | Out-Null
Start-ScheduledTask SysHealthScout
Write-Output "[done] it.support scouts today (now) and once a day at a random time until $([datetime]::Today.AddDays(__DAYS__).ToString('ddd dd MMM'))"
'@

$cleanup = @'
Unregister-ScheduledTask SysHealthScout -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\SysHealth\scout.ps1 -Force -ErrorAction SilentlyContinue
Remove-LocalUser it.support -ErrorAction SilentlyContinue
Write-Output '[done] task SysHealthScout, scout.ps1 and it.support removed'
'@

if ($Cleanup) { Invoke-OnVm $MainVm $cleanup; return }
$secondIp = Get-VmIp $SecondVm
$subnet = ($secondIp -split '\.')[0..2] -join '.'
$scoutB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($scout.Replace('__SECONDIP__', $secondIp).Replace('__SUBNET__', $subnet)))
Invoke-OnVm $MainVm $test.Replace('__PASSWORD__', (New-LabPassword)).Replace('__SCOUT__', $scoutB64).Replace('__DAYS__', [string]$Days)
Write-Host "`nRun the Attack Detection Agent once a day. Single days should stay low; by day 3 the several-days warning appears."
