param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [string]$SecondVm = 'opcc-wks-01',
    [string]$CreateAt = '02:00',
    [string]$SignInAt = '09:00',
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 8, "Secret admin account" (1 day). Run in Azure PowerShell (Cloud Shell),
# signed in to the subscription that holds the lab VMs. It runs inside both VMs through Azure Run Command (as SYSTEM).
# Times are VM time; Azure VMs run on UTC unless someone changed it, and the agent counts 19:00-07:00 UTC as night.
#
#   ./Test-08-SecretAdminAccount.ps1           schedules, on opca-wks-01 at -CreateAt (02:00): account svc_backup
#                                              created by a script, added to Administrators and Remote Desktop Users,
#                                              its password set never to expire; and on opcc-wks-01 at -SignInAt
#                                              (09:00): a sign-in to opca-wks-01 with that account over the network.
#                                              Searches 1, 2, 3, 4, 7, 8 and 9 should hit after 09:00.
#   ./Test-08-SecretAdminAccount.ps1 -Cleanup  removes svc_backup, the tasks and their files.
#
# svc_backup's password is random, made fresh each run and never shown. It sits in the two task files until they run,
# and on the night task's command line, as in a real attack; both files delete themselves.

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

# opca-wks-01: the night task (a .cmd file, so each step is its own command line in Defender's records)
$night = @'
$ErrorActionPreference = 'Continue'
New-Item C:\ProgramData\SysHealth -ItemType Directory -Force | Out-Null
@"
@echo off
net user svc_backup __PASSWORD__ /add
net localgroup Administrators svc_backup /add
net localgroup "Remote Desktop Users" svc_backup /add
powershell.exe -NoProfile -Command "Set-LocalUser -Name svc_backup -PasswordNeverExpires `$true"
del "%~f0"
"@ | Set-Content C:\ProgramData\SysHealth\acct.cmd -Encoding Ascii
$action = New-ScheduledTaskAction -Execute C:\ProgramData\SysHealth\acct.cmd
$at = [datetime]::Today.Add([timespan]'__CREATEAT__'); if ($at -lt (Get-Date)) { $at = $at.AddDays(1) }
Register-ScheduledTask SysHealthSchedule -Action $action -Trigger (New-ScheduledTaskTrigger -Once -At $at) -User SYSTEM -RunLevel Highest -Force | Out-Null
# file sharing open to opcc-wks-01, for the morning sign-in
Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue
Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -RemoteAddress '__FROMIP__' -ErrorAction SilentlyContinue
Write-Output "[done] svc_backup will be created at $($at.ToString('ddd HH:mm')) VM time"
'@

# opcc-wks-01: the morning sign-in to opca-wks-01 with the new account
$morning = @'
$ErrorActionPreference = 'Continue'
New-Item C:\ProgramData\SysHealth -ItemType Directory -Force | Out-Null
@"
`$cred = New-Object PSCredential('__TONAME__\svc_backup', (ConvertTo-SecureString '__PASSWORD__' -AsPlainText -Force))
try { New-PSDrive -Name LabC -PSProvider FileSystem -Root '\\__TOIP__\C$' -Credential `$cred -ErrorAction Stop | Out-Null; Remove-PSDrive LabC }
catch { }
Remove-Item `$MyInvocation.MyCommand.Path -Force
"@ | Set-Content C:\ProgramData\SysHealth\signin.ps1
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\SysHealth\signin.ps1'
$at = [datetime]::Today.Add([timespan]'__SIGNINAT__'); if ($at -lt (Get-Date).AddHours(1)) { $at = $at.AddDays(1) }
Register-ScheduledTask SysHealthSignIn -Action $action -Trigger (New-ScheduledTaskTrigger -Once -At $at) -User SYSTEM -RunLevel Highest -Force | Out-Null
Write-Output "[done] sign-in to __TOIP__ as svc_backup scheduled for $($at.ToString('ddd HH:mm')) VM time"
'@

$cleanupMain = @'
Remove-LocalUser svc_backup -ErrorAction SilentlyContinue
Unregister-ScheduledTask SysHealthSchedule -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\SysHealth\acct.cmd -Force -ErrorAction SilentlyContinue
Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -RemoteAddress Any -ErrorAction SilentlyContinue
Write-Output '[done] svc_backup, task SysHealthSchedule and acct.cmd removed'
'@

$cleanupSecond = @'
Unregister-ScheduledTask SysHealthSignIn -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\SysHealth\signin.ps1 -Force -ErrorAction SilentlyContinue
Write-Output '[done] task SysHealthSignIn and signin.ps1 removed'
'@

if ($Cleanup) { Invoke-OnVm $MainVm $cleanupMain; Invoke-OnVm $SecondVm $cleanupSecond; return }

$mainIp, $secondIp = (Get-VmIp $MainVm), (Get-VmIp $SecondVm)
$password = New-LabPassword
Invoke-OnVm $MainVm $night.Replace('__PASSWORD__', $password).Replace('__CREATEAT__', $CreateAt).Replace('__FROMIP__', $secondIp)
Invoke-OnVm $SecondVm $morning.Replace('__PASSWORD__', $password).Replace('__SIGNINAT__', $SignInAt).Replace('__TOIP__', $mainIp).Replace('__TONAME__', $MainVm)
Write-Host "`nAfter the morning sign-in, wait 15-60 minutes, then run the Attack Detection Agent: one story on $MainVm."
