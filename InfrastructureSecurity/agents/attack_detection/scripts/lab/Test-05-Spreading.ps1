param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [string]$SecondVm = 'opcc-wks-01',
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 5, "Spreading to other machines". Run in Azure PowerShell (Cloud Shell),
# signed in to the subscription that holds the lab VMs. It runs inside both VMs through Azure Run Command (as SYSTEM).
#
#   ./Test-05-Spreading.ps1           1. on opcc-wks-01: test admin account it.admin, and file sharing, remoting and
#                                        WMI opened to opca-wks-01's address only (a lab-only setting lets a local
#                                        admin account work remotely);
#                                     2. on opca-wks-01: downloads PsExec from Microsoft Sysinternals if missing, then,
#                                        as it.admin: PsExec starts Notepad on opcc-wks-01, PowerShell remoting and WMI
#                                        each run "cmd /c echo lab check" there, and a file is copied to its C$ share.
#                                     Searches 1, 3, 4 and 8 should hit on opcc-wks-01, each pointing back to opca-wks-01.
#   ./Test-05-Spreading.ps1 -Cleanup  removes it.admin, the copied file and the opened firewall rules' address limit.
#
# it.admin's password is random, made fresh each run and never shown; PsExec is given it on its command line, so it
# appears in Defender's records, like in a real attack. The agent's fix disables it.admin.

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

$groups = "'File and Printer Sharing', 'Windows Management Instrumentation (WMI)', 'Windows Remote Management'"

$prepareTarget = @'
$ErrorActionPreference = 'Continue'
$secure = ConvertTo-SecureString '__PASSWORD__' -AsPlainText -Force
if (Get-LocalUser it.admin -ErrorAction SilentlyContinue) { Set-LocalUser it.admin -Password $secure; Enable-LocalUser it.admin }
else { New-LocalUser it.admin -Password $secure -Description 'Lab test account' | Out-Null }
Add-LocalGroupMember -SID 'S-1-5-32-544' -Member it.admin -ErrorAction SilentlyContinue
# lets the local admin account it.admin work remotely; meant for labs only
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' LocalAccountTokenFilterPolicy 1 -Type DWord
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
foreach ($g in __GROUPS__) {
    Enable-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue
    Set-NetFirewallRule -DisplayGroup $g -RemoteAddress '__FROMIP__' -ErrorAction SilentlyContinue
}
New-Item C:\ProgramData\SysHealth -ItemType Directory -Force | Out-Null
Write-Output "[done] $env:COMPUTERNAME ready: it.admin, and file sharing, remoting and WMI open to __FROMIP__ only"
'@

$attack = @'
$ErrorActionPreference = 'Continue'
$target = '__TOIP__'
$user = '__TONAME__\it.admin'
$pw = '__PASSWORD__'
$cred = New-Object PSCredential($user, (ConvertTo-SecureString $pw -AsPlainText -Force))

$bin = 'C:\Tools\bin'
New-Item $bin -ItemType Directory -Force | Out-Null
if (-not (Test-Path "$bin\PsExec64.exe")) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest https://download.sysinternals.com/files/PSTools.zip -OutFile "$bin\PSTools.zip" -UseBasicParsing
    Expand-Archive "$bin\PSTools.zip" $bin -Force
    Write-Output '[done] PsExec downloaded from Microsoft Sysinternals'
}
Start-Service WinRM -ErrorAction SilentlyContinue
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $target -Concatenate -Force

$out = & "$bin\PsExec64.exe" "\\$target" -accepteula -nobanner -u $user -p $pw -d notepad.exe 2>&1
Write-Output "[done] PsExec started Notepad on $target ($(($out | Select-Object -Last 1)))"

try {
    Invoke-Command -ComputerName $target -Credential $cred -ScriptBlock { cmd.exe /c echo lab check } | Out-Null
    Write-Output "[done] PowerShell remoting ran a command on $target"
} catch { Write-Output "[failed] PowerShell remoting: $($_.Exception.Message)" }

try {
    Invoke-WmiMethod -ComputerName $target -Credential $cred -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c echo lab check' | Out-Null
    Write-Output "[done] WMI started a command on $target"
} catch { Write-Output "[failed] WMI: $($_.Exception.Message)" }

try {
    New-PSDrive -Name LabC -PSProvider FileSystem -Root "\\$target\C$" -Credential $cred | Out-Null
    New-Item C:\ProgramData\SysHealth -ItemType Directory -Force | Out-Null
    Set-Content C:\ProgramData\SysHealth\note.txt 'lab file'
    Copy-Item C:\ProgramData\SysHealth\note.txt LabC:\ProgramData\SysHealth\note.txt -Force
    Remove-PSDrive LabC
    Write-Output "[done] file copied to \\$target\C$\ProgramData\SysHealth"
} catch { Write-Output "[failed] admin share copy: $($_.Exception.Message)" }
'@

$cleanupTarget = @'
$ErrorActionPreference = 'Continue'
Remove-LocalUser it.admin -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\SysHealth\note.txt -Force -ErrorAction SilentlyContinue
foreach ($g in __GROUPS__) { Set-NetFirewallRule -DisplayGroup $g -RemoteAddress Any -ErrorAction SilentlyContinue }
Write-Output '[done] it.admin and the copied file removed; firewall address limit taken off'
'@

if ($Cleanup) { Invoke-OnVm $SecondVm $cleanupTarget.Replace('__GROUPS__', $groups); return }

$mainIp, $secondIp = (Get-VmIp $MainVm), (Get-VmIp $SecondVm)
Write-Host "$MainVm is $mainIp, $SecondVm is $secondIp"
$password = New-LabPassword
Invoke-OnVm $SecondVm $prepareTarget.Replace('__PASSWORD__', $password).Replace('__GROUPS__', $groups).Replace('__FROMIP__', $mainIp)
Invoke-OnVm $MainVm $attack.Replace('__PASSWORD__', $password).Replace('__TOIP__', $secondIp).Replace('__TONAME__', $SecondVm)
Write-Host "`nWait 15-60 minutes, then run the Attack Detection Agent: linked stories on $SecondVm and $MainVm."
