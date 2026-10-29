param(
    [ValidateSet('All', 'RunKey', 'StartupFile', 'LocalUser', 'Service', 'Discovery', 'Amsi')]
    [string[]]$Test = 'All',
    [switch]$Cleanup
)
# LAB VMs ONLY. Harmless signs of attack for the Attack Detection Agent to find and its auto-fix to resolve.
# Run in the VM as administrator:  powershell -ExecutionPolicy Bypass -File .\Invoke-UC1LabTest.ps1 [-Test RunKey,Service]
# Everything it creates is named UC1LabTest, does nothing when it runs, and is marked as a test, so the agent reports it
# as a TEST and the auto-fix (Defender scan-and-clean) also removes these leftovers. -Cleanup removes them by hand.
#
#   RunKey      T1547.001  HKLM Run value UC1LabTest (runs "cmd /c rem" at start-up: does nothing)
#   StartupFile T1547.001  UC1LabTest.cmd in the all-users Startup folder (a comment line only)
#   LocalUser   T1136.001  local user UC1LabTest, created with no password and disabled straight away
#   Service     T1543.003  service UC1LabTest (manual start, never started)
#   Discovery   T1082      whoami, hostname, ipconfig, systeminfo, net localgroup, tasklist from one command prompt
#   Amsi        AV         Microsoft's harmless AMSI test sample: Defender blocks it as malware
#
# Defender takes 15-60 minutes to show the events in Advanced Hunting; then run the Attack Detection Agent.

$ErrorActionPreference = 'Continue'
$Name = 'UC1LabTest'
$Run = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
$Startup = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp\$Name.cmd"
$Cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host 'Run this in PowerShell as administrator.' -ForegroundColor Red; exit 1 }

function Done([string]$what) { Write-Host "  [done] $what" -ForegroundColor Green }

if ($Cleanup) {
    Write-Host 'Removing the UC1 lab test leftovers'
    & reg.exe delete $Run /v $Name /f 2>$null | Out-Null; Done "Run value $Name"
    Remove-Item $Startup -Force -ErrorAction SilentlyContinue; Done "Startup file $Name.cmd"
    Remove-LocalUser -Name $Name -ErrorAction SilentlyContinue; Done "local user $Name"
    & sc.exe delete $Name 2>$null | Out-Null; Done "service $Name"
    exit 0
}

$all = $Test -contains 'All'
Write-Host 'UC1 lab tests (harmless)'

if ($all -or $Test -contains 'RunKey') {
    & reg.exe add $Run /v $Name /t REG_SZ /d "$Cmd /c rem $Name" /f | Out-Null
    Done 'Run key: a program set to start automatically'
}
if ($all -or $Test -contains 'StartupFile') {
    & $Cmd /c "echo @rem uc1 lab test> `"$Startup`""
    Done 'Startup folder: a file that runs at every sign-in'
}
if ($all -or $Test -contains 'LocalUser') {
    if (-not (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $Name -NoPassword -Description 'uc1 lab test' | Out-Null
    }
    Disable-LocalUser -Name $Name
    Done 'New local user account (disabled, no password)'
}
if ($all -or $Test -contains 'Service') {
    & sc.exe create $Name binPath= "$Cmd /c rem $Name" start= demand DisplayName= $Name | Out-Null
    Done 'New Windows service (never started)'
}
if ($all -or $Test -contains 'Discovery') {
    # one command prompt runs them all, so they share a parent like an attacker's script would
    & $Cmd /c "rem $Name & whoami /all & hostname & ipconfig /all & systeminfo & net localgroup administrators & tasklist" | Out-Null
    Done 'Burst of discovery commands'
}
if ($all -or $Test -contains 'Amsi') {
    # the sample is put together only inside the child, so this file itself is not flagged
    $code = "`$x = 'AMSI Test ' + 'Sample: 7e72c3ce-861b-' + '4339-8740-0ac1484f1386'; Invoke-Expression `$x # $Name"
    & powershell.exe -NoProfile -Command $code 2>$null | Out-Null
    Done 'AMSI test sample (Defender should block it)'
}
Write-Host "`nWait 15-60 minutes, then run the Attack Detection Agent. Its auto-fix scans this VM and removes the leftovers."
