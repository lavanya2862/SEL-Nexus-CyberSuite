param(
    [ValidateSet(1, 2)][int]$Part = 1,
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 1, "Ransomware". Run in Azure PowerShell (Cloud Shell), signed in to the
# subscription that holds the lab VMs. It runs inside the VM through Azure Run Command (as SYSTEM): nobody signs in.
#
#   ./Test-01-Ransomware.ps1 -Part 1   200 dummy files; backup wipe attempt on drive Z: (fails on purpose);
#                                      startup repair off and straight back on.   Searches 1 and 3 should hit.
#   (wait 15-60 minutes, run the agent, approve the protective snapshot)
#   ./Test-01-Ransomware.ps1 -Part 2   5 dummy business services stopped; the 200 files renamed to .locked;
#                                      a ransom note in 10 folders.               Searches 4, 5, 6 and 7 should hit.
#   ./Test-01-Ransomware.ps1 -Cleanup  removes the services, files and notes.

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

$services = "'SQLAgentFin', 'VeeamBackupSvc', 'BackupExecAgent', 'MailRelaySvc', 'FileSyncSvc'"

$part1 = @'
$ErrorActionPreference = 'Continue'
1..10 | ForEach-Object {
    $d = "C:\Shares\Finance\Team$_"
    New-Item $d -ItemType Directory -Force | Out-Null
    1..20 | ForEach-Object { Set-Content "$d\Report_$_.docx" 'dummy text' }
}
Write-Output '[done] 200 dummy files in C:\Shares\Finance'
& vssadmin.exe delete shadows /for=Z: /quiet 2>&1 | Out-Null
Write-Output '[done] backup copies delete attempt on drive Z: (fails on purpose, still recorded)'
& bcdedit.exe /set '{default}' recoveryenabled No | Out-Null
& bcdedit.exe /set '{default}' recoveryenabled Yes | Out-Null
Write-Output '[done] Windows startup repair switched off and straight back on'
'@

$part2 = @'
$ErrorActionPreference = 'Continue'
$svc = __SERVICES__
$svc | ForEach-Object { & sc.exe create $_ binPath= 'C:\Windows\System32\cmd.exe /c rem' start= demand | Out-Null }
$svc | ForEach-Object { & sc.exe stop $_ 2>&1 | Out-Null }
Write-Output '[done] 5 dummy business services created and stopped within a minute'
$n = 0
Get-ChildItem C:\Shares\Finance -Recurse -File | Where-Object Extension -ne '.locked' | ForEach-Object {
    Rename-Item $_.FullName "$($_.Name).locked"; $n++ }
Write-Output "[done] $n files renamed to .locked"
1..10 | ForEach-Object { Set-Content "C:\Shares\Finance\Team$_\README_RESTORE_FILES.txt" 'Lab test note.' }
Write-Output '[done] README_RESTORE_FILES.txt written into 10 folders'
'@.Replace('__SERVICES__', $services)

$cleanup = @'
$ErrorActionPreference = 'Continue'
__SERVICES__ | ForEach-Object { & sc.exe delete $_ 2>&1 | Out-Null }
Remove-Item C:\Shares\Finance\Team* -Recurse -Force -ErrorAction SilentlyContinue
Write-Output '[done] dummy services, files and notes removed'
'@.Replace('__SERVICES__', $services)

if ($Cleanup) { Invoke-OnVm $MainVm $cleanup; return }
Invoke-OnVm $MainVm $(if ($Part -eq 1) { $part1 } else { $part2 })
if ($Part -eq 1) {
    Write-Host "`nWait 15-60 minutes, run the Attack Detection Agent, approve the snapshot, then run -Part 2."
} else {
    Write-Host "`nWait 15-60 minutes, then run the Attack Detection Agent: one ransomware story on $MainVm."
}
