param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [string]$Url = 'https://example.com/',
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 3, "Harmful scripts and misused Windows tools". Run in Azure PowerShell
# (Cloud Shell), signed in to the subscription that holds the lab VMs. It runs inside the VM through Azure Run Command.
# -Url is the harmless page certutil downloads; the agent's fix blocks it on the VM, so example.com is the default.
#
#   ./Test-03-HarmfulScripts.ps1           encoded PowerShell that only prints a line; certutil downloads -Url;
#                                          mshta runs a one-line script that closes itself; update.js in Temp writes
#                                          a text file.   Searches 1, 4, 5 and 9 should hit.
#   ./Test-03-HarmfulScripts.ps1 -Cleanup  removes the downloaded and written files.

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
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "update check complete"'))
& powershell.exe -NoProfile -EncodedCommand $enc | Out-Null
Write-Output '[done] encoded PowerShell command (prints "update check complete")'

& certutil.exe -urlcache -split -f '__URL__' C:\Windows\Temp\config.txt | Out-Null
Write-Output '[done] certutil downloaded __URL__ to C:\Windows\Temp\config.txt'

$p = Start-Process mshta.exe -ArgumentList '"javascript:close();"' -PassThru
$p | Wait-Process -Timeout 20 -ErrorAction SilentlyContinue
if (-not $p.HasExited) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
Write-Output '[done] mshta ran a one-line script'

Set-Content C:\Windows\Temp\update.js 'var f=new ActiveXObject("Scripting.FileSystemObject");f.CreateTextFile(f.GetSpecialFolder(2)+"\\update_done.txt").Close();'
& wscript.exe //B C:\Windows\Temp\update.js
Write-Output '[done] update.js run from Temp (it only writes update_done.txt)'
'@

$cleanup = @'
Remove-Item C:\Windows\Temp\config.txt, C:\Windows\Temp\update.js, C:\Windows\Temp\update_done.txt -Force -ErrorAction SilentlyContinue
Write-Output '[done] config.txt, update.js and update_done.txt removed'
'@

if ($Cleanup) { Invoke-OnVm $MainVm $cleanup; return }
Invoke-OnVm $MainVm $test.Replace('__URL__', $Url)
Write-Host "`nWait 15-60 minutes, then run the Attack Detection Agent: one harmful-scripts story on $MainVm."
