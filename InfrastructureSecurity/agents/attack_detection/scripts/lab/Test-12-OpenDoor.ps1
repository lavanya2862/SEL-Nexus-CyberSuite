param(
    [string]$ResourceGroup = 'rg-uc3-lab',
    [string]$MainVm = 'opca-wks-01',
    [string]$SecondVm = 'opcc-wks-01',
    [switch]$Cleanup
)
# LAB VMs ONLY. Attack Detection lab test 12, "An open door that attackers are using right now" (1 day). Run in Azure
# PowerShell (Cloud Shell), signed in to the subscription that holds the lab VMs. It runs inside the VM through Azure
# Run Command (as SYSTEM).
#
#   ./Test-12-OpenDoor.ps1           installs the old 7-Zip 24.07 (from 7-zip.org) on opca-wks-01, whose weakness
#                                    CVE-2025-0411 Defender lists within about a day, and runs one round of scouting
#                                    (net view of opcc-wks-01 and a port-445 check of 20 addresses) as the clue.
#                                    Searches 1 and 2 hit, plus the open-door finding, once Defender lists the weakness
#                                    (Critical/High with a public exploit).
#   ./Test-12-OpenDoor.ps1 -Cleanup  uninstalls 7-Zip 24.07.

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

$test = @'
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item C:\Tools\bin -ItemType Directory -Force | Out-Null
$setup = 'C:\Tools\bin\7z2407-x64.exe'
if (-not (Test-Path $setup)) { Invoke-WebRequest https://www.7-zip.org/a/7z2407-x64.exe -OutFile $setup -UseBasicParsing }
Start-Process $setup -ArgumentList '/S' -Wait
$v = (Get-Item 'C:\Program Files\7-Zip\7z.exe' -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
Write-Output "[done] 7-Zip installed, version $v (24.07 has CVE-2025-0411)"

& net.exe view \\__SECONDIP__ 2>&1 | Out-Null
1..20 | ForEach-Object { Test-NetConnection "__SUBNET__.$_" -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue | Out-Null }
Write-Output '[done] one round of scouting: net view and a port-445 check of 20 addresses'
'@

$cleanup = @'
$u = 'C:\Program Files\7-Zip\Uninstall.exe'
if (Test-Path $u) { Start-Process $u -ArgumentList '/S' -Wait }
Write-Output "[done] 7-Zip uninstalled: $(-not (Test-Path 'C:\Program Files\7-Zip\7z.exe'))"
'@

if ($Cleanup) { Invoke-OnVm $MainVm $cleanup; return }
$secondIp = Get-VmIp $SecondVm
$subnet = ($secondIp -split '\.')[0..2] -join '.'
Invoke-OnVm $MainVm $test.Replace('__SECONDIP__', $secondIp).Replace('__SUBNET__', $subnet)
Write-Host "`nTomorrow: once Defender lists CVE-2025-0411 on the device, run the Attack Detection Agent."
