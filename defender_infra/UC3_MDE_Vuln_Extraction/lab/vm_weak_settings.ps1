<#
  LAB ONLY. Weakens Windows security settings on a test VM so Defender's security-setting
  checks and missing-update findings have something to show. Never run this on a real PC.
  Take a VM snapshot first. Defender antivirus and the Defender sensor are left ON.

  Run in an elevated PowerShell on the VM:

    powershell -ExecutionPolicy Bypass -File .\vm_weak_settings.ps1 -Role A                       # opca-wks-01
    powershell -ExecutionPolicy Bypass -File .\vm_weak_settings.ps1 -Role B                       # opcc-wks-01
    powershell -ExecutionPolicy Bypass -File .\vm_weak_settings.ps1 -Role B -RemoveLatestUpdate   # also uninstall newest cumulative update

  Role A: SMBv1, LLMNR/NetBIOS, RDP without NLA, weak password policy, AutoRun, Public firewall off,
          old authentication (anonymous enumeration, LM/NTLMv1, WDigest), weak expired certificate
  Role B: stops automatic Windows updates (optionally removes the newest cumulative update)
  Log: C:\LabApps\weak_settings.log
#>
param(
    [Parameter(Mandatory)][ValidateSet('A', 'B')][string]$Role,
    [switch]$RemoveLatestUpdate
)

$ErrorActionPreference = 'Continue'
New-Item C:\LabApps -ItemType Directory -Force | Out-Null
Start-Transcript C:\LabApps\weak_settings.log -Append | Out-Null

function Set-Dword($path, $name, $value) {
    New-Item $path -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty $path $name $value -Type DWord
}

if ($Role -eq 'A') {
    Write-Host 'SMBv1 on, SMB signing off, insecure guest logons allowed' -ForegroundColor Cyan
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart | Out-Null
    # separate calls: right after enabling the feature the SMB1 switch fails until a restart, which would block the signing change too
    Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction SilentlyContinue
    Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' AllowInsecureGuestAuth 1

    Write-Host 'LLMNR and NetBIOS on' -ForegroundColor Cyan
    Set-Dword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 1
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
        Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]1 } | Out-Null

    Write-Host 'RDP on without Network Level Authentication' -ForegroundColor Cyan
    Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0
    Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 0

    Write-Host 'Weak password and lockout policy' -ForegroundColor Cyan
    net accounts /minpwlen:0 /maxpwage:unlimited /lockoutthreshold:0

    Write-Host 'AutoRun on, Public firewall profile off' -ForegroundColor Cyan
    Set-Dword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 0
    Set-NetFirewallProfile -Profile Public -Enabled False

    Write-Host 'Old authentication: anonymous enumeration, LM/NTLMv1, WDigest' -ForegroundColor Cyan
    Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RestrictAnonymous 0
    Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RestrictAnonymousSAM 0
    Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 1
    Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 1

    Write-Host 'Weak expired certificate (RSA 1024, SHA-1)' -ForegroundColor Cyan
    New-SelfSignedCertificate -DnsName 'lab-weak.local' -CertStoreLocation Cert:\LocalMachine\My `
        -KeyAlgorithm RSA -KeyLength 1024 -HashAlgorithm SHA1 `
        -NotBefore (Get-Date).AddYears(-2) -NotAfter (Get-Date).AddDays(-1) | Out-Null
}

if ($Role -eq 'B') {
    Write-Host 'Stopping automatic Windows updates' -ForegroundColor Cyan
    Set-Dword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' NoAutoUpdate 1

    $lcus = Get-WindowsPackage -Online | Where-Object PackageName -like '*RollupFix*' | Sort-Object InstallTime -Descending
    Write-Host 'Installed cumulative updates (newest first):'
    $lcus | Select-Object PackageName, InstallTime | Format-Table -AutoSize | Out-String | Write-Host
    if ($RemoveLatestUpdate -and $lcus) {
        Write-Host "Removing $($lcus[0].PackageName) (takes a while) ..." -ForegroundColor Cyan
        Remove-WindowsPackage -Online -PackageName $lcus[0].PackageName -NoRestart | Out-Null
    }
}

Write-Host "`nDone (Role $Role on $env:COMPUTERNAME). Restart the VM now." -ForegroundColor Green
Stop-Transcript | Out-Null
