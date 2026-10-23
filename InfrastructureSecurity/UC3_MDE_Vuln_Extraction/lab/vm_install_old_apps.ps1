<#
  LAB ONLY. Installs old, vulnerable app versions on a test VM so Defender has more to report.
  Run in an elevated PowerShell on the VM:

    powershell -ExecutionPolicy Bypass -File .\vm_install_old_apps.ps1 -Role A   # opca-wks-01
    powershell -ExecutionPolicy Bypass -File .\vm_install_old_apps.ps1 -Role B   # opcc-wks-01

  Role A: browsers, Java, PDF readers, password manager, Python 2, Log4j file
  Role B: web server stack, databases, old Node.js, remote-access tools, old VC++ runtime
  Every role also turns off the apps' own auto-update so they stay old.
  Log: C:\LabApps\install_old_apps.log
#>
param([Parameter(Mandatory)][ValidateSet('A', 'B')][string]$Role)

$ErrorActionPreference = 'Continue'
New-Item C:\LabApps -ItemType Directory -Force | Out-Null
Start-Transcript C:\LabApps\install_old_apps.log -Append | Out-Null

# winget is not on PATH when running as SYSTEM (e.g. Azure run-command), so find it directly
$winget = (Get-Command winget -ErrorAction SilentlyContinue).Source
if (-not $winget) {
    $winget = Get-ChildItem 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe' -ErrorAction SilentlyContinue |
              Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $winget) { Write-Error 'winget not found. Install "App Installer" from the Microsoft Store and run again.'; exit 1 }

$apps = @{
    A = @('Mozilla.Firefox', 'Mozilla.Firefox.ESR',
          'Oracle.JavaRuntimeEnvironment', 'EclipseAdoptium.Temurin.11.JDK',
          'Adobe.Acrobat.Reader.64-bit', 'Foxit.FoxitReader',
          'DominikReichl.KeePass', 'Python.Python.2')
          # WinSCP's installer refuses to run as SYSTEM (Azure Run Command); FileZilla is not in winget
    # Oracle.MySQL is left out: Oracle's download answers 403 to winget. XAMPP brings MariaDB instead
    B = @('ApacheFriends.Xampp.8.1', 'PostgreSQL.PostgreSQL.12',
          'OpenJS.NodeJS.14', 'GlavSoft.TightVNC', 'OpenVPNTechnologies.OpenVPN',
          'TeamViewer.TeamViewer', 'AnyDesk.AnyDesk', 'Microsoft.VCRedist.2008.x64')
}

$installed = @(); $failed = @()
foreach ($id in $apps[$Role]) {
    if (& $winget list --id $id --exact --accept-source-agreements 2>$null | Select-String -SimpleMatch $id) {
        Write-Host "Already installed: $id" -ForegroundColor Green; $installed += "$id (already installed)"; continue
    }
    # winget lists versions newest first; keep the 3 oldest and try the oldest first
    $vers = @(& $winget show --id $id --exact --versions --accept-source-agreements 2>$null |
              Where-Object { $_ -match '^\s*\d+(\.\d+)+' } | ForEach-Object { $_.Trim() })
    if (-not $vers) { Write-Host "NOT FOUND in winget: $id" -ForegroundColor Yellow; $failed += "$id (not found)"; continue }
    $try = @($vers | Select-Object -Last 3); [array]::Reverse($try)
    $ok = $false
    foreach ($v in $try) {
        Write-Host "Installing $id $v ..." -ForegroundColor Cyan
        # an installer that hangs is stopped after 15 minutes so the rest still runs
        $p = Start-Process $winget -NoNewWindow -PassThru -RedirectStandardOutput C:\LabApps\winget_last.txt -ArgumentList @(
            'install', '--id', $id, '--exact', '--version', $v, '--silent', '--force',
            '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
        $null = $p.Handle                     # without this, ExitCode stays empty after WaitForExit(timeout)
        if (-not $p.WaitForExit(15 * 60 * 1000)) {
            Write-Host "  still running after 15 minutes: stopped" -ForegroundColor DarkYellow
            $p | Stop-Process -Force -ErrorAction SilentlyContinue
            Get-Content C:\LabApps\winget_last.txt -ErrorAction SilentlyContinue | Select-Object -Last 5
            break
        }
        Get-Content C:\LabApps\winget_last.txt -ErrorAction SilentlyContinue | Where-Object { $_ -match '\w' } | Select-Object -Last 3
        if ($p.ExitCode -eq 0) { $installed += "$id $v"; $ok = $true; break }
        Write-Host "  failed (exit $($p.ExitCode)), trying a newer one" -ForegroundColor DarkYellow
    }
    if (-not $ok) { $failed += "$id (install failed)" }
}

function Set-Dword($path, $name, $value) {
    New-Item $path -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty $path $name $value -Type DWord
}

Write-Host "`nTurning off app auto-updates ..." -ForegroundColor Cyan
Set-Dword 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' DisableAppUpdate 1
Set-Dword 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' bUpdater 0
Set-Dword 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy' EnableJavaUpdate 0
foreach ($svc in 'AdobeARMservice', 'FoxitReaderUpdateService') {
    Get-Service $svc -ErrorAction SilentlyContinue | Stop-Service -PassThru -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'Adobe Acrobat Update|TeamViewer.*Update|AnyDesk.*Update' } |
    Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null

if ($Role -eq 'A') {
    Write-Host "`nPlacing Log4j 2.14.1 library (file only, nothing runs it) ..." -ForegroundColor Cyan
    New-Item C:\LabApps\log4j -ItemType Directory -Force | Out-Null
    try {
        Invoke-WebRequest 'https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar' `
            -OutFile C:\LabApps\log4j\log4j-core-2.14.1.jar -UseBasicParsing
        $installed += 'log4j-core 2.14.1 (C:\LabApps\log4j)'
    } catch { $failed += "log4j-core download ($($_.Exception.Message))" }
}

Write-Host "`n===== RESULT (Role $Role on $env:COMPUTERNAME) =====" -ForegroundColor Green
Write-Host "Installed:"; $installed | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green }
Write-Host "Failed / skipped:"; $failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
Write-Host "`nNext: restart the VM. Defender usually shows the new software within a few hours (up to 24)."
Stop-Transcript | Out-Null
