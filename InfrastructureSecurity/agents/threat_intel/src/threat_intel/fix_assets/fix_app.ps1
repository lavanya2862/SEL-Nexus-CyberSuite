param([string]$Spec)
# Threat Intel fix script - runs INSIDE a lab VM as SYSTEM (sent by Azure Run Command or Defender Live Response).
# It only does what the spec says, and the spec is built by Threat Intel from config\fix_catalog.csv (an allow-list).
#   action = probe    : report winget/choco and the installed versions of the listed apps (changes nothing)
#   action = upgrade  : close the app, update it with winget (fallback: Chocolatey)
#   action = remove   : close the app, uninstall every matching entry (end-of-life versions)
#   action = replace  : remove the old app, then install the current one
#   action = setting  : change ONE security setting (from config\setting_fix_catalog.csv), reading it before and after:
#                       kind asr = attack-protection rule, defender = a Defender Antivirus option, registry = a DWORD
#   action = respond  : after a sign of attack: update Defender's signatures, quick (or full) scan, remove what it finds
#                       (kind scan_clean, the only response), counting active threats before and after; for a lab
#                       test (lab_cleanup) it also removes the fixed UC1LabTest leftovers of scripts\lab\Invoke-UC1LabTest.ps1
# The last line of output is "FIXRESULT {json}" - Threat Intel reads that. Windows PowerShell 5.1 compatible, ASCII only.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Spec)) | ConvertFrom-Json
$log = New-Object System.Collections.Generic.List[string]
$reboot = $false
$okCodes = @(0, 1641, 3010, -1978334967, -1978334966)      # 0x8A150109/10A = winget "restart needed"
$rebootCodes = @(1641, 3010, -1978334967, -1978334966)

function Say([string]$m) { $log.Add(($m -replace '[^\x20-\x7E]', '').Trim()) }

function Clean-Text([string]$t) {
    if (-not $t) { return @() }
    $lines = $t -split "`r?`n" | ForEach-Object { ($_ -replace '[^\x20-\x7E]', '').Trim() } |
        Where-Object { $_ -and $_ -notmatch '^[-\\|/ ]+$' -and $_ -notmatch '\d+(\.\d+)? ?(KB|MB|GB) ?/ ?\d' -and $_ -notmatch '^\d+%$' }
    return @($lines | Select-Object -Last 3)
}

function Run-Exe([string]$file, [string]$argList, [int]$minutes) {
    $out = Join-Path $env:TEMP ('fix_' + [guid]::NewGuid().ToString('N') + '.txt')
    try {
        $p = Start-Process -FilePath $file -ArgumentList $argList -NoNewWindow -PassThru `
             -RedirectStandardOutput $out -RedirectStandardError "$out.err"
        $null = $p.Handle                                         # cache the handle so ExitCode is available
        if (-not $p.WaitForExit($minutes * 60000)) { try { $p.Kill() } catch {}; return @{ code = -999; text = 'timed out' } }
        $text = "$(Get-Content $out -Raw -ErrorAction SilentlyContinue)`n$(Get-Content "$out.err" -Raw -ErrorAction SilentlyContinue)"
        return @{ code = [int]$p.ExitCode; text = $text }
    } catch {
        return @{ code = -997; text = $_.Exception.Message }
    } finally {
        Remove-Item $out, "$out.err" -ErrorAction SilentlyContinue
    }
}

function Get-Apps($patterns) {
    # machine-wide installs, plus per-user installs of every loaded user profile (HKEY_USERS)
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'Registry::HKEY_USERS\*\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $found = @()
    foreach ($e in (Get-ItemProperty $keys -ErrorAction SilentlyContinue)) {
        $n = "$($e.DisplayName)"
        if (-not $n) { continue }
        if ("$($e.PSPath)" -like '*HKEY_USERS\.DEFAULT\*') { continue }   # .DEFAULT is SYSTEM's profile again (S-1-5-18)
        foreach ($p in $patterns) {
            if ($n -like $p) {
                $found += [pscustomobject]@{ name = $n; version = "$($e.DisplayVersion)"; quiet = "$($e.QuietUninstallString)";
                                            uninstall = "$($e.UninstallString)"; system = ($e.SystemComponent -eq 1); key = $e.PSChildName;
                                            user = ("$($e.PSPath)" -like '*HKEY_USERS*'); bundle = "$($e.BundleCachePath)"; path = "$($e.PSPath)" }
                break
            }
        }
    }
    return @($found)
}

# kept short: Azure Run Command only returns the last 4 KB of output, and the FIXRESULT line must fit
function Short($apps) { return @($apps | Where-Object { -not $_.system } | Select-Object -First 8 | ForEach-Object { @{ name = $_.name; version = $_.version } }) }

function Stop-Apps {
    foreach ($name in @($s.procs)) {
        if ($name) { Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    }
}

function Find-Winget {
    $c = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $dirs = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Filter 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe' -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'winget.exe') } |
        Sort-Object { try { [version](($_.Name -split '_')[1]) } catch { [version]'0.0' } }
    if ($dirs) { return (Join-Path ($dirs | Select-Object -Last 1).FullName 'winget.exe') }
    return $null
}

# As SYSTEM (Run Command) winget.exe runs outside its app package and can't find the Visual C++ runtime it ships
# against: exit -1073741515 (0xC0000135, DLL not found). Put the VCLibs framework folders on PATH; if that is not
# enough, install Microsoft's Visual C++ 2015-2022 runtime once.
$dllNotFound = -1073741515
function Ready-Winget([string]$wg, [bool]$canInstall = $true) {
    if ($script:wingetReady) { return $true }
    Get-ChildItem "$env:ProgramFiles\WindowsApps" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Microsoft.VCLibs.140.00*_x64__8wekyb3d8bbwe' } |
        ForEach-Object { if ($env:Path -notlike "*$($_.FullName)*") { $env:Path = "$($_.FullName);$env:Path" } }
    $r = Run-Exe $wg '--version' 2
    if ($r.code -eq $dllNotFound -and $canInstall) {
        Say 'winget is missing the Visual C++ runtime - installing it'
        $vc = Join-Path $env:TEMP 'vc_redist.x64.exe'
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object Net.WebClient).DownloadFile('https://aka.ms/vs/17/release/vc_redist.x64.exe', $vc)
            $i = Run-Exe $vc '/install /quiet /norestart' 10
            Say "Visual C++ runtime -> exit $($i.code)"
        } catch { Say "Visual C++ runtime download failed: $($_.Exception.Message)" }
        Remove-Item $vc -ErrorAction SilentlyContinue
        $r = Run-Exe $wg '--version' 2
    }
    $script:wingetVersion = (Clean-Text $r.text | Select-Object -First 1)
    $script:wingetReady = ($r.code -eq 0)
    if (-not $script:wingetReady) { Say "winget can't start (exit $($r.code))" }
    return $script:wingetReady
}

function Invoke-Winget([string]$verb, [string]$id) {
    $wg = Find-Winget
    if (-not $wg) { Say 'winget not available'; return $null }
    if (-not (Ready-Winget $wg)) { return $null }
    $common = "--id $id --exact --silent --source winget --accept-package-agreements --accept-source-agreements --disable-interactivity"
    $scope = ''
    if ($s.scope_machine) { $scope = ' --scope machine' }
    $r = Run-Exe $wg "$verb $common$scope" 40
    if ($r.text -match 'Failed when opening source') {
        Say 'winget source broken - resetting'
        $null = Run-Exe $wg 'source reset --force' 5
        $r = Run-Exe $wg "$verb $common$scope" 40
    }
    if ($verb -eq 'upgrade' -and $r.code -in @(-1978335212, -1978335189)) {
        # winget does not recognise the installed copy: install the current version over it
        Say "winget upgrade said $($r.code) - installing the current version over the old one"
        $r = Run-Exe $wg "install $common$scope --force" 40
    }
    Say "winget $verb $id -> exit $($r.code)"
    Clean-Text $r.text | ForEach-Object { Say "  $_" }
    return $r.code
}

function Invoke-Choco([string]$id) {
    if (-not $s.allow_choco -or -not $id) { return $null }
    $choco = "$env:ProgramData\chocolatey\bin\choco.exe"
    if (-not (Test-Path $choco)) {
        Say 'installing Chocolatey (fallback installer)'
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')) | Out-Null
        } catch { Say "Chocolatey install failed: $($_.Exception.Message)"; return $null }
    }
    $r = Run-Exe $choco "upgrade $id -y --no-progress --limit-output" 40
    Say "choco upgrade $id -> exit $($r.code)"
    Clean-Text $r.text | ForEach-Object { Say "  $_" }
    return $r.code
}

function Install-Current([string]$verb) {
    $code = Invoke-Winget $verb $s.winget
    if ($null -eq $code -or $code -notin $okCodes) {
        $c2 = Invoke-Choco $s.choco
        if ($null -ne $c2) { $code = $c2; $script:engine = 'choco' } else { $script:engine = 'winget' }
    } else { $script:engine = 'winget' }
    if ($code -in $rebootCodes) { $script:reboot = $true }
    return $code
}

function Uninstall-Entry($e) {
    if ($e.bundle -and -not (Test-Path -LiteralPath $e.bundle)) { Say "remove $($e.name): its installer is gone from the Package Cache"; return -994 }
    $cmd = $e.quiet
    $isMsi = $e.key -match '^\{[0-9A-Fa-f-]{36}\}$'
    if (-not $cmd) {
        $u = $e.uninstall
        if ($isMsi -or $u -match 'msiexec') {
            $code = if ($isMsi) { $e.key } else { [regex]::Match($u, '\{[0-9A-Fa-f-]{36}\}').Value }
            if (-not $code) { return -998 }
            $r = Run-Exe 'msiexec.exe' "/x $code /qn /norestart" 30
            Say "remove $($e.name) (msi) -> exit $($r.code)"
            if ($r.code -in $rebootCodes) { $script:reboot = $true }
            return $r.code
        } elseif ($u -match 'unins\d*\.exe') { $cmd = "$u /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" }
        elseif ($u -match 'Package Cache') { $cmd = "$u /uninstall /quiet /norestart" }
        elseif ($u) { $cmd = "$u /S" }
        else { Say "remove $($e.name): no uninstall command"; return -998 }
    }
    $r = Run-Exe 'cmd.exe' "/c `"$cmd`"" 30
    Say "remove $($e.name) -> exit $($r.code)"
    if ($r.code -in $rebootCodes) { $script:reboot = $true }
    return $r.code
}

function Remove-Matching($patterns) {
    foreach ($pass in 1, 2) {                    # pass 2 catches leftovers (e.g. MSI parts of a Python bundle)
        $apps = Get-Apps $patterns
        if (-not $apps) { break }
        $targets = if ($pass -eq 1) { @($apps | Where-Object { -not $_.system }) } else { $apps }
        if (-not $targets) { $targets = $apps }
        foreach ($e in $targets) { $null = Uninstall-Entry $e }
        Start-Sleep -Seconds 3
    }
    # A bundle (e.g. Python) installs nothing itself: its MSI parts hold the files. Once those are gone, a bundle whose
    # own installer is missing from the Package Cache can never run again, so its uninstall entry is only a leftover.
    $left = @(Get-Apps $patterns)
    if (-not @($left | Where-Object { $_.system })) {
        foreach ($e in @($left | Where-Object { $_.bundle -and -not (Test-Path -LiteralPath $_.bundle) })) {
            Remove-Item -LiteralPath $e.path -Recurse -Force -ErrorAction SilentlyContinue
            Say "removed the leftover entry for $($e.name) (its parts are uninstalled and its installer is gone)"
        }
    }
}

# ------------------------------------------------------------------ security settings
function Split-RegTarget { $i = "$($s.target)".LastIndexOf('|'); return @("$($s.target)".Substring(0, $i), "$($s.target)".Substring($i + 1)) }

function Get-Setting {
    switch ($s.kind) {
        'asr' {
            $p = Get-MpPreference
            $ids = @(); if ($p.AttackSurfaceReductionRules_Ids) { $ids = @($p.AttackSurfaceReductionRules_Ids | ForEach-Object { "$_".ToLower() }) }
            $i = [array]::IndexOf($ids, "$($s.target)".ToLower())
            if ($i -lt 0) { return $null }
            return [int](@($p.AttackSurfaceReductionRules_Actions)[$i])
        }
        'defender' {
            $v = (Get-MpPreference).($s.target)
            if ($null -eq $v) { return $null }
            return [int]$v
        }
        'registry' {
            $path, $name = Split-RegTarget
            $item = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
            if ($null -eq $item) { return $null }
            return [int64]$item.$name
        }
    }
    return $null
}

function Set-Setting {
    $v = [int64]$s.value
    switch ($s.kind) {
        'asr' {
            # keep every other rule as it is: rewrite the whole list with this rule's action changed or added
            $p = Get-MpPreference
            $ids = @(); $acts = @()
            if ($p.AttackSurfaceReductionRules_Ids) { $ids = @($p.AttackSurfaceReductionRules_Ids); $acts = @($p.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ }) }
            $i = [array]::IndexOf(@($ids | ForEach-Object { "$_".ToLower() }), "$($s.target)".ToLower())
            if ($i -ge 0) { $acts[$i] = [int]$v } else { $ids += "$($s.target)"; $acts += [int]$v }
            Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $acts -ErrorAction Stop
        }
        'defender' {
            $cur = (Get-MpPreference).($s.target)
            $val = if ($cur -is [bool]) { [bool]$v } else { [int]$v }
            $splat = @{ $s.target = $val }
            Set-MpPreference @splat -ErrorAction Stop
        }
        'registry' {
            $path, $name = Split-RegTarget
            if (-not (Test-Path $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
            New-ItemProperty -Path $path -Name $name -Value ([int64]$v) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        default { throw "unknown setting kind $($s.kind)" }
    }
}

if ($s.action -eq 'setting') {
    $result = @{ id = $s.id; action = 'setting'; computer = $env:COMPUTERNAME; kind = $s.kind; wanted = [int64]$s.value }
    $result.before = Get-Setting
    if ("$($result.before)" -eq "$($s.value)") {
        Say 'already set to the wanted value - changed nothing'
    } else {
        try { Set-Setting; Say "set $($s.kind) $($s.target) to $($s.value)" }
        catch { $result.error = ($_.Exception.Message -replace '[^\x20-\x7E]', '').Trim(); Say "change failed: $($result.error)" }
    }
    $result.after = Get-Setting
    $result.log = @($log)
    Write-Output ('FIXRESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
    exit 0
}

# ------------------------------------------------------------------ response to a sign of attack
function Get-ActiveThreats { @(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive }) }

if ($s.action -eq 'respond') {
    $result = @{ id = $s.id; action = 'respond'; computer = $env:COMPUTERNAME; kind = $s.kind }
    if ($s.kind -ne 'scan_clean') { throw "unknown response kind $($s.kind)" }
    $result.before = (Get-ActiveThreats).Count
    try { Update-MpSignature -ErrorAction Stop; Say 'Defender signatures updated' }
    catch { Say "signature update failed (scanning with the current ones): $($_.Exception.Message)" }
    $scan = if ($s.scan -eq 'FullScan') { 'FullScan' } else { 'QuickScan' }     # only these two, whatever the spec says
    $result.scan = $scan
    try { Start-MpScan -ScanType $scan -ErrorAction Stop; Say "Defender $($scan -replace 'Scan', '').ToLower() scan finished" }
    catch { $result.error = ($_.Exception.Message -replace '[^\x20-\x7E]', '').Trim(); Say "scan failed: $($result.error)" }
    if (-not $result.error -and (Get-ActiveThreats).Count -gt 0) {
        try { Remove-MpThreat -ErrorAction Stop; Say 'removed the active threats Defender found' }
        catch { Say "remove failed: $($_.Exception.Message)" }
    }
    if ($s.lab_cleanup) {
        # Only these fixed names: what the lab script creates. Nothing here comes from the spec or the evidence.
        $cleaned = New-Object System.Collections.Generic.List[string]
        $run = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        if (Get-ItemProperty -Path $run -Name 'UC1LabTest' -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $run -Name 'UC1LabTest' -ErrorAction SilentlyContinue; $cleaned.Add('Run key UC1LabTest')
        }
        $startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\UC1LabTest.cmd'
        if (Test-Path $startup) { Remove-Item $startup -Force -ErrorAction SilentlyContinue; $cleaned.Add('Startup file UC1LabTest.cmd') }
        if (Get-LocalUser -Name 'UC1LabTest' -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name 'UC1LabTest' -ErrorAction SilentlyContinue; $cleaned.Add('local user UC1LabTest')
        }
        if (Get-Service -Name 'UC1LabTest' -ErrorAction SilentlyContinue) {
            & sc.exe delete UC1LabTest | Out-Null; $cleaned.Add('service UC1LabTest')
        }
        $result.lab_cleaned = @($cleaned)
        Say ("lab test clean-up: " + $(if ($cleaned.Count) { $cleaned -join ', ' } else { 'nothing left to remove' }))
    }
    $left = Get-ActiveThreats
    $result.after = $left.Count
    $result.found = @($left | Select-Object -First 5 | ForEach-Object { "$($_.ThreatName)" })
    $result.exit = if ($result.error) { 1 } else { 0 }
    $result.log = @($log)
    Write-Output ('FIXRESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
    exit 0
}

# ------------------------------------------------------------------ main
$engine = ''
$code = $null
$before = Get-Apps @($s.check)
$wg = Find-Winget
$result = @{ id = $s.id; action = $s.action; computer = $env:COMPUTERNAME }

if ($s.action -eq 'probe') {
    $wgVersion = ''
    if ($wg -and (Ready-Winget $wg $false)) { $wgVersion = $script:wingetVersion }   # read-only: no runtime install
    $result.winget = $wgVersion
    $result.winget_path = [bool]$wg
    $result.choco = Test-Path "$env:ProgramData\chocolatey\bin\choco.exe"
    $result.ps = "$($PSVersionTable.PSVersion)"
    $result.reboot_pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                             (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    $result.apps = @($before | Where-Object { -not $_.system } | ForEach-Object { "$($_.name)|$($_.version)" })
    $result.exit = 0
} else {
    # Nothing to fix? Then change NOTHING: no update, and certainly no fresh install of an app the computer never had.
    $targets = if ($s.action -eq 'upgrade') { $before } else { Get-Apps @($s.remove) }
    if (@($targets).Count -eq 0) {
        Say 'nothing matching the catalogue name is installed - changed nothing'
        $result.not_found = $true
        $result.exit = -995
        $result.before = Short $before
        $result.after = Short $before
        $result.left = @()
        $result.left_count = 0
        $result.reboot = $false
        $result.log = @($log)
        Write-Output ('FIXRESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
        exit 0
    }
    if (@($targets | Where-Object { $_.user }).Count -gt 0) { Say 'note: installed for one user only (per-user install)' }
    Stop-Apps
    switch ($s.action) {
        'upgrade' { $code = Install-Current 'upgrade' }
        'remove'  { Remove-Matching @($s.remove); $code = 0; $engine = 'uninstall' }
        'replace' {
            Remove-Matching @($s.remove)
            $code = Install-Current 'install'
        }
        default   { Say "unknown action $($s.action)"; $code = -996 }
    }
    $after = Get-Apps @($s.check)
    $left = @()
    if ($s.remove) { $left = Get-Apps @($s.remove) }
    $result.exit = $code
    $result.engine = $engine
    $result.before = Short $before
    $result.after = Short $after
    $result.left = Short $left
    $result.left_count = @($left).Count
}
$result.reboot = $reboot
$result.log = @($log | Select-Object -Last 10 | ForEach-Object { if ($_.Length -gt 140) { $_.Substring(0, 140) } else { $_ } })
Write-Output ('FIXRESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
