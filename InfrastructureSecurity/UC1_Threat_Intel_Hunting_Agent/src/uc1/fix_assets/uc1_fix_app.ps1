param([string]$Spec)
# UC1 fix script - runs INSIDE a lab VM as SYSTEM (sent by Azure Run Command or Defender Live Response).
# It only does what the spec says, and the spec is built by UC1 from config\fix_catalog.csv (an allow-list).
#   action = probe    : report winget/choco and the installed versions of the listed apps (changes nothing)
#   action = upgrade  : close the app, update it with winget (fallback: Chocolatey)
#   action = remove   : close the app, uninstall every matching entry (end-of-life versions)
#   action = replace  : remove the old app, then install the current one
#   action = setting  : change ONE security setting (from config\setting_fix_catalog.csv), reading it before and after:
#                       kind asr = attack-protection rule, defender = a Defender Antivirus option, registry = a DWORD
# The last line of output is "UC1RESULT {json}" - UC1 reads that. Windows PowerShell 5.1 compatible, ASCII only.

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
    $out = Join-Path $env:TEMP ('uc1_' + [guid]::NewGuid().ToString('N') + '.txt')
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
        foreach ($p in $patterns) {
            if ($n -like $p) {
                $found += [pscustomobject]@{ name = $n; version = "$($e.DisplayVersion)"; quiet = "$($e.QuietUninstallString)";
                                            uninstall = "$($e.UninstallString)"; system = ($e.SystemComponent -eq 1); key = $e.PSChildName;
                                            user = ("$($e.PSPath)" -like '*HKEY_USERS*') }
                break
            }
        }
    }
    return @($found)
}

# kept short: Azure Run Command only returns the last 4 KB of output, and the UC1RESULT line must fit
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

function Invoke-Winget([string]$verb, [string]$id) {
    $wg = Find-Winget
    if (-not $wg) { Say 'winget not available'; return $null }
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
    Write-Output ('UC1RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
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
    if ($wg) { $wgVersion = ((Run-Exe $wg '--version' 2).text).Trim() }
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
        Write-Output ('UC1RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
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
Write-Output ('UC1RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
