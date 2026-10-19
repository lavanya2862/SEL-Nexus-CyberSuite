# Installs the CodeQL CLI bundle (CLI + standard query packs) into .\tools\codeql so the
# Vulnerability Analysis Agent can use CodeQL as its primary SAST engine.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\install-codeql.ps1
# Download size is roughly 500-700 MB. CodeQL is free for open-source and research use; check the
# GitHub CodeQL terms for commercial/private code.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # the PS 5.1 progress bar slows large downloads dramatically
$root = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $root "tools"
$url = "https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-win64.tar.gz"
$archive = Join-Path $env:TEMP "codeql-bundle-win64.tar.gz"

New-Item -ItemType Directory -Force -Path $tools | Out-Null
Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
if (Test-Path (Join-Path $tools "codeql")) { Remove-Item -Recurse -Force (Join-Path $tools "codeql") }
Write-Host "Extracting to $tools"
tar -xzf $archive -C $tools
Remove-Item $archive
& (Join-Path $tools "codeql\codeql.exe") version
Write-Host "CodeQL installed. Restart the server; the Analysis Agent picks up tools\codeql automatically."
