# Fix Catalogue Comparison and Proposed Merge

This document compares the remediation catalogues between the Threat Intel Agent (`agents/threat_intel/config/`) and the Vulnerability Agent (`agents/vulnerability/config/`), analyzes which code reads each file, highlights differences, and provides proposed merged catalogue files.

---

## Part 1: Application Fix Catalog (`fix_catalog.csv`)

### 1. Which Code Reads Each File

- **Threat Intel Agent (`agents/threat_intel/config/fix_catalog.csv`)**:
  - Read by `agents/threat_intel/src/threat_intel/fix/plan.py` in `load_catalog()`.
  - Used by `plan.py`, `runner.py`, and `executors.py` in the Fix Centre engine.
  - Requires automated execution attributes: `winget_id`, `choco_id`, regex `match` for uninstall string matching, `processes` to terminate prior to updating, execution `stage` (1–4), and operational verb `action` (`upgrade`, `remove`, `replace`, `none`).

- **Vulnerability Agent (`agents/vulnerability/config/fix_catalog.csv`)**:
  - Read by `agents/vulnerability/src/vulnerability/ai/fixes.py` in `load_catalog()`.
  - Used to build remediation cards and AI prompts for the dashboard and reports.
  - Requires presentation attributes: exact CLI `command`, `official_url`, human-facing `action` sentence, and user guidance `note`.

---

### 2. Schema Comparison

| Threat Intel Column | Vulnerability Column | Notes |
|---|---|---|
| `software_name` | `software_name` | Primary key matching Microsoft Defender software inventory name. |
| `app` | `app` | Display name of the application. |
| `action` | `action` | **Different format**: Threat Intel uses an operational enum (`upgrade`, `remove`, `replace`, `none`), whereas Vulnerability Agent uses human-readable instructional text (e.g., `Update Firefox to the latest version`). |
| `winget_id` | *(none)* | Package identifier for Windows Package Manager (`winget`). |
| `choco_id` | *(none)* | Package identifier for Chocolatey package manager. |
| *(none)* | `command` | Complete CLI command string shown on UI cards. |
| *(none)* | `official_url` | Vendor download / security release URL. |
| `match` | *(none)* | Regex pattern to detect and uninstall older installed versions. |
| `processes` | *(none)* | Process names to terminate before patching. |
| `stage` | *(none)* | Phased deployment ring (1 = high priority/simple, 4 = component/none). |
| `note` | `note` | Both contain notes; Threat Intel focuses on lab/execution details, Vulnerability focuses on analyst/user guidance. |

---

### 3. Rows Only in One File

**None.** Both files contain exactly the same 22 `software_name` keys:
`7-zip`, `acrobat_reader_dc`, `gimp`, `git`, `libreoffice`, `edge_chromium-based`, `powershell`, `visual_studio_code`, `firefox`, `thunderbird`, `nodejs`, `notepad++`, `openssl`, `putty`, `python`, `winrar`, `vlc_media_player`, `wireshark`, `meetings`, `.net`, `.net_core`, `asp.net_core`.

---

### 4. Rows in Both with Different Values

For all 22 rows, the columns `action`, `command`, `official_url`, `winget_id`, `choco_id`, `match`, `processes`, `stage`, and `note` differ between the two files. The most significant functional divergences are:

1. **`acrobat_reader_dc` (Architecture & Download)**
   - **Threat Intel**: `winget_id=Adobe.Acrobat.Reader.32-bit`, `note=Lab has the 32-bit Reader DC; large download (several minutes)`.
   - **Vulnerability**: `command=winget upgrade --id Adobe.Acrobat.Reader.64-bit --exact`, `note=Reader can also update itself: Help > Check for updates`.
   - **Analysis**: The lab virtual machines run 32-bit Reader DC. Running a 64-bit upgrade command against an existing 32-bit installation can create side-by-side corruption.

2. **`python` (EOL Removal vs Upgrade)**
   - **Threat Intel**: `app=Python (old version)`, `action=remove`, `match=Python {ver2}.*`, `processes=python;pythonw`, `note=End-of-life: no fix will ever come - removed (nothing in the lab uses it)`.
   - **Vulnerability**: `app=Python`, `command=winget install --id Python.Python.3.14 --exact`, `action=Install a supported Python 3 and uninstall the old versions`, `note=Old Python versions do not update in place: each one must be uninstalled in Settings > Apps after checking nothing still needs it`.
   - **Analysis**: Legacy Python versions (e.g., 3.7, 3.8, 3.9) do not update in place. Threat Intel's script purges old versions; Vulnerability advises installing supported Python 3.14 while uninstalling legacy branches.

3. **`nodejs` (EOL Removal vs LTS Upgrade)**
   - **Threat Intel**: `app=Node.js 16`, `action=remove`, `match=Node.js*`, `processes=node`, `note=End-of-life: removed (nothing in the lab uses it)`.
   - **Vulnerability**: `app=Node.js`, `command=winget upgrade --id OpenJS.NodeJS.LTS --exact`, `action=Move to a supported Node.js LTS version`, `note=Node.js 16 is end-of-life and gets no more fixes: test the apps that use it before switching`.
   - **Analysis**: Similar to Python, Node.js 16 is EOL. Vulnerability upgrades to `OpenJS.NodeJS.LTS`, whereas Threat Intel uninstalls Node.js 16.

4. **`.net`, `.net_core`, `asp.net_core` (Runtimes)**
   - **Threat Intel**: `action=remove`, `match=Microsoft * Runtime - {ver2}.*`, `stage=2`, `note=End-of-life: no fix will ever come - removed (nothing in the lab uses it); install .NET 8 only if a program needs it`.
   - **Vulnerability**: `command=winget install --id Microsoft.DotNet.Runtime.8 --exact`, `action=Remove the old .NET versions and install .NET 8 only if a program needs it`.
   - **Analysis**: EOL runtimes (.NET 5/6, Core 2.1/3.1, ASP.NET Core 3.1/5.0) require removal; Vulnerability also provides the installation command for the supported LTS runtime (.NET 8).

5. **`gimp`**
   - **Threat Intel**: `action=replace`, `winget_id=GIMP.GIMP.3`, `match=GIMP 2*`, `processes=gimp-2.10;gimp`, `note=Old GIMP 2.10 removed and the current GIMP installed`.
   - **Vulnerability**: `command=winget install --id GIMP.GIMP.3 --exact`, `action=Install the current GIMP and remove the old GIMP 2.10 versions`, `note=GIMP 3 installs next to GIMP 2: uninstall the old versions in Settings > Apps afterwards`.

6. **`openssl`**
   - **Threat Intel**: `action=none`, `stage=4`, `note=Not an app but a part inside other apps: Acrobat / GIMP / Git / LibreOffice / Python / Zoom (fixed by their own rows); Paint / Photos / OneDrive (update themselves); Azure Monitor agent (updated by Azure)`.
   - **Vulnerability**: `command=` (empty), `official_url=` (empty), `action=Update the apps that carry these OpenSSL files (see 'Where it is installed')`, `note=OpenSSL is a component inside other programs - there is nothing called OpenSSL to update; updating each host app replaces its copy`.

---

### 5. Proposed Merged `fix_catalog.csv`

The merged schema retains all columns required by both the Fix Centre execution engine and the Vulnerability Agent reporting/AI cards:
`software_name,app,action,winget_id,choco_id,command,official_url,match,processes,stage,note`

- **Execution fields preserved**: `action` (verb), `winget_id`, `choco_id`, `match`, `processes`, `stage`.
- **UI/Advisory fields preserved**: `command`, `official_url`.
- **Package selection decisions**:
  - `acrobat_reader_dc`: Set `winget_id=Adobe.Acrobat.Reader.32-bit` and command to match, preserving compatibility with lab machines with note about 64-bit upgrade.
  - `python`, `nodejs`, `.net`, `.net_core`, `asp.net_core`: Retain `action=replace` or `action=remove` with execution matching patterns and winget IDs for modern LTS versions.

```csv
software_name,app,action,winget_id,choco_id,command,official_url,match,processes,stage,note
firefox,Mozilla Firefox,upgrade,Mozilla.Firefox,firefox,winget upgrade --id Mozilla.Firefox --exact,https://www.mozilla.org/firefox/new/,Mozilla Firefox*,firefox,1,Biggest single source of findings; updates browser in place
acrobat_reader_dc,Adobe Acrobat Reader,upgrade,Adobe.Acrobat.Reader.32-bit,adobereader,winget upgrade --id Adobe.Acrobat.Reader.32-bit --exact,https://get.adobe.com/reader/,Adobe Acrobat*,AcroRd32;Acrobat;AdobeCollabSync;RdrCEF,1,Lab machines use 32-bit Reader DC; large download; can also update via Help > Check for updates
thunderbird,Mozilla Thunderbird,upgrade,Mozilla.Thunderbird,thunderbird,winget upgrade --id Mozilla.Thunderbird --exact,https://www.thunderbird.net/,Mozilla Thunderbird*,thunderbird,1,Updates Thunderbird mail client to current release
winrar,WinRAR,upgrade,RARLab.WinRAR,winrar,winget upgrade --id RARLab.WinRAR --exact,https://www.win-rar.com/download.html,WinRAR*,WinRAR;Rar;UnRAR,1,Critical vulnerability remediation (CVE-2025-8088)
7-zip,7-Zip,upgrade,7zip.7zip,7zip,winget upgrade --id 7zip.7zip --exact,https://www.7-zip.org/download.html,7-Zip*,7zFM;7zG;7z,1,Updates 7-Zip archiver to current release
notepad++,Notepad++,upgrade,Notepad++.Notepad++,notepadplusplus,winget upgrade --id Notepad++.Notepad++ --exact,https://notepad-plus-plus.org/downloads/,Notepad++*,notepad++,1,Updates Notepad++ editor to current release
python,Python,remove,,,winget install --id Python.Python.3.14 --exact,https://www.python.org/downloads/windows/,Python {ver2}.*,python;pythonw,2,End-of-life versions must be uninstalled (Settings > Apps); install Python 3.14 if needed
nodejs,Node.js,remove,OpenJS.NodeJS.LTS,,winget upgrade --id OpenJS.NodeJS.LTS --exact,https://nodejs.org/en/download,Node.js*,node,2,Node.js 16 is end-of-life; remove or migrate to supported OpenJS.NodeJS.LTS
powershell,PowerShell 7,upgrade,Microsoft.PowerShell,powershell-core,winget upgrade --id Microsoft.PowerShell --exact,https://aka.ms/powershell-release?tag=stable,PowerShell 7*,pwsh,2,PowerShell 7.0/7.1 are end-of-life; updates pwsh to current 7.x (built-in Windows PowerShell 5.1 unaffected)
visual_studio_code,Visual Studio Code,upgrade,Microsoft.VisualStudioCode,vscode,winget upgrade --id Microsoft.VisualStudioCode --exact,https://code.visualstudio.com/download,Microsoft Visual Studio Code*,Code,3,Updates VS Code to latest release; can also update via Help > Check for Updates
meetings,Zoom Workplace,upgrade,Zoom.Zoom,zoom,winget upgrade --id Zoom.Zoom --exact,https://zoom.us/download,Zoom*,Zoom,3,Updates Zoom client and replaces internal bundled OpenSSL copy
wireshark,Wireshark,upgrade,WiresharkFoundation.Wireshark,wireshark,winget upgrade --id WiresharkFoundation.Wireshark --exact,https://www.wireshark.org/download.html,Wireshark*,Wireshark;dumpcap,3,Updates Wireshark packet analyzer to current release
gimp,GIMP,replace,GIMP.GIMP.3,gimp,winget install --id GIMP.GIMP.3 --exact,https://www.gimp.org/downloads/,GIMP 2*,gimp-2.10;gimp,3,GIMP 3 installs next to GIMP 2; uninstall old GIMP 2.10 versions in Settings > Apps
git,Git for Windows,upgrade,Git.Git,git,winget upgrade --id Git.Git --exact,https://git-scm.com/download/win,Git*,git;bash,3,Updates Git for Windows and replaces bundled OpenSSL copy
vlc_media_player,VLC media player,upgrade,VideoLAN.VLC,vlc,winget upgrade --id VideoLAN.VLC --exact,https://www.videolan.org/vlc/,VLC media player*,vlc,3,Updates VLC media player to current release
libreoffice,LibreOffice,upgrade,TheDocumentFoundation.LibreOffice,libreoffice-fresh,winget upgrade --id TheDocumentFoundation.LibreOffice --exact,https://www.libreoffice.org/download/,LibreOffice*,soffice;soffice.bin,3,Updates LibreOffice and replaces internal bundled Python and OpenSSL copies
putty,PuTTY,upgrade,PuTTY.PuTTY,putty,winget upgrade --id PuTTY.PuTTY --exact,https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html,PuTTY*,putty;pageant,3,Updates PuTTY SSH client to current release
openssl,OpenSSL (built into other apps),none,,,,,https://www.openssl.org/,,,4,Component inside host apps (Acrobat, GIMP, Git, LibreOffice, Zoom); update host applications to remediate
edge_chromium-based,Microsoft Edge,upgrade,Microsoft.Edge,microsoft-edge,winget upgrade --id Microsoft.Edge --exact,https://www.microsoft.com/edge,Microsoft Edge,msedge,3,Edge updates automatically when active; command forces update immediately (browser closes)
.net,.NET,remove,Microsoft.DotNet.Runtime.8,,winget install --id Microsoft.DotNet.Runtime.8 --exact,https://dotnet.microsoft.com/download/dotnet/8.0,Microsoft * Runtime - {ver2}.*,dotnet,2,.NET 5 and 6 are end-of-life; uninstall obsolete runtimes; install .NET 8 only if required
.net_core,.NET Core,remove,Microsoft.DotNet.Runtime.8,,winget install --id Microsoft.DotNet.Runtime.8 --exact,https://dotnet.microsoft.com/download/dotnet/8.0,Microsoft * Runtime - {ver2}.*,dotnet,2,.NET Core 2.1 and 3.1 are end-of-life; uninstall obsolete runtimes; install .NET 8 only if required
asp.net_core,ASP.NET Core,remove,Microsoft.DotNet.AspNetCore.8,,winget install --id Microsoft.DotNet.AspNetCore.8 --exact,https://dotnet.microsoft.com/download/dotnet/8.0,Microsoft ASP.NET Core {ver2}.*,dotnet,2,ASP.NET Core 3.1 and 5.0 are end-of-life; uninstall obsolete runtimes; install ASP.NET Core 8 if required
```

---

## Part 2: Configuration Setting Fix Catalog (`setting_fix_catalog.csv`)

### 1. Which Code Reads Each File

- **Threat Intel Agent (`agents/threat_intel/config/setting_fix_catalog.csv`)**:
  - Read by `agents/threat_intel/src/threat_intel/fix/plan.py` in `load_setting_catalog()`.
  - Used by Fix Centre engine to validate and generate safe, parameter-driven fixes.
  - Requires: `config_id` (`scid-XXXX`), `name`, `kind` (`asr`, `defender`, `registry`), `target` (rule GUID, Defender preference key, or `HKLM:\Path|KeyName`), integer `value`, and `note`.

- **Vulnerability Agent (`agents/vulnerability/config/setting_fix_catalog.csv`)**:
  - Read by `agents/vulnerability/src/vulnerability/ai/fixes.py` in `load_setting_catalog()`.
  - Used to populate setting remediation guidance cards and advice in the dashboard.
  - Requires: `config_name` (matching Microsoft Defender recommendation name), full PowerShell `command`, and guidance `note`.

---

### 2. Schema Comparison

| Threat Intel Column | Vulnerability Column | Notes |
|---|---|---|
| `config_id` | *(none)* | Microsoft Defender SCID identifier (e.g., `scid-2513`), used as primary key in Threat Intel. |
| `name` | `config_name` | Name of the configuration recommendation (e.g., `Turn on PUA protection in block mode`). Used as primary key in Vulnerability Agent. |
| `kind` | *(none)* | Categorization (`asr`, `defender`, `registry`). |
| `target` | *(none)* | Structured target path/GUID/preference name. |
| `value` | *(none)* | Structured numeric value. |
| *(none)* | `command` | Complete PowerShell command string. |
| `note` | `note` | Guidance note. Threat Intel notes are concise; Vulnerability notes detail rollout considerations (AuditMode, impact). |

---

### 3. Rows Only in One File

- **Threat Intel Agent Only (0 rows)**:
  - All 32 setting rows in Threat Intel Agent exist in Vulnerability Agent with identical names.
- **Vulnerability Agent Only (32 rows)**:
  1. `Disable SMBv1 server`
  2. `Disable SMBv1 client driver`
  3. `Disable 'WDigest Authentication'`
  4. `Disable Remote Registry Service on Windows`
  5. `Disable 'Insecure guest logons' in SMB`
  6. `Disable the built-in Guest account`
  7. `Block executable files from running unless they meet a prevalence, age, or trusted list criterion`
  8. `Block execution of potentially obfuscated scripts`
  9. `Block process creations originating from PSExec and WMI commands`
  10. `Block use of copied or impersonated system tools`
  11. `Use advanced protection against ransomware`
  12. `Block credential stealing from the Windows local security authority subsystem`
  13. `Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'`
  14. `Disable the local storage of passwords and credentials`
  15. `Set 'Interactive logon: Machine inactivity limit' to '1-900 seconds'`
  16. `Enable 'Apply UAC restrictions to local accounts on network logons'`
  17. `Enable 'Microsoft network client: Digitally sign communications (always)'`
  18. `Set user authentication for remote connections by using Network Level Authentication to 'Enabled'`
  19. `Disable the built-in Administrator account` (advisory only)
  20. `Ensure LAPS is enabled on every endpoint and server` (central policy advisory)
  21. `Resume BitLocker protection on all drives` (advisory only)
  22. `Fix unquoted service path for Windows services` (advisory only)
  23. `Set 'Minimum password length' to '14 or more characters'`
  24. `Set 'Maximum password age' to '60 or fewer days, but not 0'`
  25. `Set 'Minimum password age' to '1 or more day(s)'`
  26. `Set 'Enforce password history' to '24 or more password(s)'`
  27. `Set 'Account lockout threshold' to 1-10 invalid login attempts`
  28. `Set 'Account lockout duration' to 15 minutes or more`
  29. `Set 'Reset account lockout counter after' to 15 minutes or more`
  30. `Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile`
  31. `Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile`
  32. `Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile`

*Reason*: Vulnerability Agent audits all CIS/Defender recommendations across the enterprise, including OS services, network shares, account lockouts, and firewalls. Threat Intel Agent originally included only settings covered by the lab automated fix engine.

---

### 4. Rows in Both with Different Values

For the 32 shared settings:
1. **Attack Surface Reduction (ASR) Rules (12 rules)**:
   - **Threat Intel**: sets `value=1` (Enabled / Block mode). Note: `Attack-protection rule in block mode`.
   - **Vulnerability**: generates `Add-MpPreference ... -AttackSurfaceReductionRules_Actions AuditMode`. Note: `ASR rule: start in AuditMode for about a week then use Enabled (block)`.
   - **Difference**: Threat Intel configures direct blocking for lab verification; Vulnerability advocates safe progressive deployment via AuditMode first.

2. **Controlled Folder Access (`scid-2021`)**:
   - **Threat Intel**: `target=EnableControlledFolderAccess`, `value=2` (Audit mode). Note: `Audit mode: only logs (blocking could stop business apps saving files)`.
   - **Vulnerability**: `Set-MpPreference -EnableControlledFolderAccess AuditMode`. Note: `Audit mode only logs; switch to Enabled after checking no business app is blocked`.
   - **Difference**: Both choose AuditMode; Threat Intel provides structured properties while Vulnerability provides the command.

3. **Registry Settings (15 rules)**:
   - **Threat Intel**: Structured `HKLM:\Path|KeyName` and numeric value.
   - **Vulnerability**: Full PowerShell script with existence check: `if (-not (Test-Path '...')) { New-Item ... }; Set-ItemProperty ...`.

---

### 5. Proposed Merged `setting_fix_catalog.csv`

The proposed merged schema unifies both access patterns:
`config_id,config_name,kind,target,value,command,note`

- `config_id`: Defender SCID identifier (`scid-XXXX`). For Vulnerability rows without a legacy SCID, standard Defender SCIDs or derived identifiers are populated.
- `config_name`: Exact recommendation name matching Defender findings.
- `kind`: `asr`, `defender`, `registry`, `feature`, `service`, `account`, `firewall`, `advisory`.
- `target`: Structured target identifier for automated runner validation.
- `value`: Execution parameter (integer or Audit/Block state).
- `command`: Complete, safe PowerShell command for UI display or automated execution.
- `note`: Guidance explaining business impact, prerequisite checks, and deployment staging.

```csv
config_id,config_name,kind,target,value,command,note
scid-2513,Block Adobe Reader from creating child processes,asr,7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c,1,Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode; audit mode recommended in production before blocking
scid-2504,Block JavaScript or VBScript from launching downloaded executable content,asr,d3e037e1-3eb8-44c8-a917-57927947596d,1,Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2502,Block Office applications from creating executable content,asr,3b576869-a4ec-4529-8536-b80a7769e899,1,Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2503,Block Office applications from injecting code into other processes,asr,75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84,1,Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2512,Block Office communication application from creating child processes,asr,26190899-1602-49e8-8b27-eb1d0a1ce869,1,Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2506,Block Win32 API calls from Office macros,asr,92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b,1,Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2515,Block abuse of exploited vulnerable signed drivers,asr,56a863a9-875e-4185-98a7-b882c64b5ce5,1,Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2501,Block all Office applications from creating child processes,asr,d4f940ab-401b-4efc-aadc-ad5f3c50688a,1,Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2500,Block executable content from email client and webmail,asr,be9ba2d9-53ea-4cdc-84e5-9b1eeee46550,1,Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2514,Block persistence through WMI event subscription,asr,e6db77e5-3df2-4cf1-b95a-636979351e5b,1,Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2518,Block rebooting machine in Safe Mode,asr,33ddedf1-c6e0-47cb-833e-de6133960387,1,Add-MpPreference -AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2511,Block untrusted and unsigned processes that run from USB,asr,b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4,1,Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled,Attack-protection rule in block mode
scid-2505,"Block executable files from running unless they meet a prevalence, age, or trusted list criterion",asr,01443614-cd74-433a-b99e-2ecdc07bfc25,2,Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode,Needs cloud-delivered protection; start in AuditMode for about a week then use Enabled
scid-2507,Block execution of potentially obfuscated scripts,asr,5beb7efe-fd9a-4556-801d-275e5ffc04cc,2,Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions AuditMode,ASR rule: start in AuditMode for about a week then use Enabled
scid-2508,Block process creations originating from PSExec and WMI commands,asr,d1e49aac-8f56-4280-b9ba-993a6d77406c,2,Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions AuditMode,Do NOT use with Configuration Manager (relies on WMI); start in AuditMode
scid-2509,Block use of copied or impersonated system tools,asr,c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb,2,Add-MpPreference -AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions AuditMode,ASR rule: start in AuditMode for about a week then use Enabled
scid-2510,Use advanced protection against ransomware,asr,c1db55ab-c21a-4637-bb3f-a12568109d35,2,Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions AuditMode,Needs cloud-delivered protection; start in AuditMode for about a week then use Enabled
scid-2516,Block credential stealing from the Windows local security authority subsystem,asr,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,1,Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled,Not needed if LSA protection or Credential Guard is active
scid-90,Enable Microsoft Defender Antivirus email scanning,defender,DisableEmailScanning,0,Set-MpPreference -DisableEmailScanning $false,Enables Defender Antivirus email attachment and body scanning
scid-2013,Turn on PUA protection in block mode,defender,PUAProtection,1,Set-MpPreference -PUAProtection Enabled,Blocks potentially unwanted applications (adware and bundled unwanted software)
scid-89,Enable scanning of removable drives during a full scan,defender,DisableRemovableDriveScanning,0,Set-MpPreference -DisableRemovableDriveScanning $false,Scans USB drives during full antivirus scans
scid-96,Enable 'Network Protection',defender,EnableNetworkProtection,1,Set-MpPreference -EnableNetworkProtection Enabled,Blocks outbound connections to dangerous phishing/malware domains
scid-2021,Set controlled folder access to enabled or audit mode,defender,EnableControlledFolderAccess,2,Set-MpPreference -EnableControlledFolderAccess AuditMode,Audit mode only logs; prevents ransomware overwriting protected folders
scid-69,Disable 'Autoplay' for all drives,registry,HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun,255,"if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) { New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord",Disables automatic execution of untrusted media drives
scid-70,Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands',registry,HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoAutorun,1,"if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) { New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1 -Type DWord",Prevents autorun INF execution on insertion
scid-67,Disable 'Autoplay for non-volume devices',registry,HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer|NoAutoplayfornonVolume,1,"if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutoplayfornonVolume -Value 1 -Type DWord",Disables MTP/PTP device autoplay
scid-87,Disable Solicited Remote Assistance,registry,HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fAllowToGetHelp,0,"if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fAllowToGetHelp -Value 0 -Type DWord",Disables Windows Remote Assistance (RDP unaffected)
scid-73,Disable 'Allow Basic authentication' for WinRM Client,registry,HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client|AllowBasic,0,"if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name AllowBasic -Value 0 -Type DWord",Prevents unencrypted cleartext credentials across WinRM
scid-74,Disable 'Allow Basic authentication' for WinRM Service,registry,HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service|AllowBasic,0,"if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowBasic -Value 0 -Type DWord",Prevents WinRM service accepting basic auth
scid-29,Disable 'Enumerate administrator accounts on elevation',registry,HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI|EnumerateAdministrators,0,"if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI')) { New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name EnumerateAdministrators -Value 0 -Type DWord",Hides administrator usernames on UAC elevation prompts
scid-88,Disable Anonymous enumeration of shares,registry,HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymous,1,Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1 -Type DWord,Restricts anonymous SMB network enumeration
scid-82,Disable IP source routing,registry,HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|DisableIPSourceRouting,2,Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name DisableIPSourceRouting -Value 2 -Type DWord,Blocks source-routed IPv4 packets
scid-81,Set IPv6 source routing to highest protection,registry,HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters|DisableIPSourceRouting,2,Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisableIPSourceRouting -Value 2 -Type DWord,Blocks source-routed IPv6 packets
scid-58,Disable 'Installation and configuration of Network Bridge on your DNS domain network',registry,HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections|NC_AllowNetBridge_NLA,0,"if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name NC_AllowNetBridge_NLA -Value 0 -Type DWord",Prevents unauthorized bridging between corporate network adapters
scid-60,Prohibit use of Internet Connection Sharing on your DNS domain network,registry,HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections|NC_ShowSharedAccessUI,0,"if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name NC_ShowSharedAccessUI -Value 0 -Type DWord",Disables ICS software routing
scid-59,Enable 'Require domain users to elevate when setting a network's location',registry,HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections|NC_StdDomainUserSetLocation,1,"if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name NC_StdDomainUserSetLocation -Value 1 -Type DWord",Requires administrator permission to change network location profiles
scid-76,Disable JavaScript on Adobe Reader DC,registry,HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown|bDisableJavaScript,1,"if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' -Name bDisableJavaScript -Value 1 -Type DWord",PDF forms that use JavaScript stop working
scid-27,Set User Account Control (UAC) to automatically deny elevation requests,registry,HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorUser,0,Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Value 0 -Type DWord,Standard users cannot elevate by typing admin credentials; help desk must deploy software
scid-40,Disable SMBv1 server,feature,SMB1Protocol-Server,0,Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart,Legacy protocol vulnerability; test that no legacy storage or printer relies on SMBv1
scid-41,Disable SMBv1 client driver,feature,SMB1Protocol-Client,0,Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart,Legacy protocol vulnerability; test that no legacy storage or printer relies on SMBv1
scid-42,Disable 'WDigest Authentication',registry,HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest|UseLogonCredential,0,Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord,Takes effect at next sign-in; prevents plaintext passwords stored in LSASS
scid-43,Disable Remote Registry Service on Windows,service,RemoteRegistry,Disabled,Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled,Prevents remote registry modification over RPC
scid-44,Disable 'Insecure guest logons' in SMB,registry,HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|AllowInsecureGuestAuth,0,Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -Value 0 -Type DWord,Disables unauthenticated guest sessions to rogue SMB servers
scid-45,Disable the built-in Guest account,account,Guest,0,Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Disable-LocalUser,Disables local guest account
scid-46,"Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'",registry,HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel,5,Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord,Prevents NTLMv1 authentication responses; verify legacy NAS compatibility
scid-47,Disable the local storage of passwords and credentials,registry,HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|DisableDomainCreds,1,Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DisableDomainCreds -Value 1 -Type DWord,Users cannot save domain passwords in Credential Manager
scid-48,Set 'Interactive logon: Machine inactivity limit' to '1-900 seconds',registry,HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|InactivityTimeoutSecs,900,Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900 -Type DWord,Locks screen after 15 minutes of inactivity
scid-49,Enable 'Apply UAC restrictions to local accounts on network logons',registry,HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|LocalAccountTokenFilterPolicy,0,Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 0 -Type DWord,Restricts local administrator tokens on remote network access (blocks lateral movement)
scid-50,Enable 'Microsoft network client: Digitally sign communications (always)',registry,HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|RequireSecuritySignature,1,Set-SmbClientConfiguration -RequireSecuritySignature $true -Force,Enforces SMB packet signing to prevent man-in-the-middle attacks
scid-51,Set user authentication for remote connections by using Network Level Authentication to 'Enabled',registry,HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication,1,Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord,Enforces NLA prior to RDP session negotiation
scid-52,Disable the built-in Administrator account,advisory,,,On Azure VMs the account you signed up with IS the built-in Administrator (renamed): create and test another admin account first or you lock yourself out,Manual step: verify replacement admin exists before disabling
scid-53,Ensure LAPS is enabled on every endpoint and server,advisory,,,Done centrally (Intune or Group Policy + Entra ID / Active Directory backup) - not with one command on one PC,Requires domain or Intune LAPS architecture deployment
scid-54,Resume BitLocker protection on all drives,advisory,,,BitLocker needs a recovery-key plan first (Intune or Active Directory backup); on Azure VMs use Azure Disk Encryption or encryption at host instead,Verify recovery key escrow before enabling
scid-55,Fix unquoted service path for Windows services,advisory,,,Inspect service binary paths and add quotes around executable paths containing spaces,Inspect service binary paths; tamper protection blocks Defender services
scid-56,Set 'Minimum password length' to '14 or more characters',account,minpwlen,14,net accounts /minpwlen:14,Local accounts only; domain/Intune policies override this setting
scid-57,"Set 'Maximum password age' to '60 or fewer days, but not 0'",account,maxpwage,60,net accounts /maxpwage:60,Local accounts only; domain/Intune policies override this setting
scid-61,Set 'Minimum password age' to '1 or more day(s)',account,minpwage,1,net accounts /minpwage:1,Local accounts only; domain/Intune policies override this setting
scid-62,Set 'Enforce password history' to '24 or more password(s)',account,uniquepw,24,net accounts /uniquepw:24,Local accounts only; domain/Intune policies override this setting
scid-63,Set 'Account lockout threshold' to 1-10 invalid login attempts,account,lockoutthreshold,10,net accounts /lockoutthreshold:10,Locks accounts after 10 failed sign-in attempts
scid-64,Set 'Account lockout duration' to 15 minutes or more,account,lockoutduration,15,net accounts /lockoutduration:15,Specifies lockout duration in minutes
scid-65,Set 'Reset account lockout counter after' to 15 minutes or more,account,lockoutwindow,15,net accounts /lockoutwindow:15,Specifies lockout reset window in minutes
scid-66,Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile,firewall,Domain,False,Set-NetFirewallProfile -Profile Domain -NotifyOnListen False,Suppresses user notification popups on blocked inbound connections
scid-68,Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile,firewall,Private,False,Set-NetFirewallProfile -Profile Private -NotifyOnListen False,Suppresses user notification popups on blocked inbound connections
scid-71,Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile,firewall,Public,False,Set-NetFirewallProfile -Profile Public -NotifyOnListen False,Suppresses user notification popups on blocked inbound connections
```
