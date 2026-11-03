# Remediations the agent does not perform

The Remediation Agent (the fix engine in the Threat Intel Agent) changes a device only through moves that a person has
vetted in advance. This document lists what it leaves to IT, why, and how each item appears in the portal.

Snapshot of 3 November 2026 (devices opca-wks-01 and opcc-wks-01). The live list is always
**Remediation › Security configuration › Remediation: Manual action required** and the **No automated fix** status on
the Updates & upgrades cards.

## Why some remediations stay manual

The agent runs commands on servers and workstations with administrative rights. It runs only these moves:

| Move | Source of the exact command |
| --- | --- |
| Install a newer version with winget or Chocolatey | the package ID in `config/fix_catalog.csv` |
| Uninstall a version | the uninstall name pattern in `config/fix_catalog.csv` |
| Change a Windows or Defender setting | the rule, option or registry value in `config/setting_fix_catalog.csv` |
| Defender update, quick scan, full scan and threat removal | built in (attack and indicator responses) |

The AI reads the evidence and writes the cause and manual steps. It never decides which command runs. A package ID or
uninstall pattern that the AI made up could install the wrong software or remove the wrong application on a production
device, so an app or setting without a vetted row is not automated. The catalogs are the allow-list. They are not
a gap in the agent: adding a row after review is how a new item becomes automatable.

## How the portal shows it

| Status on the card | Meaning | Action on the card |
| --- | --- | --- |
| **No automated fix** | No vetted move exists. The agent has prepared the steps. | **Hand over to IT** |
| **With IT for manual fix** | Handed over. Nobody has run it yet. | None. Open **Details**, follow the steps, select **Mark as fixed manually**. |
| **Agent could not remediate** | The agent ran its allowed moves and none of them removed the finding. | None. Open **Details** to see what it tried, the evidence and the steps, then select **Mark as fixed manually**. |
| **Failed** / **Still listed by Defender** | The run did not finish, or Defender still lists the finding afterwards. | **Retry** |

**Approve** appears only where the agent can run the fix itself. A manually fixed item shows as Pending verification
until Microsoft Defender's next scan confirms it, and then shows as Verified. The Remediation history has separate
views for **Agent could not remediate** and **With IT for manual fix**.

## Software (Updates & upgrades)

| Software | Devices | Why it is manual | What IT does |
| --- | --- | --- | --- |
| OpenSSL (built into other apps) | opca-wks-01, opcc-wks-01 | OpenSSL is bundled inside other vendors' applications and Microsoft components. It is not an installed package that can be updated on its own. The agent tried and could not remediate it on opca-wks-01. | In Defender Vulnerability Management, open the software inventory, list the files that carry the OpenSSL DLLs (libssl, libcrypto), and update each parent application to the version that ships a fixed OpenSSL. |
| PHP 8.1 | opcc-wks-01 | No vetted package. A PHP upgrade can break the web applications that run on it. | Upgrade to a supported PHP branch (8.3 or later) after the application owner has tested it, or remove PHP if it is not used. |
| log4j | opcc-wks-01 | A Java library inside applications, not a package. | Find the owning application (from the JAR paths in the Defender evidence) and apply the vendor's update. Where no update exists, set `log4j2.formatMsgNoLookups=true` or remove `JndiLookup.class`. |

Defender "No security update available" items also stay manual until the vendor releases a fix. Apply compensating
controls in the meantime.

## Security configuration

Defender lists 38 settings that are weaker than the Microsoft baseline and have no vetted automated change. They must be
set centrally through **Group Policy or Intune**. A per-device change would be overwritten by policy, or it could
lock users out or break line-of-business applications.

**Accounts and passwords**: domain password and lockout policy.
- Account lockout duration, 15 minutes or more
- Reset account lockout counter after 15 minutes or more
- Enforce password history, 24 or more
- Maximum password age, 60 days or fewer (not 0)
- Minimum password age, 1 day or more
- Minimum password length, 14 or more
- Disable the built-in Administrator account
- Disable the local storage of passwords and credentials
- Ensure LAPS is enabled on every endpoint and server

**Authentication and network protocols**: test application compatibility first.
- Disable NTLM authentication for Windows workstations
- LAN Manager authentication level: Send NTLMv2 response only, refuse LM and NTLM
- Microsoft network client: digitally sign communications (always)
- Require LDAP client signing
- Encrypt LDAP client traffic
- Disable SMBv1 client driver (opca-wks-01)
- Network Level Authentication for remote connections
- Disable WDigest authentication (opca-wks-01)

**Device hardening**: some of these need a restart or hardware support.
- Enable Memory Integrity (HVCI)
- Turn on Microsoft Defender Credential Guard
- Resume BitLocker protection on all drives
- Require additional authentication at startup
- Minimum PIN length for startup, 6 or more
- Apply UAC restrictions to local accounts on network logons
- Interactive logon: machine inactivity limit, 1 to 900 seconds
- Fix unquoted service path for Windows services (opca-wks-01): the service owner must correct the service's image path.

**Attack surface reduction rules**: deploy in audit mode first, review the ASR events in Advanced Hunting, then
switch to block mode.
- Block executable files unless they meet a prevalence, age or trusted-list criterion
- Block execution of potentially obfuscated scripts
- Block process creations from PSExec and WMI commands
- Block use of copied or impersonated system tools
- Use advanced protection against ransomware
- Block outbound connections from mshta.exe

**Microsoft Defender Firewall**: Domain, Private and Public profiles.
- Turn off notifications when programs are blocked (three profiles)
- Turn off merging of local firewall rules and connection rules with Group Policy (Public profile)
- Block file transfer over RDP

**Applications**
- Disable Flash in Adobe Reader DC (opca-wks-01)

## Making an item automatable

1. A security engineer reviews the exact command (package ID, uninstall pattern, ASR rule ID, Defender option or
   registry value) and tests it on a lab device.
2. Add one row to `agents/threat_intel/config/fix_catalog.csv` (software) or `setting_fix_catalog.csv` (settings).
   The fix engine validates every row when it starts and rejects malformed IDs and paths.
3. On the next run, the card shows **Approve** in place of **Hand over to IT**.
