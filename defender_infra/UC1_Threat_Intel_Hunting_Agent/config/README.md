# config/: every setting explained

All files are plain text (CSV or `.kql`); edit them with Notepad or LibreOffice. Changes apply on the next run. Nothing here is secret. Keys go only in `..\.env`.

| File | What it controls | Change it when… |
|---|---|---|
| `settings.example.env` | Template for `..\.env`: Defender login (tenant, client ID, secret), Gemini key/model/speed, feed keys, optional Teams webhook, tuning values. **The real `.env` is in the UC1 folder root, and only you type the keys there.** | Setting up a new machine |
| `feeds.csv` | Which feeds run (`enabled` yes/no): `attack`, `kev`, `nvd`, `ncsc_nl`, `cert_eu`, `msrc`, `abusech`, `otx`, `lab_test` | A feed is broken or unwanted, or you add OTX |
| `risk_policy.csv` | The **risk rules**: points per signal (CISA KEV 35, ransomware 15, EPSS, CVSS, public exploit 10, NCSC-NL [H/H] 15, exposed 15, possible match 8, fresh IOCs 20), rating thresholds (Critical ≥ 70, High ≥ 50, Medium ≥ 30), caps (49 when not on our devices, 69 for a possible product match) and the hunt-hit score (95). | The security team wants different priorities. Every threat's "why" line shows which rules applied. |
| `opco_mapping.csv` | Which business unit (OpCo) each Defender device belongs to. `match_type` = `rbac_group` (Defender device group), `tag` (device tag, e.g. `OpCo A`) or `name_pattern` (e.g. `opcc-*`). Tried in that order; unmatched = "Unassigned". Copied from UC3. | New devices or OpCos |
| `ioc_allowlist.csv` | Big legitimate shared sites (GitHub, Google, Dropbox, OneDrive, Microsoft, AWS, Discord CDN, Cloudflare Workers…) that are **never treated as bad domains as a whole**. A bad file hosted there is still hunted by its exact URL. Added after the GitHub false alarm of 30 Sep. | A hit turns out to be a well-known legitimate site |
| `lab_test_iocs.csv` | Harmless **TEST** indicators: the `example.com` domain and the EICAR test-file fingerprint. Always shown as [TEST]. | Never needed; remove the rows to stop TEST hunting |
| `metrics_assumptions.csv` | **Assumptions** for "manual effort": 120 min per threat, 45 min per hunt, 240 min per report. Used only for the hours-saved estimate, clearly labelled as an assumption. | The team gives real figures |
| `tech_watchlist.example.csv` | **Example only, not active.** Products Defender can't see (firewalls, VPN appliances such as Citrix NetScaler, FortiGate, PAN-OS). To use it, copy it to `tech_watchlist.csv` with the client's real list; matches are shown as "watch-list, not verified". | A client provides its product list |
| `kql_templates\*.kql` | The **hunt query library** (Defender KQL). Header lines give name, kind (`ioc`/`behaviour`/`manual`), IOC type and ATT&CK technique. Placeholders: `{{LOOKBACK}}` (days), `{{VALUES}}` (the indicators, safely quoted by the code). | Adding a new behaviour hunt (copy an existing `bh_*.kql`) |

## The hunt templates

| File | Kind | Looks for |
|---|---|---|
| `ioc_ip.kql` | IOC | Network connections to bad IP addresses |
| `ioc_domain.kql` | IOC | Connections to bad domains |
| `ioc_url.kql` | IOC | Visits to or downloads from bad web links |
| `ioc_hash.kql` | IOC | Files or programs with a bad fingerprint (SHA-256/SHA-1/MD5) |
| `bh_encoded_powershell.kql` | Behaviour (T1059.001) | PowerShell started with a hidden, encoded command |
| `bh_lolbins.kql` | Behaviour (T1218) | Windows tools (mshta, regsvr32, rundll32, certutil, bitsadmin) misused to download or run code |
| `bh_lsass_access.kql` | Behaviour (T1003.001) | Unusual programs reading the memory where Windows keeps passwords (LSASS) |
| `bh_scheduled_task.kql` | Behaviour (T1053.005) | New scheduled tasks created from the command line (a way to survive a restart) |
| `bh_av_detection.kql` | Behaviour (T1204.002) | Malware detections by Defender antivirus |
| `cve_exposure.kql` | Manual | Which devices have given CVEs (for analysts; not run automatically) |

Every query, template or AI-drafted, passes the validator (`src\uc1\hunting\validator.py`) before it runs: allowed tables only, a time filter, a row limit, no external data.

## `fix_catalog.csv`: what the fix loop may do (allow-list)

One row per app name as Defender reports it (`software_name`). `action` is `upgrade` (winget update), `remove` (uninstall every
entry matching `match`, e.g. end-of-life Python; `{ver2}` = the first two parts of the vulnerable version), `replace` (remove the
old version, then install `winget_id`) or `none` (nothing to run). `choco_id` is the Chocolatey fallback, `processes` are closed
first (`;`-separated), and `stage` sets urgency (1 urgent, 2 end-of-life, 3 other; anything on CISA KEV is always stage 1).
Only letters, digits and `. + _ - ( ) * { }` are accepted, and a row with anything else stops the plan, so no command can be injected.
Apps not listed show as "No action" in the Fix Centre.
