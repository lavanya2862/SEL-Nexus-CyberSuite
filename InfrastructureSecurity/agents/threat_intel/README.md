# Threat Intel Agent: AI Threat Intelligence & Threat Hunting Agent

An AI agent that **collects** public threat intelligence, **understands** it with an LLM: Azure AI Foundry or Google Gemini (every claim checked by code), **checks** it against Microsoft Defender for Endpoint ("does this affect us?"), **hunts** for attack clues and attacker behaviour, **connects** findings to computers, business units, users and Defender alerts, **rates** the risk with fixed, explainable rules, and **reports** through a Word/PDF report, alerts, key metrics and the data behind the Unified Cyber Portal's Threats and Attack detection pages. Its **fix engine** can update or remove vulnerable apps on lab computers after a person approves on the portal's Fix page.

## How one run works

```
Threat feeds ─► Gemini analysis (checked by code) ─► Defender inventory ─► exposure + risk score
   ─► hunts in Defender (validated KQL) ─► connect to devices / users / alerts ─► report, portal data, alerts
   ─► fix: propose the fixes that are new in this run (a person decides on each)
```

Both runs (`run` and `attack-check`) end with a **Fix** step that rebuilds the fix plan and lists the fixes that are new in that run: app updates and security settings, and for every sign of attack a Defender scan-and-clean of that computer (signature update, quick scan, remove active threats). Nothing runs until a person presses **Fix** (or **Save for later**) on the portal's run page and then **Run fixes**; the portal shows the Fix step as waiting until every new fix has a decision. Isolating a computer is not offered: it needs `Machine.Isolate`, so it stays a job for Defender itself.

Feeds: NVD, EPSS, MITRE ATT&CK, NCSC-NL, CERT-EU, Microsoft MSRC, ThreatFox, URLhaus, MalwareBazaar (+ AlienVault OTX, optional).

## Setup

Requires Python 3.12+ on Windows.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\pip install -e .
copy ..\..\.env.example ..\..\.env    # once, for the whole suite; then fill it in (never commit it)
.\.venv\Scripts\python.exe -m threat_intel check
.\.venv\Scripts\python.exe -m threat_intel live-test
```

What `.env` needs:

| Setting | Where it comes from |
|---|---|
| `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` | An Entra ID app registration with the WindowsDefenderATP application permissions `Machine.Read.All`, `Vulnerability.Read.All`, `AdvancedQuery.Read.All`, `Alert.Read.All` (admin consent granted) |
| `AZURE_FOUNDRY_ENDPOINT`, `AZURE_FOUNDRY_API_KEY`, `AZURE_FOUNDRY_DEPLOYMENT` | Azure AI Foundry model deployment (Foundry portal -> Models + endpoints). When all three are set the agent uses it instead of Gemini; `AI_PROVIDER=gemini` switches back. Reasoning models such as gpt-5 work too (`AZURE_FOUNDRY_REASONING_EFFORT`, default low) |
| `GEMINI_API_KEY` | Free key from Google AI Studio (used when Azure AI Foundry is not set) |
| `GEMINI_API_KEY_2`, `GEMINI_API_KEY_3` … (optional) | Spare Gemini keys: when one key uses up its daily quota the next takes over. Each must be from a different Google Cloud project (keys in one project share its quota) |
| `NVD_API_KEY`, `ABUSECH_AUTH_KEY`, `OTX_API_KEY` | Free keys from NVD, abuse.ch and AlienVault OTX (OTX is optional) |
| Fix loop (optional) | Azure role **Virtual Machine Contributor** on `FIX_RESOURCE_GROUP` (Run Command), and/or `Machine.LiveResponse` + `Library.Manage` (Live Response) |

Without Defender settings the agent still collects and rates public threats, but skips inventory and hunting.

## Commands

```powershell
.\.venv\Scripts\python.exe -m threat_intel serve       # service for the portal: http://127.0.0.1:8700/api (this computer only)
.\.venv\Scripts\python.exe -m threat_intel run         # one full run: collect, inventory, analyse, hunt, report
.\.venv\Scripts\python.exe -m threat_intel summary     # what's in the database
```

`python -m threat_intel --help` lists every command, including the single steps (`collect`, `inventory`, `analyse`, `hunt`, `report`, `dashboard`, `alerts`, `metrics`) and the fix loop (`fix-plan`, `fix-refresh`, `fix-status`, `fix-probe`, `fix-approve`, `fix-run`). `fix-refresh` pulls a fresh inventory first; the Vulnerability Agent's Fix stage calls it.

## What the portal gets

The agent has no web pages of its own: the Unified Cyber Portal is the only user interface.

| Output | Used for |
|---|---|
| `data/dashboard/dashboard_data.json` | The portal's Threats and Attack detection pages: headline numbers, charts, threat explorer, hunts, devices, metrics |
| `data/dashboard/site_data.json` | The portal's threat detail page |
| `data/dashboard/clues.json` | Every clue (IP, domain, web link, file hash) collected |
| `data/reports/` | Word/PDF reports and the spot-check workbook, downloaded from the portal's Reports page |
| `threat_intel serve` on port 8700 | The API the portal calls: run status, **Run now** and the fix engine (`/api/status`, `/api/run`, `/api/fix…`) |

## Folder layout

| Folder | Contents |
|---|---|
| `src/threat_intel/` | The agent: `feeds/`, `inventory.py`, `analyse.py` + `ai/`, `exposure.py`, `scoring.py`, `hunting/`, `correlate.py`, `report.py`, `dashboard.py` (portal data), `site.py` (API for the portal), `fix/` (fix loop), `pipeline.py` |
| `config/` | Editable rules: risk points, feeds on/off, hunt queries, OpCo mapping, IOC allow-list, fix catalogue. See [config/README.md](config/README.md) |
| `data/`, `logs/` | Created at run time: database, raw feed copies, reports, logs (not in git) |

## Safety

- Read-only Defender access for analysis and hunting; every hunt query passes a validator (allowed tables, time filter, row limit).
- The AI never decides alone: its answers are checked against the source data, and risk ratings come from fixed rules.
- Fixes only run on approved items, on the lab VMs (optionally limited with `FIX_DEVICES`), using the allow-list in `config/fix_catalog.csv`. The response to a sign of attack is one fixed action (Defender scan-and-clean), never a command from the AI or from the evidence.
- Lab tests: `scripts\lab\Invoke-UC1LabTest.ps1` (in a lab VM, as administrator) creates 6 harmless signs of attack named UC1LabTest: Run key, Startup-folder file, local user, Windows service, a burst of discovery commands and Microsoft's AMSI test sample. Each has its own hunt in `config\kql_templates`, is reported as a TEST, and the auto-fix's scan-and-clean also removes the leftovers. `-Cleanup` removes them by hand.
- Auto-fix (on by default): at the end of each attack-check run the agent approves and runs every scan-and-clean response nobody has decided on (new and from earlier runs) and the ones not clean yet (they show as approved by "Attack Detection Agent (auto-fix)"). Each one is repeated until Defender lists no active threat: quick scan, then a full scan, then a full scan once more; what is still not clean is tried again on the next run. A person can Defer one to keep it out of auto-fix, or select Auto-fix on any card to run it now. `ATTACK_AUTO_FIX=0` goes back to waiting for a person's approval. Vulnerability and setting fixes run only from a person's Approve or Auto-fix click.
- Secrets live only in `.env`, which is never committed or printed.

## Spec

Attack detection code (`hunting/`, `correlate.py`, `resolve.py`, `attack_report.py`, and `attack_check()` in `pipeline.py`) belongs to the Attack Detection Agent and is specified separately.
The fix engine (`fix/`, `fix_assets/`, and the `fix_plan()` pipeline step) belongs to the shared Fix Centre (`shared/remediation`) and is specified separately.

### Inputs

- **Microsoft Defender for Endpoint APIs**:
  - `GET /api/machines`: Defender Machines API (paginated via `@odata.nextLink`), reads machine identifiers, computer DNS names, OS platforms, OS versions, RBAC device groups, machine tags, health status, and last seen timestamps — read by `inventory.py:pull_devices`.
  - `POST /api/advancedqueries/run`: Defender Advanced Hunting API (read-only KQL execution) — read by `inventory.py:pull`:
    - `DeviceTvmSoftwareInventory`: software vendor, software name, software version installed across devices.
    - `DeviceTvmSoftwareVulnerabilities` (joined with `DeviceTvmSoftwareVulnerabilitiesKB`): CVE IDs, vulnerability severity levels, CVSS scores, exploit availability flags, and recommended security updates.
    - `DeviceTvmSoftwareVulnerabilities | count`: total vulnerability row count check against Defender's 100,000-row query limit (`MAX_HUNT_ROWS` in `api_client.py`).
    - `DeviceTvmSecureConfigurationAssessment` (joined with `DeviceTvmSecureConfigurationAssessmentKB`): non-compliant security configuration checks (`IsApplicable == 1 and IsCompliant == 0`), configuration categories, and impact.
- **Threat Feeds & Intelligence APIs**:
  - MITRE ATT&CK Enterprise STIX JSON (`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`): enterprise attack techniques, tactics, kill-chain phases, and platforms — read by `feeds/attack.py:collect`.
  - NVD (National Vulnerability Database) CVE API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`): CVE descriptions, CVSS v3.1/v4.0/v3.0/v2 metrics and vectors, severity, CPE configurations, and affected product ranges — read incrementally by `feeds/nvd.py:fetch_window` and for specific CVE lookups by `feeds/nvd.py:fetch_cves`.
  - FIRST EPSS API (`https://api.first.org/data/v1/epss`): exploit prediction probability and percentile scores for CVEs — read in batches by `feeds/epss.py:collect`.
  - NCSC-NL Security Advisories RSS (`https://advisories.ncsc.nl/rss/advisories`): security advisories — read by `feeds/advisories.py:collect_rss`.
  - CERT-EU Security Advisories RSS (`https://cert.europa.eu/publications/security-advisories-rss`): security advisories — read by `feeds/advisories.py:collect_rss`.
  - Microsoft MSRC CVRF API (`https://api.msrc.microsoft.com/cvrf/v3.0/updates` and monthly CVRF document URLs): monthly security updates, critical vulnerabilities, and public disclosures — read by `feeds/advisories.py:collect_msrc`.
  - abuse.ch ThreatFox API (`https://threatfox-api.abuse.ch/api/v1/`): recent IOC indicators (IP, domain, URL, hash) — read by `feeds/iocs.py:collect_abusech`.
  - abuse.ch URLhaus API (`https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/`): recent malware distribution URLs and payloads — read by `feeds/iocs.py:collect_abusech`.
  - abuse.ch MalwareBazaar API (`https://mb-api.abuse.ch/api/v1/`): recent malware samples and SHA256 hashes — read by `feeds/iocs.py:collect_abusech`.
  - AlienVault OTX API (`https://otx.alienvault.com/api/v1/pulses/subscribed`): subscribed threat pulses, indicator lists, CVEs, and ATT&CK IDs (optional feed) — read by `feeds/iocs.py:collect_otx`.
- **Configuration & Seed Files**:
  - `config/feeds.csv`: feed enablement flags (`enabled: yes/no`) — read by `feeds/__init__.py:enabled_feeds`.
  - `config/opco_mapping.csv`: operating company mapping rules based on RBAC group, tag, or computer name pattern — read by `inventory.py:pull_devices` and `inventory.py:opco_for`.
  - `config/risk_policy.csv`: scoring weights for CVSS, EPSS, exploit availability, and exposure — read by `config.py:read_policy` and `scoring.py:run`.
  - `config/ioc_allowlist.csv`: trusted multi-tenant domain allow-list — read by `feeds/iocs.py:allowlisted`.
  - `config/lab_test_iocs.csv`: test indicators for pipeline verification — read by `feeds/iocs.py:load_lab_test_iocs`.
  - `config/tech_watchlist.csv`: watchlist of vendors/products not visible in Defender inventory — read by `exposure.py:compute`.
  - `config/metrics_assumptions.csv`: manual effort baseline parameters — read by `metrics.py:compute`.

### Steps

1. **Gather news**:
   - `feeds/__init__.py:collect_all` (invoked via `pipeline.py:Pipeline.collect`): runs all enabled threat feeds (`feeds/attack.py:collect`, `feeds/nvd.py:collect`, `feeds/advisories.py:collect_rss`, `feeds/advisories.py:collect_msrc`, `feeds/iocs.py:collect_abusech`, `feeds/iocs.py:collect_otx`, `feeds/iocs.py:load_lab_test_iocs`), saves raw payloads to `data/raw/<run_id>/` via `feeds/common.py:FeedContext.save_raw`, and populates `threats`, `threat_links`, `iocs`, `cves`, and `attack_techniques` in `store.py:Store`.
   - `inventory.py:pull` (invoked via `pipeline.py:Pipeline.inventory`): calls `inventory.py:pull_devices` to query Defender machines and resolve OpCos via `inventory.py:opco_for`; then executes Advanced Hunting queries against Defender for installed software (`DeviceTvmSoftwareInventory`), vulnerabilities (`DeviceTvmSoftwareVulnerabilities`), and security configurations (`DeviceTvmSecureConfigurationAssessment`), storing results in `devices`, `software`, `device_vulns`, `defender_seen`, and `device_settings`.
   - `derive.py:run` (invoked via `pipeline.py:Pipeline.enrich`): synthesizes new threats for high-severity NVD CVEs (CVSS >= 7) matching installed software products before Defender reports them (`derive.py:relevant_new_cves`), purges repeats (`derive.py:forget_repeats`), and cleans up retired feed data (`derive.py:forget_retired`).
   - `feeds/nvd.py:fetch_cves` (invoked via `pipeline.py:Pipeline.enrich`): fetches complete CVE records for any advisory CVEs missing from `cves`.
   - `feeds/epss.py:collect` (invoked via `pipeline.py:Pipeline.enrich`): queries FIRST EPSS for newly linked and device CVEs (`feeds/epss.py:wanted_cves`) and stores exploit probabilities in `cves`.
   - `exposure.py:products_from_cves` (invoked via `pipeline.py:Pipeline.enrich`): extracts CPE vendor and product names from NVD data and adds them to `threat_links`.
   - `analyse.py:run` (invoked via `pipeline.py:Pipeline.analyse`): retrieves pending threats (`analyse.py:pending`), calls Azure AI Foundry (`ai/azure_client.py:AzureFoundryClient`) or Google Gemini (`ai/gemini_client.py:GeminiClient`) with system prompt `ai/prompts.py:EXTRACT_SYSTEM` and schema `ai/schemas.py:ThreatAnalysis`. Validates facts against source text using `ai/guard.py:check` (dropping unverified products, techniques, CVEs, or IOCs), falls back to rules-based extraction (`analyse.py:rules_only`) if AI is unavailable or unconfigured, and saves structured results via `analyse.py:_save`.
2. **Affects us?**:
   - `exposure.py:defender_first_listed`: gathers the earliest dates Defender or the Vulnerability Agent first identified each CVE on each computer.
   - `exposure.py:compute` (invoked via `pipeline.py:Pipeline.score`): checks each threat against installed software and vulnerabilities. Matches by CVE (leaving out matches where Defender reported the CVE on that device before Threat Intel saw the threat), early matches where Defender does not list the hole yet but installed versions fall in NVD affected ranges (`exposure.py:in_range`), product matches for advisory threats without CVEs (`exposure.py:product_matches`), and watchlist matches (`config/tech_watchlist.csv`). Writes matches to `exposure`.
   - `scoring.py:run` (invoked via `pipeline.py:Pipeline.score`): computes deterministic risk scores (0–100) and qualitative ratings (`Critical`, `High`, `Medium`, `Low`) for every threat via `scoring.py:score_one`, applying weights from `config/risk_policy.csv` based on EPSS, CVSS, exploit availability, and device exposure. Writes ratings to `scores`.
3. **Fix steps**:
   - `fix_advice.py:affected`: gathers all threats with confirmed device exposure (`exposure.match_type = 'cve'`), ordered by risk score.
   - `fix_advice.py:evidence`: compiles threat summaries, CVE details, affected devices, Defender's recommended updates, and source text into evidence context.
   - `fix_advice.py:advise_one`: prompts Azure AI Foundry or Google Gemini using `ai/prompts.py:FIX_SYSTEM` and schema `ai/schemas.py:FixAdvice`.
   - `fix_advice.py:checked`: validates AI-generated remediation steps, dropping any step that references CVEs or version numbers not present in the evidence data.
   - `fix_advice.py:standard`: generates fallback remediation steps from Defender's recommended updates and source advice if AI is unavailable or fewer than 2 checked steps survive.
   - `fix_advice.py:run` (invoked via `pipeline.py:Pipeline.fix_advice`): writes verified remediation instructions and done criteria to `threat_fixes`.
4. **Write report**:
   - `alerts.py:run` (invoked via `pipeline.py:Pipeline.outputs`): evaluates high-risk candidates (`Critical`/`High` risk with active exposure or findings), generates deterministic alert IDs, persists records to `alerts`, appends lines to `data/alerts.jsonl`, and posts alerts to Microsoft Teams if `TEAMS_WEBHOOK_URL` is configured.
   - `report.py:build` (invoked via `pipeline.py:Pipeline.outputs`): extracts run metrics, newly collected threats, exposed devices, AI fix steps, MITRE ATT&CK techniques, defanged warning signs, and alerts via `report.py:gather`. Formats the document using `infra_core.docstyle.Report` and saves `data/reports/Threat_Intel_Report_<stamp>.docx` and `.pdf`, storing report metadata in `reports`.
   - `dashboard.py:build` (invoked via `pipeline.py:Pipeline.outputs`): compiles frontend datasets and writes `data/dashboard/dashboard_data.json` (overview, explorer, metrics, devices via `dashboard.py:gather`), `data/dashboard/site_data.json` (individual threat detail views via `dashboard.py:export_site_data`), `data/dashboard/clues.json` (defanged indicators via `dashboard.py:export_clues`), and `data/dashboard/threat_matches.json` (threat-to-application vulnerability mappings via `dashboard.py:export_threat_matches`).
   - `metrics.py:write` (invoked via `pipeline.py:Pipeline.outputs`): calculates operational performance statistics (mean/median time to assess, time to report, proactive threats identified, manual hours saved based on assumptions, and spot-check accuracy) via `metrics.py:compute` and writes `data/metrics.json`.

### Outputs

- **Files written under `data/`**:
  - `data/threat_intel.duckdb`: duckdb database containing all tables (`runs`, `feed_state`, `threats`, `threat_links`, `cves`, `iocs`, `attack_techniques`, `devices`, `software`, `device_vulns`, `defender_seen`, `device_settings`, `analysis`, `exposure`, `scores`, `hunts`, `hunt_results`, `findings`, `alerts`, `reports`, `resolutions`, `threat_fixes`, `ai_usage`) — written by `store.py:Store`.
  - `data/last_run.json`: JSON metadata for the latest Threat Intel run (run ID, status, timestamps, failed steps, failed feeds) — written by `pipeline.py:Pipeline.run_all`.
  - `data/last_attack_check.json`: JSON metadata for the latest attack-check run — written by `pipeline.py:Pipeline.attack_check`.
  - `data/.run.lock`: active run lock containing the running process PID — written by `pipeline.py:run_lock`.
  - `data/alerts.jsonl`: append-only log of raised high-risk alerts — written by `alerts.py:run`.
  - `data/metrics.json`: key operational metrics and performance measurements — written by `metrics.py:write`.
  - `data/demo_notes.md`: demo walkthrough script populated with live metrics — written by `demo.py:write`.
  - `data/ai_spotcheck_result.json`: evaluation scores from AI spot-checking — written by `spotcheck.py:score`.
  - `data/raw/<run_id>/...`: raw downloaded JSON/XML responses from external feeds — written by `feeds/common.py:FeedContext.save_raw`.
  - `data/cache/enterprise-attack.json`: cached STIX data bundle for MITRE ATT&CK — written by `feeds/attack.py:collect`.
  - `data/reports/Threat_Intel_Report_<stamp>.docx`: executive Word report — written by `report.py:build`.
  - `data/reports/Threat_Intel_Report_<stamp>.pdf`: executive PDF report — written by `report.py:build`.
  - `data/reports/Threat_Intel_AI_Spotcheck_<date>.xlsx`: Excel validation workbook of 20 random AI extractions — written by `spotcheck.py:export`.
  - `data/dashboard/dashboard_data.json`: headline numbers, threat explorer data, device counts, charts, and metrics — written by `dashboard.py:build`.
  - `data/dashboard/site_data.json`: full threat detail dictionary indexed by threat ID — written by `dashboard.py:export_site_data`.
  - `data/dashboard/clues.json`: full list of defanged indicators (IP, domain, URL, hash) — written by `dashboard.py:export_clues`.
  - `data/dashboard/threat_matches.json`: matrix of software applications, CVEs, devices, and associated threats — written by `dashboard.py:export_threat_matches`.
- **Files read by the dashboard (see `dashboard/src/dashboard/sources.py`)**:
  - `data/dashboard/dashboard_data.json`: read by `ThreatIntelSource.dashboard()` to supply data for portal overview, threat explorer, devices, and metrics cards.
  - `data/last_run.json`: read by `ThreatIntelSource.last_run()` to report agent health, run timestamps, and execution status.
  - `data/dashboard/clues.json`: read by `ThreatIntelSource.clues()` for the indicators / clues browser table.
  - `data/dashboard/site_data.json`: read by `ThreatIntelSource.threat(threat_id)` (cached by file modification time) to provide the individual threat detail view.
  - `data/dashboard/threat_matches.json`: read by `ThreatIntelSource._matches()`, `ThreatIntelSource.threat_match_counts()`, and `ThreatIntelSource.threat_matches()` to display vulnerable software matched by threats in the news.
  - `data/reports/*.*`: read by `ThreatIntelSource.reports()` to list `.docx`, `.pdf`, and `.xlsx` downloads on the Reports page (excluding legacy threat hunting reports).

### Actions that need a person

- The Threat Intel Agent's analysis, feed ingestion, Defender inventory reading, scoring, reporting, and dashboard generation are entirely read-only:
  - Defender API access is restricted to read-only endpoints (`GET /api/machines`, and read-only KQL execution via `POST /api/advancedqueries/run`).
  - Threat feed collection performs read-only HTTP GET/POST queries to public endpoints.
  - Automated notification delivery: `alerts.py` sends an automated outbound HTTP POST payload to Microsoft Teams if `TEAMS_WEBHOOK_URL` is defined.
- Device remediation and configuration changes:
  - Threat Intel only creates fix proposals (`fix_advice.py:run` populating `threat_fixes`).
  - Physical execution on devices (application upgrades/uninstalls via Azure Run Command or Defender Live Response, and Defender scan-and-clean) is handled exclusively by the fix engine (`fix/` / `shared/remediation`).
  - Approval check location: No action is executed on an endpoint or in Defender without human approval. Approvals are checked and recorded in `fix/state.py:FixState` (`data/fix/state.json`) via explicit human action on the web portal or CLI (`python -m threat_intel fix-approve`). `fix/runner.py:FixRunner` validates that every target fix has status `approved` in `FixState` before invoking any execution mechanism.

### Settings

All environment variables read by the agent, loaded in `config.py:load_settings`:

- `THREAT_INTEL_DATA_DIR`: path to agent working and storage directory (default: `./data`, with backward-compatibility alias)
- `THREAT_INTEL_LOG_DIR`: path to agent log directory (default: `./logs`, with backward-compatibility alias)
- `DEFENDER_API_BASE`: base URL for Microsoft Defender APIs (default: `"https://api.security.microsoft.com"`)
- `DEFENDER_TENANT_ID`: Microsoft Entra tenant ID for Defender authentication (default: `None`)
- `DEFENDER_CLIENT_ID`: Microsoft Entra application (client) ID for Defender authentication (default: `None`)
- `DEFENDER_CLIENT_SECRET`: Microsoft Entra client secret for Defender authentication (default: `None`)
- `GEMINI_API_KEY`: primary API key for Google Gemini (default: `None`)
- `GEMINI_API_KEY_2` through `GEMINI_API_KEY_9`: secondary fallback keys rotated upon quota exhaustion (default: `()`)
- `GEMINI_MODEL`: primary Gemini model for analysis and summaries (default: `"gemini-3.5-flash-lite"`)
- `GEMINI_FALLBACK_MODEL`: backup Gemini model (default: `"gemini-3.1-flash-lite"`)
- `GEMINI_RPM`: requests-per-minute rate limit for Gemini API (default: `15`)
- `GEMINI_DAILY_CAP`: daily call quota cap for Gemini API (default: `5000`)
- `GEMINI_WORKERS`: number of concurrent worker threads for Gemini analysis (default: `2`)
- `AI_PROVIDER`: preferred AI provider selection: `auto`, `azure`, or `gemini` (default: `"auto"`)
- `AZURE_FOUNDRY_ENDPOINT`: endpoint URL for Azure AI Foundry deployment (default: `None`)
- `AZURE_FOUNDRY_API_KEY`: API key for Azure AI Foundry (default: `None`)
- `AZURE_FOUNDRY_DEPLOYMENT`: deployment name in Azure AI Foundry (default: `None`)
- `AZURE_FOUNDRY_RPM`: requests-per-minute rate limit for Azure AI Foundry (default: `60`)
- `AZURE_FOUNDRY_REASONING_EFFORT`: reasoning effort for reasoning-capable models, e.g. `low`, `medium`, `high`, or `off` (default: `"low"`)
- `AZURE_FOUNDRY_DAILY_CAP`: daily call quota cap for Azure AI Foundry (default: `5000`)
- `AZURE_FOUNDRY_WORKERS`: number of concurrent worker threads for Azure analysis (default: `4`)
- `NVD_API_KEY`: API key for National Vulnerability Database to increase rate limits (default: `None`)
- `ABUSECH_AUTH_KEY`: authentication key for abuse.ch API (ThreatFox, URLhaus, MalwareBazaar) (default: `None`)
- `OTX_API_KEY`: API key for AlienVault OTX pulses (default: `None`)
- `TEAMS_WEBHOOK_URL`: incoming webhook URL for Microsoft Teams alert notifications (default: `None`)
- `CVE_WINDOW_DAYS`: lookback window in days for considering recently published NVD CVEs (default: `30`)
- `NVD_BACKFILL_DAYS`: lookback window in days for initial NVD download backfill (default: `3`)
- `FEED_BACKFILL_DAYS`: lookback window in days for initial feed backfills (default: `7`)
- `HUNT_LOOKBACK_DAYS`: lookback window in days for hunting queries, max 30 (default: `30`)
- `AZURE_SUBSCRIPTION_ID`: Azure subscription ID for VM Run Command execution (default: `None`)
- `FIX_RESOURCE_GROUP`: Azure resource group containing lab VMs eligible for Run Command fixes (default: `"rg-uc3-lab"`)
- `FIX_METHOD`: preferred remediation execution mechanism: `runcommand` or `liveresponse` (default: `"runcommand"`)
- `FIX_ALLOW_CHOCO`: whether to allow Chocolatey package manager fallback on target machines (default: `False`)
- `FIX_START_VMS`: whether to automatically start deallocated lab VMs before running fixes (default: `True`)
- `FIX_DEVICES`: comma-separated filter of specific device names eligible for fix execution (default: `()`)
- `ATTACK_AUTO_FIX`: whether attack check runs auto-approve scan-and-clean actions (default: `True`)
- `THREAT_INTEL_VULN_AGENT_DIR`: filesystem path to the Vulnerability Agent directory (default: `"../vulnerability"`, with backward-compatibility alias)

### Reads from other agents

- `agents/vulnerability/data/dashboard/dashboard_data.json`: read by `exposure.py:defender_first_listed` (via `settings.vuln_agent_dir`) to retrieve baseline first-seen dates for device CVE findings. Falls back gracefully to the local `defender_seen` table if missing or inaccessible.

### Open questions

- In `pipeline.py:run_all()`, line 261 executes `self.correlate()`, which invokes `correlate.py:run(store, defender, run_id)` during the Threat Intel run even though no hunting occurs in this pipeline run ("no hunts in this run: refreshes which computers each threat affects"). Per `ARCHITECTURE.md`, `correlate.py` belongs to the Attack Detection Agent, and Threat Intel should calculate exposure via `exposure.py` alone.
- In `inventory.py:pull()`, device vulnerabilities are queried via Defender Advanced Hunting (`DeviceTvmSoftwareVulnerabilities`), which enforces a hard 100,000-row limit (`MAX_HUNT_ROWS`), risking incomplete inventory on large estates where the Vulnerability Agent's export API would be more appropriate.
- In `exposure.py:defender_first_listed()`, the function directly reads `data/dashboard/dashboard_data.json` from the Vulnerability Agent's directory (`settings.vuln_agent_dir`) instead of consuming an official published contract under `data/out/`.
- In `alerts.py:candidates()`, alerts are filtered by `t.threat_id IN (SELECT threat_id FROM findings)`. Because `findings` are populated by hunt correlation, a standalone Threat Intel run with newly exposed Critical threats will not generate alerts if hunting findings do not exist.
- In `derive.py:forget_repeats()`, threats matching no installed software are deleted from the database. If software inventory synchronization is incomplete or if software naming conventions differ between NVD CPE strings and Defender inventory names, valid threat records may be deleted prematurely.
- Concurrency and lock contention: Both `threat_intel run` and `threat_intel attack-check` share `data/threat_intel.duckdb` and the single lock file `data/.run.lock`, causing one process to wait up to 30 minutes if the other is active.
- In `metrics.py:compute()`, monthly projected hunts are calculated as `per_run * 6 * 30` assuming a 4-hour schedule interval, rather than reading the active scheduler configuration.

