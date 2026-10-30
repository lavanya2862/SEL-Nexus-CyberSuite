# Attack Detection Agent Specification

### Inputs - every Microsoft Defender API, query template (config/kql_templates/) and file it reads, with the file:function that reads it

#### Microsoft Defender APIs
- `POST /api/advancedqueries/run` (Advanced Hunting KQL Execution)
  - `threat_intel/hunting/runner.py:HuntRunner.execute` — executes rendered KQL queries for IOC sweeps, static behaviour templates, and AI-drafted hunt queries via `threat_intel/api_client.py:DefenderClient.run_query`.
  - `threat_intel/correlate.py:_users` — executes `USERS_QUERY` against the `DeviceLogonEvents` table in Defender Advanced Hunting via `threat_intel/api_client.py:DefenderClient.run_query` to identify user accounts logged into involved devices over the last 7 days.
- `GET /api/alerts` (Defender Incident and Alert Retrieval)
  - `threat_intel/correlate.py:_alerts` — queries Defender alerts using OData parameters (`$filter=alertCreationTime ge {since}&$top=1000`) via `threat_intel/api_client.py:DefenderClient.get_all` to correlate Defender alerts from the last 30 days with devices having hunt hits.
- *Defender Live Response APIs (invoked if `ATTACK_AUTO_FIX=1` executes scan-and-clean remediation via Live Response)*:
  - `PUT /api/libraryfiles` — `threat_intel/fix/executors.py:LiveResponseExecutor._ensure_script` uploads `assets/fix_app.ps1` to the Defender Live Response library.
  - `POST /api/machines/{device_id}/runliveresponse` — `threat_intel/fix/executors.py:LiveResponseExecutor.run` initiates the Live Response remediation job on the targeted computer.
  - `GET /api/machineactions/{action_id}` — `threat_intel/fix/executors.py:LiveResponseExecutor._wait_action` polls the running status of the Live Response action.
  - `GET /api/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index=0)` — `threat_intel/fix/executors.py:LiveResponseExecutor.run` downloads the result log.
  *(Note: If `fix_method` is set to `runcommand`, remediation executes via Azure Virtual Machine Run Command REST API rather than Defender APIs).*

#### Query Templates (`config/kql_templates/`)
Parsed and loaded by `threat_intel/hunting/templates.py:load` and `threat_intel/hunting/templates.py:parse` (called by `threat_intel/hunting/runner.py:HuntRunner.__init__`):
- **Behaviour Hunt Templates (`kind: behaviour`)**:
  - `config/kql_templates/bh_av_detection.kql` — Antivirus detection events in `DeviceEvents` (technique: T1562.001).
  - `config/kql_templates/bh_discovery_burst.kql` — Rapid user/group discovery in `DeviceProcessEvents` (technique: T1087).
  - `config/kql_templates/bh_encoded_powershell.kql` — Encoded PowerShell execution in `DeviceProcessEvents` (technique: T1059.001).
  - `config/kql_templates/bh_local_account.kql` — Local account creation in `DeviceEvents` / `DeviceProcessEvents` (technique: T1136.001).
  - `config/kql_templates/bh_lolbins.kql` — Living-off-the-land binaries in `DeviceProcessEvents` (technique: T1218).
  - `config/kql_templates/bh_lsass_access.kql` — LSASS process memory access in `DeviceProcessEvents` (technique: T1003.001).
  - `config/kql_templates/bh_new_service.kql` — Windows service creation in `DeviceEvents` / `DeviceProcessEvents` (technique: T1543.003).
  - `config/kql_templates/bh_run_key.kql` — Registry Run key persistence in `DeviceRegistryEvents` (technique: T1547.001).
  - `config/kql_templates/bh_scheduled_task.kql` — Scheduled task creation in `DeviceProcessEvents` (technique: T1053.005).
  - `config/kql_templates/bh_startup_folder.kql` — Startup folder file drops in `DeviceFileEvents` (technique: T1547.001).
- **Indicator of Compromise Templates (`kind: ioc`)**:
  - `config/kql_templates/ioc_domain.kql` — Network events matching domain indicators in `DeviceNetworkEvents`.
  - `config/kql_templates/ioc_hash.kql` — Process, file, and image load events matching file hashes (SHA256, SHA1, MD5) in `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceImageLoadEvents`.
  - `config/kql_templates/ioc_ip.kql` — Network events matching remote IP indicators in `DeviceNetworkEvents`.
  - `config/kql_templates/ioc_url.kql` — Network events matching remote URL indicators in `DeviceNetworkEvents`.
- **Other Template in Directory**:
  - `config/kql_templates/cve_exposure.kql` — Exposure check query with `kind: manual`; loaded by `templates.py:load` but not rendered by `HuntRunner`.

#### Files Read
- `config/ioc_allowlist.csv` — `threat_intel/feeds/iocs.py:load_allowlist` (invoked via `threat_intel/hunting/runner.py:HuntRunner.ioc_values`) reads allowlisted domains to skip during IOC sweeps.
- `config/risk_policy.csv` — `threat_intel/config.py:read_policy` (invoked via `threat_intel/scoring.py:run` during the rescore step) reads policy weights for risk score adjustment.
- `config/fix_catalog.csv` — `threat_intel/fix/plan.py:load_catalog` (invoked during `Pipeline.fix_plan` -> `plan.refresh`) reads approved package IDs and actions.
- `config/setting_fix_catalog.csv` — `threat_intel/fix/plan.py:load_setting_catalog` (invoked during `Pipeline.fix_plan` -> `plan.refresh`) reads security setting definitions.
- `data/fix/state.json` — `threat_intel/fix/state.py:FixState.read` (invoked via `threat_intel/fix/plan.py:refresh` and `threat_intel/pipeline.py:Pipeline.auto_fix`) reads decided fix statuses and history.
- `data/fix/plan.json` — `threat_intel/fix/plan.py:read_plan` (invoked via `threat_intel/pipeline.py:Pipeline.auto_fix`) reads pending remediation proposals.
- `data/.run.lock` — `threat_intel/pipeline.py:lock_active` reads the process ID to verify that no concurrent pipeline run is active.
- `.env` — `threat_intel/config.py:load_settings` reads environment variables from the suite settings file.
- `assets/fix_app.ps1` — `threat_intel/fix/executors.py:LiveResponseExecutor._ensure_script` reads the remediation script when pushing to the Live Response library.

---

### Steps - its four steps (Search devices, Connect evidence, How to resolve, Publish): which files and functions do each, in order

1. **Search devices** (`hunt`)
   - `threat_intel/pipeline.py:Pipeline.hunt` calls `threat_intel/hunting/runner.py:HuntRunner.run_all(feed_backfill_days)`.
   - `HuntRunner.run_all` executes three sub-steps in sequence:
     1. `threat_intel/hunting/runner.py:HuntRunner.ioc_sweeps`: Queries active threat IOCs and test indicators from DuckDB table `threat_links`, filters out allowlisted domains via `threat_intel/feeds/iocs.py:allowlisted`, chunks indicators into batches of 400, renders queries using `threat_intel/hunting/templates.py:Template.render`, and calls `HuntRunner.execute`.
     2. `threat_intel/hunting/runner.py:HuntRunner.behaviour_hunts`: Iterates through all behaviour templates (`bh_*.kql`), renders queries with `lookback_days`, and calls `HuntRunner.execute`.
     3. `threat_intel/hunting/runner.py:HuntRunner.ai_hunts`: Queries ATT&CK techniques associated with Critical/High threats not covered by static templates; uses Gemini via `threat_intel/ai/gemini_client.py:GeminiClient.json` (prompted by `threat_intel/ai/prompts.py:kql_prompt`) to draft KQL queries; checks drafts via `threat_intel/hunting/validator.py:validate` and `ensure_limit`; attempts fix on error with `kql_fix_prompt`; calls `HuntRunner.execute`. Caches working drafts in the `hunts` database table.
   - `threat_intel/hunting/runner.py:HuntRunner.execute`: Dispatches each query to Defender via `threat_intel/api_client.py:DefenderClient.run_query`, handles rate limits and retries, extracts matched fields, and writes records to DuckDB tables `hunts` and `hunt_results`.

2. **Connect evidence** (`correlate` and `rescore`)
   - `threat_intel/pipeline.py:Pipeline.correlate` calls `threat_intel/correlate.py:run(store, client, run_id)`:
     - Retrieves hunt hits from `hunts` and `hunt_results` for `run_id`, grouping hits by IOC value or behaviour template/technique and device ID.
     - Decodes base64 PowerShell command arguments via `threat_intel/correlate.py:decode_powershell`.
     - Detects lab test activity via `threat_intel/correlate.py:is_lab_test` (checks for EICAR hash, `UC1LabTest` marker, or AMSI test GUID).
     - Queries recently logged-on users for involved devices via `threat_intel/correlate.py:_users` (running `USERS_QUERY` in Defender Advanced Hunting).
     - Fetches recent Defender alerts for involved devices via `threat_intel/correlate.py:_alerts` (`GET /api/alerts`).
     - Creates synthetic threat entries for standalone behaviour hits via `threat_intel/correlate.py:_hunt_threat` in DuckDB table `threats`.
     - Constructs event timelines combining hunt matches and temporally correlated Defender alerts.
     - Preserves previous hit timestamps and upserts finding records into DuckDB table `findings`.
   - `threat_intel/pipeline.py:Pipeline.score("rescore")`:
     - Calls `threat_intel/exposure.py:compute` to refresh exposure links.
     - Calls `threat_intel/scoring.py:run(store)` to recalculate threat scores, elevating the rating of threats that have confirmed hunt hits on devices.

3. **How to resolve** (`resolve`)
   - `threat_intel/pipeline.py:Pipeline.resolve` calls `threat_intel/resolve.py:run(store, settings, ai)`:
     - Identifies findings in table `findings` where `kind <> 'exposure'` that lack AI-generated resolutions.
     - Compiles finding evidence into structured text via `threat_intel/resolve.py:evidence(f)`.
     - Calls `threat_intel/resolve.py:resolve_one` using Gemini AI (`threat_intel/ai/gemini_client.py:GeminiClient.json`) with `RESOLVE_SYSTEM` and `resolve_prompt`.
     - Validates AI-generated steps via `threat_intel/resolve.py:checked(answer, text)`, discarding steps mentioning IP addresses or file hashes not found in the evidence text.
     - If AI is unavailable or fewer than two steps pass validation, falls back to `threat_intel/resolve.py:standard(f)` (isolation guidance, user verification, Defender antivirus scan, indicator blocking, password reset).
     - Upserts resolutions into DuckDB table `resolutions`.

4. **Publish** (`alerts`, `report`, `dashboard`, `fix_plan`, `auto_fix`)
   - **Alerts**: `threat_intel/pipeline.py:Pipeline.step("alerts", alerts.run)` calls `threat_intel/alerts.py:run(store, settings)`, inserting alerts for Critical/High threats into DuckDB table `alerts`, appending to `data/alerts.jsonl`, and sending to Teams if `TEAMS_WEBHOOK_URL` is set.
   - **Report**: `threat_intel/pipeline.py:Pipeline.step("report", attack_report.build)` calls `threat_intel/attack_report.py:build(store, settings, run_id, steps)`, producing Word report `data/reports/Attack_Detection_Report_{timestamp}.docx`.
   - **Dashboard**: `threat_intel/pipeline.py:Pipeline.step("dashboard", ...)` calls `threat_intel/dashboard.py:build(store, settings)`, exporting `data/dashboard/dashboard_data.json`, `site_data.json`, `clues.json`, and `threat_matches.json`.
   - **Fix Plan**: `threat_intel/pipeline.py:Pipeline.fix_plan("attack_detection")` calls `threat_intel/fix/plan.py:refresh(store, settings, "attack_detection")`, building scan-and-clean response items (`kind: response`, `action: respond`) and saving `data/fix/plan.json`.
   - **Auto-Fix**: If `ATTACK_AUTO_FIX=1`, `threat_intel/pipeline.py:Pipeline.auto_fix` auto-approves response items via `threat_intel/fix/plan.py:approve` and executes remediation via `threat_intel/fix/runner.py:FixRunner.run_approved`.
   - **Run Tracking**: `threat_intel/pipeline.py:Pipeline.attack_check` logs run status to DuckDB table `runs` and writes `data/last_attack_check.json`.

---

### Outputs - every file and database table it writes, and which of them the dashboard reads (see dashboard/src/dashboard/sources.py)

#### Files Written
- `data/dashboard/dashboard_data.json` — Written by `threat_intel/dashboard.py:build`.
  - **Read by dashboard**: Yes. `dashboard/src/dashboard/sources.py:ThreatIntelSource.dashboard()` reads this file. Its `hits` array (attack findings) and `hunts` array (latest searches) directly populate the Attack Detection page (`web/src/agents/attack-detection/Hunting.tsx`) and the overview cards in `dashboard/src/dashboard/summary.py`.
- `data/dashboard/site_data.json` — Written by `threat_intel/dashboard.py:export_site_data`.
  - **Read by dashboard**: Yes. `dashboard/src/dashboard/sources.py:ThreatIntelSource.threat(threat_id)` reads this file, including the `findings` and `hunts` arrays associated with each threat.
- `data/dashboard/clues.json` — Written by `threat_intel/dashboard.py:export_clues`.
  - **Read by dashboard**: Yes. `dashboard/src/dashboard/sources.py:ThreatIntelSource.clues()` reads this file to display indicators and note which ones were detected on devices.
- `data/dashboard/threat_matches.json` — Written by `threat_intel/dashboard.py:export_threat_matches`.
  - **Read by dashboard**: Yes. `dashboard/src/dashboard/sources.py:ThreatIntelSource._matches()` reads this file.
- `data/reports/Attack_Detection_Report_{timestamp}.docx` — Written by `threat_intel/attack_report.py:build`.
  - **Read by dashboard**: Yes. `dashboard/src/dashboard/sources.py:ThreatIntelSource.reports()` lists all `.docx`, `.pdf`, and `.xlsx` files in `data/reports/`.
- `data/last_attack_check.json` — Written by `threat_intel/pipeline.py:Pipeline.attack_check`.
  - **Read by dashboard**: Not read directly by `sources.py` (which reads `last_run.json`), but tracked by `dashboard/src/dashboard/runs.py:RunManager` for run status.
- `data/alerts.jsonl` — Appended by `threat_intel/alerts.py:run`.
  - **Read by dashboard**: Not read directly by `sources.py` (the dashboard consumes alerts through `dashboard_data.json`).
- `data/fix/plan.json` — Written by `threat_intel/fix/plan.py:refresh`.
  - **Read by dashboard**: Read by the Fix Centre backend adapter (`dashboard/src/dashboard/remediation.py` via `threat_intel/fix/plan.py:view`).
- `data/fix/state.json` — Written/updated by `threat_intel/fix/plan.py:approve` and `FixRunner` during `auto_fix`.
  - **Read by dashboard**: Read by the Fix Centre backend adapter via `threat_intel/fix/plan.py:view`.
- `data/.run.lock` — Managed by `threat_intel/pipeline.py:run_lock`.
  - **Read by dashboard**: Inspected by `dashboard/src/dashboard/runs.py` / `runner.py`.

#### Database Tables Written (`data/threat_intel.duckdb`)
- `runs`: Run execution records (`run_id`, `command: 'attack-check'`, `started_at`, `finished_at`, `status`, `steps`).
- `hunts`: Query definitions and run metadata (`hunt_id`, `run_id`, `threat_id`, `name`, `template`, `origin`, `technique`, `query`, `status`, `row_count`, `error`, `duration_s`).
- `hunt_results`: Raw event records retrieved from Defender (`hunt_id`, `row_no`, `device_id`, `device_name`, `event_time`, `account`, `summary`, `row_json`).
- `threats`: Synthetic threat records created by `correlate.py:_hunt_threat` for behaviour hunt hits.
- `threat_links`: MITRE ATT&CK technique links for synthetic hunt threats.
- `findings`: Detection finding records (`kind: 'ioc_hit'`, `'behaviour_hit'`, device info, timeline, users, alerts).
- `scores`: Threat risk scores recalculated during the rescore step.
- `resolutions`: AI and standard resolution steps per finding (`what_happened`, `steps`, `done_when`, `source`, `model`).
- `alerts`: Alert records generated for high-risk threats affecting devices.
*(Note: Per rules in `dashboard/src/dashboard/sources.py`, the dashboard never opens the agent's live DuckDB database directly to avoid lock contention; all dashboard reads are performed against exported files).*

---

### Actions that need a person - anything that changes a device or Defender, and where the approval is checked

- **Device Isolation**:
  - Recommended in `threat_intel/resolve.py:standard` ("Isolate {dev} in Microsoft Defender... so it cannot reach other computers").
  - Where checked: Device isolation requires `Machine.Isolate` permission and is never performed by the agent. It is strictly a manual analyst action carried out directly in the Microsoft Defender portal.
- **Remediation Responses (Antivirus Scan and Clean)**:
  - Proposed by `threat_intel/fix/plan.py:response_items` for each sign of attack (`action: "respond"`, `kind: "response"`), creating an antivirus scan task (`RESPONSE_LADDER`: QuickScan, FullScan) via Defender Live Response or Azure Run Command.
  - Where checked:
    - *Manual Mode (`ATTACK_AUTO_FIX=0`)*: Remediations remain in status `"proposed"` in `data/fix/plan.json`. A person must review and approve each response in the portal (Fix Centre / `/fixes` page). Approval is verified in `threat_intel/fix/plan.py:approve` (updating `data/fix/state.json`) and checked in `threat_intel/fix/runner.py:FixRunner.run_approved`.
    - *Auto-Fix Mode (`ATTACK_AUTO_FIX=1`, default)*: In `threat_intel/pipeline.py:Pipeline.auto_fix`, the pipeline automatically approves pending proposals with `who="Attack Detection Agent (auto-fix)"` and executes them immediately. A human can defer or prevent execution by choosing "Save for later" (status `"saved"`) in the portal, or pause/retry via the Fix Centre UI.
- **Indicator Blocking in Defender**:
  - Recommended in `threat_intel/resolve.py:standard` ("Block the indicator in Microsoft Defender (Settings, Endpoints, Indicators)").
  - Where checked: Manual analyst action in Microsoft Defender portal. The agent does not automate indicator blocking.
- **Account Password Resets and Session Revocations**:
  - Recommended in `threat_intel/resolve.py:standard` ("reset the password of {user} and sign them out of all sessions").
  - Where checked: Manual administrator action in Microsoft Entra ID / Microsoft 365 Admin Center.

---

### Settings - every environment variable it reads, with its default

Read in `threat_intel/config.py:load_settings`:
- `DEFENDER_API_BASE`: Microsoft Defender API endpoint URL. Default: `"https://api.security.microsoft.com"`.
- `DEFENDER_TENANT_ID`: Microsoft Entra tenant ID. Default: `None`.
- `DEFENDER_CLIENT_ID`: Entra application client ID. Default: `None`.
- `DEFENDER_CLIENT_SECRET`: Entra application client secret. Default: `None`.
- `AI_PROVIDER`: Choice of AI backend (`"auto"`, `"azure"`, `"gemini"`). Default: `"auto"`.
- `AZURE_FOUNDRY_ENDPOINT`: Azure AI Foundry endpoint URL. Default: `None`.
- `AZURE_FOUNDRY_API_KEY`: Azure AI Foundry API key. Default: `None`.
- `AZURE_FOUNDRY_DEPLOYMENT`: Azure AI Foundry deployment name. Default: `None`.
- `AZURE_FOUNDRY_RPM`: Rate limit for Azure Foundry calls (requests per minute). Default: `60`.
- `AZURE_FOUNDRY_REASONING_EFFORT`: Reasoning effort for Azure Foundry reasoning models (`"low"`, `"minimal"`, `"medium"`, `"high"`, `"off"`). Default: `"low"`.
- `AZURE_FOUNDRY_DAILY_CAP`: Daily ceiling for Azure Foundry requests. Default: `5000`.
- `AZURE_FOUNDRY_WORKERS`: Worker threads for parallel Azure AI requests. Default: `4`.
- `GEMINI_API_KEY`: Primary Google Gemini API key. Default: `None`.
- `GEMINI_API_KEY_2` through `GEMINI_API_KEY_9`: Fallback Gemini API keys for quota exhaustion. Default: `()`.
- `GEMINI_MODEL`: Primary Gemini model identifier. Default: `"gemini-3.5-flash-lite"`.
- `GEMINI_FALLBACK_MODEL`: Fallback Gemini model identifier. Default: `"gemini-3.1-flash-lite"`.
- `GEMINI_RPM`: Rate limit for Gemini requests per minute. Default: `15`.
- `GEMINI_DAILY_CAP`: Daily ceiling for Gemini requests. Default: `5000`.
- `GEMINI_WORKERS`: Worker threads for parallel Gemini requests. Default: `2`.
- `FEED_BACKFILL_DAYS`: Number of days of threat IOCs to include in hunt sweeps. Default: `7`.
- `HUNT_LOOKBACK_DAYS`: Defender Advanced Hunting query time window in days (capped at 30). Default: `30`.
- `TEAMS_WEBHOOK_URL`: Webhook URL for Microsoft Teams notification delivery. Default: `None`.
- `ATTACK_AUTO_FIX`: Switch to automatically approve and execute scan-and-clean fixes (`1` for true, `0` for false). Default: `True` (`1`).
- `FIX_RESOURCE_GROUP`: Azure resource group targeting VMs for Azure Run Command remediation. Default: `"rg-uc3-lab"`.
- `FIX_METHOD`: Default remediation method (`"runcommand"` or `"liveresponse"`). Default: `"runcommand"`.
- `FIX_ALLOW_CHOCO`: Allow Chocolatey package manager fallback during remediation. Default: `False` (`0`).
- `FIX_START_VMS`: Start deallocated Azure VMs before running remediation. Default: `True` (`1`).
- `FIX_DEVICES`: Comma-separated allowlist of device names eligible for remediation. Default: `()` (all devices eligible).
- `AZURE_SUBSCRIPTION_ID`: Azure subscription ID for VM Run Command. Default: `None` (auto-discovered).
- Directory path settings loaded from legacy environment variables in `threat_intel/config.py`:
  - Data directory path setting. Default: `"./data"`.
  - Log directory path setting. Default: `"./logs"`.

---

### Shared with the Threat Intel Agent - code, database tables and files both use

- **Shared Code**:
  - `threat_intel/pipeline.py`: Single `Pipeline` class defines both `run_all()` (Threat Intel) and `attack_check()` (Attack Detection); shares process locking (`run_lock`, `lock_active`, `_pid_alive`), run ID generation (`new_run_id`), and client factory functions (`make_defender`, `make_ai`).
  - `threat_intel/correlate.py`: `correlate.run` is executed in both runs; handles both vulnerability exposure and hunt findings, linking them to devices, users, alerts, and timelines.
  - `threat_intel/scoring.py` and `exposure.py`: Threat risk scoring and exposure evaluation are shared; `attack_check` invokes scoring (`"rescore"`) to raise threat scores when hunt hits occur.
  - `threat_intel/alerts.py`: `alerts.run` generates alert records and sends notifications for both runs.
  - `threat_intel/dashboard.py`: `dashboard.build` writes all dashboard export files (`dashboard_data.json`, `site_data.json`, `clues.json`, `threat_matches.json`) for both runs.
  - `threat_intel/fix/`: The entire remediation subsystem (`plan.py`, `state.py`, `runner.py`, `executors.py`) is shared between vulnerability fixes and attack responses.
  - `threat_intel/api_client.py` and `threat_intel/auth.py`: Shared `DefenderClient` and `EntraTokenProvider`.
  - `threat_intel/ai/`: Shared AI clients (`gemini_client.py`, `azure_client.py`), prompts, and schemas.
  - `threat_intel/config.py`: Shared `Settings` configuration dataclass and loader.
  - `threat_intel/store.py`: Shared DuckDB `Store` class, SQL schema, and database connection.
- **Shared Database Tables (`data/threat_intel.duckdb`)**:
  - `runs`: History for both `run` and `attack-check` commands.
  - `threats` & `threat_links`: Threat Intel writes news threats and indicators; Attack Detection queries IOC links for sweeps and inserts synthetic hunt threats.
  - `devices`: Created and refreshed by Threat Intel inventory; read by Attack Detection for device correlation, reporting, and dashboard export.
  - `exposure`: Created by Threat Intel; read by Attack Detection correlation.
  - `findings`: Contains exposure findings from Threat Intel and hunt hit findings from Attack Detection.
  - `scores`: Re-scored and updated during Attack Detection runs.
  - `alerts`: Alert records from both runs.
  - `ai_usage`: Token usage tracking for AI calls from both runs.
- **Shared Files**:
  - `data/threat_intel.duckdb`: Single shared DuckDB database file.
  - `data/.run.lock`: Single process lock preventing concurrent execution.
  - `data/alerts.jsonl`: Shared alert log file.
  - `data/fix/plan.json` and `data/fix/state.json`: Shared remediation plan and execution state.
  - `data/dashboard/dashboard_data.json`, `site_data.json`, `clues.json`, `threat_matches.json`: Shared dashboard export files overwritten by either pipeline.
  - `config/risk_policy.csv`: Shared risk scoring configuration.
  - `config/ioc_allowlist.csv`: Shared domain allowlist.

---

### Open questions - anything that looks wrong or unclear (do not fix it)

1. **Single shared DuckDB database locking**: Both pipelines operate out of `data/threat_intel.duckdb`. DuckDB restricts write access to a single process at a time. When Attack Detection is separated into `agents/attack_detection`, how will it access IOCs and device inventory without opening Threat Intel's database or contending for locks? (ARCHITECTURE.md Rule 2 specifies data exchange solely via `data/out/`, such as reading `threat_intel/data/out/iocs.json`).
2. **Dual ownership of `correlate.py`**: `threat_intel/correlate.py` currently handles both exposure findings (`kind = 'exposure'`) and hunt findings (`kind IN ('ioc_hit', 'behaviour_hit')`), and explicitly deletes exposure findings on each run (`DELETE FROM findings WHERE kind = 'exposure'`). ARCHITECTURE.md notes that `correlate.py` should move to Attack Detection while Threat Intel answers "Affects us?" with `exposure.py` alone. How will the finding lifecycle be decoupled during the migration?
3. **Dashboard export coupling**: `Pipeline.attack_check` executes `threat_intel/dashboard.py:build()`, which regenerates Threat Intel-specific files (`site_data.json`, `threat_matches.json`, `clues.json`) in addition to `dashboard_data.json`. In the target architecture, Attack Detection should only publish `data/out/findings.json` and `status.json`, with the dashboard adapter reading them independently.
4. **`last_run.json` versus `last_attack_check.json`**: `Pipeline.attack_check` writes `data/last_attack_check.json`, while `dashboard/src/dashboard/sources.py:ThreatIntelSource.last_run()` only reads `data/last_run.json`. Consequently, the dashboard sources layer does not recognize attack check runs directly from that file.
5. **Auto-fix enabled by default**: `ATTACK_AUTO_FIX` defaults to `True` (`1`), which causes `Pipeline.auto_fix()` to automatically approve and execute scan-and-clean actions on machines without waiting for user interaction. Is this intentional or does it conflict with ARCHITECTURE.md Rule 3 ("Agents propose fixes; the Fix Centre runs them. Nothing changes on a device without a person's approval") and CLAUDE.md ("Nothing changes on a device or in Defender without a person approving it")?
6. **Hardcoded lab test markers in `correlate.py`**: `threat_intel/correlate.py` defines `LAB_MARKER = "threat_intel lab test"` and checks for the lab marker `UC1LabTest`. Will both marker formats continue to be supported when Attack Detection is moved out of Threat Intel into its own agent?
7. **Legacy environment variable names in `config.py`**: `threat_intel/config.py` continues to read legacy folder prefix names for the data directory, log directory, and vulnerability agent directory rather than the target `ATTACK_*` and `THREAT_INTEL_*` names specified in ARCHITECTURE.md.
8. **Template classification for `cve_exposure.kql`**: `config/kql_templates/cve_exposure.kql` resides in the KQL template folder but is marked with `kind: manual` and used only for exposure verification rather than hunting. Should this template remain in Threat Intel rather than moving with the hunting templates to Attack Detection?
9. **AI client provider restriction in hunting and resolution**: While Threat Intel supports both Azure AI Foundry and Google Gemini for analysis via `AI_PROVIDER`, `threat_intel/hunting/runner.py:HuntRunner.ai_hunts` and `threat_intel/resolve.py:run` explicitly type-hint and call `GeminiClient`. It is unclear whether Attack Detection is intended to support Azure AI Foundry or remain Gemini-only.
