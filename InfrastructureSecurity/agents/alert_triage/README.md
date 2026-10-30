# Alert Triage Agent: Alert Triage Agent (SOC Monitoring)

An **AI triage assistant** for security incidents. For every new incident it collects the related logs, checks threat intelligence, history and watchlists, applies fixed safety rules, and **recommends** close / escalate / contain, with the evidence behind it. A human always decides.

## How it works (one incident)

```
Defender / Sentinel incident ─► packet (alerts, devices, accounts, files; attacker text kept apart)
   ─► playbook for its type ─► read-only searches ±24 h, threat intel, history, watchlists
   ─► safety rules (before) ─► ONE AI call, strict JSON ─► answer checker ─► safety rules (after: only more cautious)
   ─► the portal's Alert triage page ─► analyst agrees / disagrees ─► metrics + accuracy
```

## Setup

Requires Python 3.12+ on Windows.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\pip install -e .
copy ..\..\.env.example ..\..\.env    # once, for the whole suite; then fill it in (never commit it)
.\.venv\Scripts\python.exe -m alert_triage check
.\.venv\Scripts\python.exe -m alert_triage live-test
```

What `.env` needs:

| Setting | Where it comes from |
|---|---|
| `UC4_TENANT_ID`, `UC4_CLIENT_ID`, `UC4_CLIENT_SECRET` | An Entra ID app registration with Microsoft Graph application permissions `SecurityIncident.Read.All`, `SecurityAlert.Read.All`, `ThreatHunting.Read.All` and WindowsDefenderATP `Machine.Read.All` (admin consent granted) |
| `AZURE_FOUNDRY_ENDPOINT`, `AZURE_FOUNDRY_API_KEY`, `AZURE_FOUNDRY_DEPLOYMENT` | Azure AI Foundry model deployment (Foundry portal -> Models + endpoints). When all three are set the agent uses it instead of Gemini; `AI_PROVIDER=gemini` switches back. Reasoning models such as gpt-5 work too (`AZURE_FOUNDRY_REASONING_EFFORT`, default low) |
| `GEMINI_API_KEY` | Free key from Google AI Studio (used when Azure AI Foundry is not set) |
| `GEMINI_API_KEY_2`, `GEMINI_API_KEY_3` … (optional) | Spare Gemini keys: when one key uses up its daily quota the next takes over. Each must be from a different Google Cloud project (keys in one project share its quota) |
| `ABUSECH_AUTH_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY` | Free threat-intel keys (all optional) |

Optional actions are **off** by default and need extra permissions when switched on:

| Setting | Does | Extra permission |
|---|---|---|
| `UC4_WRITEBACK=1` | Posts one "AI triage" comment on each lab incident | Graph `SecurityIncident.ReadWrite.All` |
| `UC4_RESPOND=1` | Asks Defender to scan / quarantine | WindowsDefenderATP `Machine.Scan`, `Machine.StopAndQuarantine` |
| `UC4_CONTAIN=1` | Lets an analyst approve isolating a lab device (only names in `UC4_LAB_DEVICES`) | WindowsDefenderATP `Machine.Isolate` |

## Commands

```powershell
.\.venv\Scripts\python.exe -m alert_triage serve       # service for the portal: http://127.0.0.1:8900/api (this computer only)
.\.venv\Scripts\python.exe -m alert_triage run         # pick up new incidents and triage them
.\.venv\Scripts\python.exe -m alert_triage backtest    # accuracy on GUIDE + lab incidents
.\.venv\Scripts\python.exe -m alert_triage metrics     # MTTR, MTTC, SLA, effort (MEASURED / ASSUMPTION)
```

Backtest data: Microsoft's **GUIDE** dataset (about 1 M analyst-labelled incidents, CDLA-Permissive-2.0) from Kaggle ("Microsoft Security Incident Prediction"). Put `GUIDE_Train.csv` and `GUIDE_Test.csv` in `data/inbox/guide/`.

## Folder layout

| Path | Purpose |
|---|---|
| `src/alert_triage/` | The agent: incident packets, playbooks, safety rules, AI call + answer checker, threat intel, backtest, metrics, `site.py` (API for the portal; no web pages) |
| `config/` | Settings template, playbooks, safety rules (`guardrails.yaml`), containment menu, watchlists, KQL queries, SLA policy, answer schema |
| `data/`, `logs/` | Created at run time (not in git) |

## Rules

- Recommend-only: the agent never closes, reclassifies or contains anything by itself unless an optional action above is switched on.
- Text written by an attacker (alert titles, command lines) is kept apart from the instructions and never obeyed.
- Secrets live only in `.env`; nothing prints them.

## Spec

### Inputs
- **Microsoft Graph Security API** (`https://graph.microsoft.com/v1.0`):
  - `GET security/incidents`: `alert_triage/api.py:GraphClient.incidents` (called by `alert_triage/ingest.py:fetch`)
  - `GET security/incidents/{incident_id}`: `alert_triage/api.py:GraphClient.incident` (called by `alert_triage/ingest.py:fetch_incident`, `alert_triage/packet.py:build`)
  - `POST security/runHuntingQuery`: `alert_triage/api.py:GraphClient.hunt` (called by `alert_triage/tools/logs.py:LogTools.run`, `alert_triage/tools/history.py:for_incident`, `alert_triage/autoresolve.py:run`)
  - `PATCH security/incidents/{incident_id}`: `alert_triage/api.py:GraphClient.update_incident` (called by `alert_triage/close.py:act`, `alert_triage/autoresolve.py:run`, `alert_triage/autoresolve.py:reopen`)
  - `POST security/incidents/{incident_id}/comments`: `alert_triage/api.py:GraphClient.add_comment` (called by `alert_triage/writeback.py:post_comment`, `alert_triage/close.py:act`, `alert_triage/autoresolve.py:run`)
- **Azure Log Analytics Query API** (`https://api.loganalytics.io/v1`):
  - `POST workspaces/{workspace_id}/query`: `alert_triage/api.py:LogAnalyticsClient.query` (called by `alert_triage/api.py:GraphClient.hunt` via `workspace().query` for Sentinel custom logs `..._CL`)
- **Microsoft Defender for Endpoint API** (`https://api.security.microsoft.com`):
  - `GET api/machines/{machine_id}`: `alert_triage/api.py:DefenderClient.machine` (called by `alert_triage/packet.py:enrich_device`, `alert_triage/tools/context.py:device_info`)
  - `GET api/files/{sha}`: `alert_triage/api.py:DefenderClient.file_info` (called by `alert_triage/packet.py:enrich_file`)
  - `GET api/ips/{ip}/stats`: `alert_triage/api.py:DefenderClient.ip_stats` (called by `alert_triage/packet.py:enrich_ip`)
  - `POST api/machines/{machine_id}/isolate`: `alert_triage/api.py:DefenderClient.isolate` (called by `alert_triage/contain.py:act`, `alert_triage/respond.py:plan`)
  - `POST api/machines/{machine_id}/unisolate`: `alert_triage/api.py:DefenderClient.release` (called by `alert_triage/contain.py:act`)
  - `POST api/machines/{machine_id}/runAntiVirusScan`: `alert_triage/api.py:DefenderClient.antivirus_scan` (called by `alert_triage/respond.py:run_scan`)
  - `POST api/machines/{machine_id}/StopAndQuarantineFile`: `alert_triage/api.py:DefenderClient.stop_and_quarantine` (called by `alert_triage/respond.py:quarantine_file`)
  - `GET api/machineactions/{action_id}`: `alert_triage/api.py:DefenderClient.machine_action` (called by `alert_triage/contain.py:wait_action`)
  - `GET api/machineactions`: `alert_triage/api.py:DefenderClient.machine_actions` (called by `alert_triage/respond.py:collect_view`)
- **External Threat Intelligence Feeds**:
  - MalwareBazaar (`POST https://mb-api.abuse.ch/api/v1/`): `alert_triage/tools/ti.py:ThreatIntel._hash`
  - URLhaus (`POST https://urlhaus-api.abuse.ch/v1/host/`): `alert_triage/tools/ti.py:ThreatIntel._domain`
  - AbuseIPDB (`GET https://api.abuseipdb.com/api/v2/check`): `alert_triage/tools/ti.py:ThreatIntel._ip`
  - GreyNoise (`GET https://api.greynoise.io/v3/community/{ip}`): `alert_triage/tools/ti.py:ThreatIntel._ip`
- **AI Model APIs**:
  - Azure AI Foundry (`AZURE_FOUNDRY_ENDPOINT`): `alert_triage/llm.py:AzureFoundryClient.ask`
  - Google Gemini: `alert_triage/llm.py:GeminiClient.ask`
- **Configuration and Policy Files**:
  - `config/playbooks/*.yaml` (`cloud.yaml`, `default.yaml`, `endpoint.yaml`, `identity.yaml`, `phishing.yaml`): `alert_triage/router.py:load_playbooks`
  - `config/kql/*.kql` (`device_logons.kql`, `inbox_rules.kql`, `network_connections.kql`, `powershell_activity.kql`, `signin_failures.kql`, `solorigate_dns.kql`): `alert_triage/tools/logs.py:LogTools.run`
  - `config/guardrails.yaml`: `alert_triage/guardrails.py:load`
  - `config/auto_resolve.yaml`: `alert_triage/autoresolve.py:run`
  - `config/containment_menu.yaml`: `alert_triage/checker.py:check`
  - `config/sla_policy.csv`: `alert_triage/metrics.py:compute`
  - `config/metrics_assumptions.csv`: `alert_triage/metrics.py:compute`
  - `config/watchlists/*.csv` (`admin_accounts.csv`, `crown_jewel_assets.csv`, `known_scanners.csv`, `vip_users.csv`): `alert_triage/tools/context.py:watchlists`
  - `config/opco_mapping.csv` (repository shared config): `alert_triage/tools/context.py:opco_for`
- **Inbox Datasets**:
  - `data/inbox/guide/GUIDE_Train.csv`, `data/inbox/guide/GUIDE_Test.csv`: `alert_triage/guide.py:load_guide`
  - `data/inbox/ledger/*.txt`: `alert_triage/ledger.py:load_inbox`

### Steps
Its four steps from ARCHITECTURE.md:

1. **Read alerts**
   - `alert_triage/pipeline.py:run`: builds clients via `alert_triage/pipeline.py:build_clients`.
   - `alert_triage/ingest.py:fetch`: queries Microsoft Graph for updated incidents using `alert_triage/api.py:GraphClient.incidents`.
   - `alert_triage/packet.py:build`: parses incidents into standardized incident packets, isolating attacker-supplied text.
   - `alert_triage/injection.py:scan_packet`: scans alert text and commands for prompt injection patterns.
   - `alert_triage/packet.py:save`: writes parsed packets to `data/packets/<safe_id>.json`.

2. **Check alert**
   - `alert_triage/pipeline.py:run`: iterates packets and delegates each to `alert_triage/triage.py:Triage.run_one`.
   - `alert_triage/router.py:route`: selects matching playbook from `config/playbooks/`.
   - `alert_triage/tools/logs.py:LogTools.run`: executes playbook KQL hunting queries over Graph / Log Analytics.
   - `alert_triage/tools/ti.py:ThreatIntel.lookup_all`: queries external threat intelligence feeds for indicators.
   - `alert_triage/tools/context.py:gather`: checks watchlists, opco mapping, and Defender machine metadata.
   - `alert_triage/tools/history.py:for_incident`: extracts historical verdicts for matching incident types from the local store.
   - `alert_triage/guardrails.py:evaluate`: runs pre-guardrail rule checks from `config/guardrails.yaml`.
   - `alert_triage/triage.py:Triage._verdict`: prompts LLM via `alert_triage/verdict.py:ask` and checks schema/facts via `alert_triage/checker.py:check` (falls back to `alert_triage/verdict.py:rules_only` if AI is absent or validation fails).
   - `alert_triage/guardrails.py:apply`: enforces post-guardrail safety constraints.
   - `alert_triage/triage.py:three_outcomes`: normalizes verdict into three triage categories.
   - `alert_triage/triage.py:Triage._store`: commits incident and verdict records to DuckDB (`incidents`, `verdicts`) and saves full analysis to `data/verdicts/<safe_id>.json`.

3. **Take action**
   - `alert_triage/pipeline.py:run`: executes configured automated actions:
     - `alert_triage/autoresolve.py:run`: auto-resolves or escalates matching lab incidents in Defender via `alert_triage/api.py:GraphClient.update_incident` and `alert_triage/api.py:GraphClient.add_comment`.
     - `alert_triage/respond.py:run`: executes automated scans and quarantines via `alert_triage/api.py:DefenderClient.antivirus_scan` and `alert_triage/api.py:DefenderClient.stop_and_quarantine`.
     - `alert_triage/respond.py:collect_view`: collects Defender action statuses via `alert_triage/api.py:DefenderClient.machine_actions` and writes `data/verdicts/<safe_id>.defender.json`.
     - `alert_triage/writeback.py:post_pending`: posts summary triage comments to Defender via `alert_triage/api.py:GraphClient.add_comment`.
   - Interactive human-approved actions handled through portal service `alert_triage/site.py:Site.do_POST`:
     - `alert_triage/close.py:act`: closes or escalates an incident in Defender via `alert_triage/api.py:GraphClient.update_incident`.
     - `alert_triage/contain.py:act`: isolates or releases a device via `alert_triage/api.py:DefenderClient.isolate` or `release`.
     - `alert_triage/autoresolve.py:reopen`: reopens an auto-resolved incident via `alert_triage/api.py:GraphClient.update_incident`.

4. **Update queue**
   - `alert_triage/pipeline.py:run`: runs post-triage queue synchronization and export steps:
     - `alert_triage/feedback.py:import_all`: imports human feedback and action audit records from `data/feedback/` into DuckDB.
     - `alert_triage/ledger.py:load_inbox` and `match_incidents`: matches lab incident ground-truth ledger entries.
     - `alert_triage/backtest.py:grade_lab`: evaluates accuracy scores against lab ground truth.
     - `alert_triage/metrics.py:write`: calculates SLA and MTTR metrics and writes `data/export/metrics.json`.
     - `alert_triage/export.py:export_all`: builds queue and summary aggregates and writes `data/export/triage_data.json`.
     - `alert_triage/report.py:build`: generates executive reports (`.docx` and `.pdf`) in `data/reports/`.
     - `alert_triage/pipeline.py:_write_last_run`: records run outcome and step statuses into `data/last_run.json`.

### Outputs
Files written under `data/`:
- `data/alert_triage.duckdb`: local state store (incidents, verdicts, runs, actions, feedback, ledger). *(Not read by dashboard)*
- `data/.run.lock`: process execution lock file. *(Not read by dashboard)*
- `data/last_run.json`: last pipeline run timestamp, steps, and status. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource.last_run` and `automation`)*
- `data/raw/<incident_id>.json`: raw incident payload from Graph API. *(Not read by dashboard)*
- `data/packets/<safe_id>.json`: preprocessed incident packet. *(Not read by dashboard)*
- `data/verdicts/<safe_id>.json`: full verdict, evidence, queries, and threat intel output. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource.case`)*
- `data/verdicts/<safe_id>.defender.json`: Defender remediation actions view. *(Read by `alert_triage/site.py:Site.incident`)*
- `data/cache/ti/<kind>_<key>.json`: disk cache for threat intel lookups. *(Not read by dashboard)*
- `data/feedback/feedback.jsonl`: analyst agree/disagree feedback and verdicts. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource._feedback`, `queue`, `case`)*
- `data/feedback/actions.jsonl`: audit trail of actions taken. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource.queue`, `case`)*
- `data/feedback/ask.jsonl`: log of ad-hoc analyst questions. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource.case`)*
- `data/export/triage_data.json`: public incident queue, totals, and verdict counts. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource.queue`, `case`)*
- `data/export/metrics.json`: computed operational, SLA, and effort metrics. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource.metrics`)*
- `data/export/backtest.json`: accuracy metrics on benchmark and lab datasets. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource.backtest`)*
- `data/reports/Alert_Triage_Report_*.*` (`.docx`, `.pdf`): executive summary reports. *(Read by `dashboard/src/dashboard/sources.py:AlertTriageSource.reports`)*
- `data/reports/Alert_Triage_Backtest_*.xlsx`: backtest Excel workbook. *(Not read by dashboard sources)*

### Actions that need a person
1. **Device Isolation / Release** (`isolate_device`, `release_device`):
   - Modifies host network isolation state in Defender for Endpoint via `DefenderClient.isolate` / `DefenderClient.release`.
   - Checked in `alert_triage/contain.py:act`: verifies `settings.contain` is enabled, checks device against `settings.lab_devices`, and verifies human confirmation via `body.get("confirm") is True` and header `X-Alert-Triage: contain` in `alert_triage/site.py:Site.do_POST` at `/api/contain`.
2. **Agree & Close / Escalate Incident in Defender** (`close_incident`, `escalate_incident`):
   - Updates status, classification, determination, and tags in Microsoft Graph via `GraphClient.update_incident` and adds an audit comment via `GraphClient.add_comment`.
   - Checked in `alert_triage/close.py:act`: verifies `settings.close` is enabled, and verifies human confirmation via `body.get("confirm") is True` and header `X-Alert-Triage: close` in `alert_triage/site.py:Site.do_POST` at `/api/close`.
3. **Reopen an Automatically Resolved Incident** (`reopen`):
   - Sets incident status back to `inProgress` in Defender via `GraphClient.update_incident`.
   - Checked in `alert_triage/autoresolve.py:reopen`: requires human confirmation via `body.get("confirm") is True` and header `X-Alert-Triage: reopen` in `alert_triage/site.py:Site.do_POST` at `/api/reopen`.
4. **Automated changes (toggled by settings, execute without human click)**:
   - Automated incident resolve/escalate: `alert_triage/autoresolve.py:run` executes if `settings.auto_resolve` is enabled.
   - Automated response scans/quarantines: `alert_triage/respond.py:run` executes if `settings.respond` is enabled (and automated isolation if `settings.auto_isolate` is enabled).
   - Automated pilot comment writeback: `alert_triage/writeback.py:post_pending` executes if `settings.writeback` is enabled.

### Settings
Environment variables read by `alert_triage/config.py:load_settings` (target setting names per ARCHITECTURE.md; currently read via legacy agent prefix in `config.py`):
- `TRIAGE_DATA_DIR`: directory for agent databases, exports, and caches (default: `./data`)
- `TRIAGE_LOG_DIR`: directory for daily execution log files (default: `./logs`)
- `TRIAGE_TENANT_ID`: Entra ID tenant ID for Microsoft Graph and Defender APIs (default: `None`)
- `TRIAGE_CLIENT_ID`: Entra ID application client ID (default: `None`)
- `TRIAGE_CLIENT_SECRET`: Entra ID application client secret (default: `None`)
- `GEMINI_API_KEY`: primary Google Gemini API key (default: `None`)
- `GEMINI_API_KEY_2` ... `GEMINI_API_KEY_9`: rollover Gemini API keys (default: `()`)
- `GEMINI_MODEL`: primary Gemini model name (default: `"gemini-3.5-flash-lite"`)
- `GEMINI_FALLBACK_MODEL`: fallback Gemini model name (default: `"gemini-3.1-flash-lite"`)
- `GEMINI_RPM`: rate limit for Gemini requests per minute (default: `15`)
- `TRIAGE_GEMINI_DAILY_CAP`: maximum Gemini requests per day (default: `1500`)
- `AI_PROVIDER`: provider selection `"auto"` | `"azure"` | `"gemini"` (default: `"auto"`)
- `AZURE_FOUNDRY_ENDPOINT`: Azure AI Foundry endpoint URL (default: `None`)
- `AZURE_FOUNDRY_API_KEY`: Azure AI Foundry API key (default: `None`)
- `AZURE_FOUNDRY_DEPLOYMENT`: Azure AI Foundry deployment name (default: `None`)
- `AZURE_FOUNDRY_RPM`: rate limit for Azure AI Foundry calls per minute (default: `60`)
- `AZURE_FOUNDRY_REASONING_EFFORT`: reasoning effort for reasoning models (`"low"`, `"minimal"`, `"medium"`, `"high"`, `"off"`) (default: `"low"`)
- `AZURE_FOUNDRY_DAILY_CAP`: maximum Azure AI Foundry calls per day (default: `1500`)
- `ABUSECH_AUTH_KEY`: API authentication key for MalwareBazaar and URLhaus (default: `None`)
- `OTX_API_KEY`: AlienVault OTX API key (default: `None`)
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key (default: `None`)
- `GREYNOISE_API_KEY`: GreyNoise API key (default: `None`)
- `TRIAGE_LOOKBACK_DAYS`: lookback window in days for initial incident ingest (default: `30` in `load_settings`, `14` in dataclass)
- `TRIAGE_WINDOW_HOURS`: time window in hours (+/- around alert time) for hunting queries (default: `24`, clamped 1-72)
- `TRIAGE_MAX_QUERIES`: maximum hunting queries per incident (default: `12`)
- `TRIAGE_MAX_ROWS`: maximum rows fetched per hunting query (default: `500`, capped at 1000)
- `TRIAGE_AI_ROWS`: maximum query rows presented in the prompt to the AI (default: `15`)
- `TRIAGE_MAX_TI_LOOKUPS`: maximum threat intel lookups per incident (default: `20`)
- `TRIAGE_WRITEBACK`: flag to enable posting summary triage comments to Defender (default: `False`)
- `TRIAGE_CONTAIN`: flag to enable human-approved device isolation in Defender (default: `False`)
- `TRIAGE_CLOSE`: flag to enable human-approved incident closing in Defender (default: `False`)
- `TRIAGE_AUTO_RESOLVE`: flag to enable automated incident closing/escalating (default: `False`)
- `TRIAGE_RESPOND`: flag to enable automated response playbook actions (default: `False`)
- `TRIAGE_AUTO_ISOLATE`: flag to allow automated response playbooks to isolate devices (default: `False`)
- `TRIAGE_ASK_DAILY_CAP`: daily limit on ad-hoc questions asked to AI (default: `100`)
- `TRIAGE_SCAN_TYPE`: antivirus scan type requested by response playbook (`"Full"` or `"Quick"`) (default: `"Full"`)
- `TRIAGE_THREAT_INTEL_DIR`: path to Threat Intel Agent folder (default: `"../threat_intel"`)
- `TRIAGE_LAB_DEVICES`: comma-separated names of lab devices eligible for containment actions (default: `"opca-wks-01,opcc-wks-01"`)
- `TRIAGE_LAB_ALERT_TITLES`: pipe-separated prefixes of alert titles treated as lab exercises (default: `("sign-ins from ips that attempt sign-ins to disabled accounts", "malicious inbox rule", "solorigate network beacon")`)
- `TRIAGE_SENTINEL_WORKSPACE_ID`: explicit Log Analytics workspace ID for Sentinel queries (default: `None`)

### Reads from other agents
- `agents/threat_intel/data/fix/plan.json`: read by `alert_triage/fixlink.py:fixes_for` to display software remediation options for affected incident devices.
- `agents/threat_intel/data/fix/state.json`: read by `alert_triage/fixlink.py:fixes_for` to show the current approval/execution status of device fixes.
- Shared repository configuration: `config/opco_mapping.csv` is read by `alert_triage/tools/context.py:opco_for`.

### Open questions
1. **Setting default discrepancy for lookback days**: In `alert_triage/config.py`, the dataclass default for `lookback_days` is `14` (line 102), but `load_settings` specifies a default of `30` (line 244).
2. **Unused AlienVault OTX key**: `OTX_API_KEY` is defined in `Settings` and reported in `describe()`, but `alert_triage/tools/ti.py` contains no lookup implementation for AlienVault OTX.
3. **Private cross-agent folder reads**: `alert_triage/fixlink.py` directly opens `threat_intel_dir / "data" / "fix" / "plan.json"` and `state.json`, reading private files across module boundaries instead of consuming a public contract from `data/out/` or querying the Fix Centre service.
4. **Hardcoded legacy service port/variable**: `alert_triage/fixlink.py` hardcodes `http://127.0.0.1:8700/fix` under a variable name using the legacy agent acronym.
5. **Verdict transformation alters outcome handling**: `alert_triage/triage.py:three_outcomes` re-maps `benign_positive` verdicts to `likely_false_positive` (storing the original in `ai_said`). However, downstream modules `alert_triage/close.py` and `alert_triage/autoresolve.py` define distinct logic branches and determination mappings specifically for `benign_positive` that may be bypassed.
6. **Automated isolation capability**: When `settings.auto_isolate` is set, `alert_triage/respond.py:plan` schedules device isolation without requiring interactive human confirmation.
