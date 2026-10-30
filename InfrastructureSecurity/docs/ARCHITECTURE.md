# Infrastructure Security: architecture and work guide

This is the agreed target structure for the Infrastructure Security module and the order in which we get there.
Every chat or person working on an agent reads this first. Keep it up to date: when a phase or an agent is done,
update the status tables below in the same change.

We never say UC1, UC3 or UC4. We say **Threat Intel Agent**, **Vulnerability Agent**, **Attack Detection Agent** and
**Alert Triage Agent**. The old folder names only appear in the "comes from" notes below until the move is done.

## The four agents

| Agent | Its four steps (from the architecture slide) | Folder |
|---|---|---|
| Threat Intel Agent | Gather news → Affects us? → Fix steps → Write report | `agents/threat_intel` |
| Vulnerability Agent | Extract → Validate → Score & report → Fix advice | `agents/vulnerability` |
| Attack Detection Agent | Search devices → Connect evidence → How to resolve → Publish | `agents/attack_detection` |
| Alert Triage Agent | Read alerts → Check alert → Take action → Update queue | `agents/alert_triage` |

Besides the agents there are two shared parts and the website:

| Part | What it is | Folder |
|---|---|---|
| infra_core | Reusable library: Defender sign-in and API client, AI clients, settings, run lock, progress events, report styling. No security logic. | `shared/infra_core` |
| Fix Centre | Runs fixes on devices after a person approves them. Three agents send it fix proposals, so no agent owns it. | `shared/remediation` |
| Dashboard | The website. One page folder and one backend adapter per agent. | `dashboard` |

## Target layout

```
InfrastructureSecurity/
├── agents/
│   ├── threat_intel/
│   ├── vulnerability/
│   ├── attack_detection/
│   └── alert_triage/
├── shared/
│   ├── infra_core/
│   └── remediation/
├── dashboard/
├── contracts/          JSON schemas of what each agent publishes
├── config/             settings shared by everyone (opco_mapping.csv)
├── docs/ARCHITECTURE.md
├── Start_Infrastructure_Security.cmd
└── Stop_Infrastructure_Security.cmd
```

Every agent has the same skeleton:

```
agents/<agent>/
├── README.md           purpose, inputs, the four steps, outputs, actions that need approval
├── pyproject.toml      depends on infra_core (path dependency); its own .venv
├── config/             only this agent's settings
├── src/<agent>/
│   ├── __main__.py     check | run | live-test (| serve for Alert Triage)
│   ├── pipeline.py     the four steps, in order
│   ├── publish.py      the ONLY code that writes data/out/
│   └── ...             private logic
├── tests/
└── data/               gitignored; data/out/ is public, everything else is private
```

### agents/threat_intel

```
config/      feeds.csv, risk_policy.csv, tech_watchlist.example.csv, metrics_assumptions.csv, kql/cve_exposure.kql
src/threat_intel/
  feeds/                 ← uc1/feeds/
  analyse.py             ← uc1/analyse.py
  prompts.py, schemas.py ← uc1/ai/ (the AI clients go to infra_core)
  guard.py               ← uc1/ai/guard.py
  derive.py, inventory.py, exposure.py, scoring.py, fix_advice.py, alerts.py, report.py,
  spotcheck.py, metrics.py, demo.py, store.py   ← uc1/ same names
  publish.py             ← uc1/dashboard.py
scripts/check_not_in_defender.py
data/out/    threats.json, iocs.json, status.json
```

### agents/attack_detection

```
config/      kql/bh_*.kql, kql/ioc_{hash,ip,domain,url}.kql, ioc_allowlist.csv, lab_test_iocs.csv
src/attack_detection/
  pipeline.py            ← attack_check() in uc1/pipeline.py
  hunting/               ← uc1/hunting/ (runner, templates; validator goes to infra_core)
  correlate.py           ← uc1/correlate.py
  resolve.py             ← uc1/resolve.py
  report.py              ← uc1/attack_report.py
  store.py, publish.py
scripts/lab/Invoke-AttackLabTest.ps1   ← scripts/lab/Invoke-UC1LabTest.ps1
data/out/    findings.json, status.json
reads        threat_intel/data/out/iocs.json
```

### agents/vulnerability

```
config/      sla_policy.csv, assumptions.csv, fix_catalog.csv, setting_fix_catalog.csv (one merged copy)
src/vulnerability/
  extract.py, posture.py, load.py, transform.py, quality.py, report.py, excel.py,
  metrics.py, proof.py, status.py, retention.py   ← uc3/ same names
  pipeline.py            ← uc3/pipeline.py
  fix_guide.py           ← uc3/ai/fixes.py
  publish.py             ← uc3/publish.py + uc3/dashboard/build.py
lab/                     ← uc3/lab/
data/lake/, data/raw/    private
data/out/    vulnerabilities.parquet, exposure.json, fix_proposals.json, status.json
```

### agents/alert_triage

```
config/      playbooks/, kql/, watchlists/, guardrails.yaml, auto_resolve.yaml, containment_menu.yaml,
             verdict.schema.json, sla_policy.csv, metrics_assumptions.csv
src/alert_triage/
  read/      ingest.py, packet.py, injection.py                        "Read alerts"
  check/     router.py, triage.py, verdict.py, checker.py, guardrails.py, tools/   "Check alert"
  act/       respond.py, contain.py, close.py, autoresolve.py, writeback.py        "Take action"
  queue/     export.py, feedback.py, ledger.py, labels.py              "Update queue"
  ask.py, backtest.py, guide.py, metrics.py, report.py, store.py
  service.py             ← uc4/site.py (button clicks from the website)
data/out/    queue.json, verdicts/, status.json
reads        vulnerability/data/out/fix_proposals.json via the Fix Centre (replaces uc4/uc1link.py)
```

### shared/infra_core

```
defender_auth.py     ← uc1/auth.py, uc3/auth.py, uc4/auth.py
defender_client.py   ← uc1/api_client.py, uc3/api_client.py, uc4/api.py
ai/azure.py, ai/gemini.py   ← uc1/ai/*_client.py, uc3/ai/azure.py, uc3/ai/gemini.py, uc4/llm.py
kql_guard.py         ← uc1/hunting/validator.py, uc4/validator.py
settings.py          reads the one suite .env
run_lock.py          one run at a time per agent
progress.py          standard step events the dashboard follows
docstyle.py          ← the three identical docstyle.py copies
```

### shared/remediation (Fix Centre)

```
plan.py, state.py, runner.py, executors.py   ← uc1/fix/
assets/fix_app.ps1                           ← uc1/fix_assets/uc1_fix_app.ps1
service.py                                   ← the fix part of uc1/site.py
```

### dashboard

```
config/device_names.csv
src/dashboard/                 ← Unified_Cyber_Portal/src/portal/
  agents/threat_intel.py, vulnerability.py, attack_detection.py, alert_triage.py
                               the ONLY code that reads an agent's data/out/ (alert_triage.py ← uc4proxy.py)
  remediation.py               ← fixproxy.py
  runs.py, runner.py, summary.py, notifications.py, activity.py, audit.py, helpbot.py, helpready.py,
  services.py, app.py, auth.py, config.py
web/src/
  app/                         App.tsx, shells, Home, Login
  shared/                      ui components, kit, Chart, lib/
  agents/threat-intel/         ← pages/uc1/ThreatNews, ThreatDetail, timeline
  agents/attack-detection/     ← pages/uc1/Hunting
  agents/vulnerability/        ← pages/uc3/Vulnerabilities, VulnDetail, DataQuality
  agents/alert-triage/         ← pages/Respond, RespondCase
  agents/fixes/                ← pages/uc3/FixCentre, FixProgress, FixHistory, AttackResponses
```

## Rules

1. **No agent imports another agent's code.** Enforced with `import-linter` once the move is done.
2. **Data crosses between parts only through `data/out/`.** Each file has a `schema_version` and a schema in
   `contracts/`. A reader treats missing or older data as "no information", never as an error.
3. **Agents propose fixes; the Fix Centre runs them.** Nothing changes on a device without a person's approval.
4. **infra_core stays small and generic.** Security logic belongs in its agent. A change to infra_core must pass
   every agent's tests.
5. **The dashboard reads an agent only through its adapter** in `dashboard/src/dashboard/agents/`, and follows runs
   through the standard progress events, not by parsing an agent's own log lines.
6. **Each agent has its own .venv, data folder, run lock and process.** A crash in one stays in that one.
7. **Only parts where people click buttons run a service:** the Fix Centre (8700) and Alert Triage (8900). The
   dashboard is 8800. The other agents start, run and exit.
8. **Working on one agent means touching only** `agents/<agent>/`, its `web/src/agents/<agent>/` pages and its
   dashboard adapter. A needed change to infra_core, contracts, the Fix Centre or the dashboard shell is its own
   small change, described in the agent's notes below, and agreed before it lands.

## Naming

| Old | New |
|---|---|
| Routes `/uc1`, `/uc1/hunts`, `/uc3`, `/respond` | `/threat-intel`, `/attack-detection`, `/vulnerabilities`, `/alert-triage`, `/fixes` |
| Env `UC1_*`, `UC3_*`, `UC4_*`, `PORTAL_UC*` | `THREAT_INTEL_*`, `ATTACK_*`, `VULN_*`, `TRIAGE_*`, `REMEDIATION_*`, `DASHBOARD_*` (old names accepted with a warning for one release). The sign-in settings `PORTAL_LOGIN_URL`, `PORTAL_AUTH_DIR` etc. stay: the sign-in page shares them |
| Report files `UC1_*`, `UC3_*` | named after the agent |
| Run keys `uc1`, `uc3`, `uc4`, `attack` | `threat_intel`, `vulnerability`, `alert_triage`, `attack_detection`. Runs saved under the old keys are still read (`OLD_KEYS` in `dashboard/src/dashboard/runs.py`) |
| Databases `data/uc1.duckdb` etc. | `data/<agent>.duckdb`; the Start script renames an old file once |

**Names that stay on purpose**, because they are names of real things outside the code: the lab objects Defender has
already seen (`UC1LabTest`, the `UC4LAB` ledger lines), the Azure app registrations (`UC1-Hunting-Agent-Lab`,
`UC1-ThreatIntel-PoC`, `UC4-Triage-Agent-Lab`) and the resource group `rg-uc3-lab`. Rename them in Azure first, then here.

## Phases

Phases 0 to 3 change the layout, not the behaviour, and are done one at a time in one place. Phase 4 is where the
four agents are worked on in parallel, each in its own chat and branch.

| Phase | What | Status |
|---|---|---|
| 0. Safety net | `tests/`: every module imports, every command line answers, each agent rebuilds its dashboard data from a copy of its database, and every read-only dashboard API keeps its shape (`tests/snapshots/`, keys and types only, no data). Run: `<dashboard venv>\Scripts\python.exe -m pytest tests -q` from this folder. When a phase moves things, update `tests/layout.py` only | done |
| 1. Rename and move | `agents/threat_intel`, `agents/vulnerability`, `agents/alert_triage` and `dashboard` with their packages; website pages in `web/src/agents/<agent>/`; routes and API paths by agent name; service headers `X-Threat-Intel`, `X-Alert-Triage`; databases and logs named after the agent; the Start script moves data out of the old folders once. Phase 0 tests pass with only the run, report and summary keys renamed | done |
| 2. infra_core | `shared/infra_core` on every part's path (`infra_core.pth`, written by the Start script); `docstyle.py` lives there once; `infra_core.settings.env()` reads settings by agent name (`THREAT_INTEL_*`, `VULN_*`, `TRIAGE_*`, `DASHBOARD_*`) and still accepts the old ones (each config's `OLD_NAMES`); the dashboard reads each agent through `dashboard/src/dashboard/agents/<agent>.py`. Also fixed: agents read the repository-root `.env` again (broken by the phase 1 move). Left for later: Defender sign-in and API clients and the AI clients still have one copy per agent (they differ; merge them in the agent chats), the two fix catalogues (phase 3, after `docs/fix_catalog_diff.md`) | done |
| 3. Split | `agents/attack_detection` is its own agent with its own database and `.venv`: each run loads Threat Intel's `data/out/hunt_inputs.json`, hunts, connects evidence, writes resolution steps and its report, publishes `data/out/findings.json`, then runs `python -m threat_intel attack-import` (re-score, alerts, dashboard data, fix proposals and auto-fix stay in Threat Intel). Threat Intel no longer hunts; its correlate step makes exposure findings only. History from before the split was copied once (`python -m attack_detection import-history`). Test: `tests/test_attack_round_trip.py`. **Left for later** (not needed for the agents to be independent): the fix engine still lives in `agents/threat_intel/fix/` (move to `shared/remediation`), the two fix catalogues stay separate (execution list vs advice cards, see `docs/fix_catalog_diff.md`), a contract test against `contracts/`, standard run-progress events | done (structure) |
| 4. Make each agent work | One chat per agent, in parallel (see below) | not started |

## Working on one agent (phase 4)

1. **Spec.** Write the agent's README: inputs (which Defender, Sentinel or feed APIs), the four steps, outputs
   (`data/out/` and its contract), actions that need approval.
2. **Baseline.** Run `check` and `live-test` against the lab tenant. Record each step as works, partly works or
   broken in the agent's notes below. That list is the backlog.
3. **Fix step by step,** in pipeline order, with a test per step (recorded API responses, no live tenant needed).
4. **Prove the contract.** Contract test: `data/out/` matches its schema; the dashboard adapter test passes.
5. **End to end** in the dashboard: run, see results, approve an action, see it verified in Defender.

An agent is **done** when all four steps pass on the lab tenant, its tests pass on their own, its output matches its
contract, and the other agents' tests did not have to change.

## Agent notes

Each chat keeps its agent's section current: baseline results, what is fixed, open questions, and any change it needs
outside its own folder.

### Threat Intel Agent
- Open decision: `correlate.py` runs in both the Threat Intel run and the attack check today. Plan: it moves to Attack
  Detection, and Threat Intel answers "Affects us?" with `exposure.py` alone. Confirm during phase 3.

### Vulnerability Agent
- `fix_catalog.csv` and `setting_fix_catalog.csv` differ between the Threat Intel and Vulnerability folders today;
  merge them in phase 2.

### Attack Detection Agent
- Today it lives inside the Threat Intel folder (`hunting/`, `correlate.py`, `attack_report.py`, `resolve.py`).

### Alert Triage Agent
- `fixlink.py` (was `uc1link.py`) reads the Threat Intel folder's private fix plan; replace it with the Fix Centre in
  phase 3. Its key in the triage context is now `fixes` (was `uc1`); verdicts saved before phase 1 still say `uc1`.

### Cross-folder reads (found 31 Oct 2026)

| Reader file:line | What it reads (path) | Owner folder |
|---|---|---|
| `agents/threat_intel/src/threat_intel/exposure.py:95` | `data/dashboard/dashboard_data.json` (via `vuln_agent_dir`) | `agents/vulnerability` |
| `agents/alert_triage/src/alert_triage/fixlink.py:26` | `data/fix/plan.json` (via `threat_intel_dir`) | `agents/threat_intel` |
| `agents/alert_triage/src/alert_triage/fixlink.py:27` | `data/fix/state.json` (via `threat_intel_dir`) | `agents/threat_intel` |
| `agents/vulnerability/src/vulnerability/pipeline.py:142` | `.venv` Python executable to invoke `fixes fix-refresh` (via `fix_engine_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/activity.py:81` | `data/fix/state.json` (via `threat_intel_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/app.py:64` | `data/fix/plan.json` (via `threat_intel_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/app.py:65` | `data/fix/state.json` (via `threat_intel_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/app.py:363` | `data/reports/` (via `threat_intel_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/app.py:363` | `data/reporting/` (via `vulnerability_dir`) | `agents/vulnerability` |
| `dashboard/src/dashboard/app.py:364` | `data/reports/` (via `alert_triage_dir`) | `agents/alert_triage` |
| `dashboard/src/dashboard/notifications.py:95` | `data/feedback/actions.jsonl` (via `alert_triage_dir`) | `agents/alert_triage` |
| `dashboard/src/dashboard/runs.py:846` | `data/fix/state.json` (via `fix_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/runs.py:847` | `data/fix/plan.json` (via `fix_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/runs.py:1004` | `data/dashboard/dashboard_data.json` (via `uc_dirs[uc]`) | `agents/threat_intel`, `agents/vulnerability` |
| `dashboard/src/dashboard/services.py:64` | `data/fix/.fix.lock` (via `threat_intel_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/fixproxy.py:137` | `.venv` Python executable to start `threat_intel serve` (via `threat_intel_dir`) | `agents/threat_intel` |
| `dashboard/src/dashboard/triageproxy.py:112` | `.venv` Python executable to start `alert_triage serve` (via `alert_triage_dir`) | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/threat_intel.py:21` | `data/dashboard/dashboard_data.json` | `agents/threat_intel` |
| `dashboard/src/dashboard/agents/threat_intel.py:25` | `data/last_run.json` | `agents/threat_intel` |
| `dashboard/src/dashboard/agents/threat_intel.py:29` | `data/dashboard/clues.json` | `agents/threat_intel` |
| `dashboard/src/dashboard/agents/threat_intel.py:36` | `data/dashboard/site_data.json` | `agents/threat_intel` |
| `dashboard/src/dashboard/agents/threat_intel.py:53` | `data/dashboard/threat_matches.json` | `agents/threat_intel` |
| `dashboard/src/dashboard/agents/threat_intel.py:113` | `data/reports/*.*` | `agents/threat_intel` |
| `dashboard/src/dashboard/agents/vulnerability.py:23` | `data/reporting/{name}.parquet` | `agents/vulnerability` |
| `dashboard/src/dashboard/agents/vulnerability.py:43` | `data/status/last_run.json` | `agents/vulnerability` |
| `dashboard/src/dashboard/agents/vulnerability.py:47` | `data/dashboard/dashboard_data.json` | `agents/vulnerability` |
| `dashboard/src/dashboard/agents/vulnerability.py:97` | `data/reporting/ai_fixes.json` | `agents/vulnerability` |
| `dashboard/src/dashboard/agents/vulnerability.py:109` | `data/reporting/*.*` | `agents/vulnerability` |
| `dashboard/src/dashboard/agents/alert_triage.py:83` | `data/reports/Alert_Triage_Report_*.*` | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/alert_triage.py:89` | `data/last_run.json` | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/alert_triage.py:92` | `data/feedback/feedback.jsonl` | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/alert_triage.py:98` | `data/export/triage_data.json` | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/alert_triage.py:103` | `data/feedback/actions.jsonl` | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/alert_triage.py:129` | `data/verdicts/{incident_id}.json` | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/alert_triage.py:139` | `data/feedback/ask.jsonl` | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/alert_triage.py:156` | `data/export/metrics.json` | `agents/alert_triage` |
| `dashboard/src/dashboard/agents/alert_triage.py:159` | `data/export/backtest.json` | `agents/alert_triage` |

