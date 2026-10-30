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
| Env `UC1_*`, `UC3_*`, `UC4_*`, `PORTAL_UC*` | `THREAT_INTEL_*`, `ATTACK_*`, `VULN_*`, `TRIAGE_*`, `REMEDIATION_*`, `DASHBOARD_*` (old names accepted with a warning for one release) |
| Report files `UC1_*`, `UC3_*` | named after the agent |

## Phases

Phases 0 to 3 change the layout, not the behaviour, and are done one at a time in one place. Phase 4 is where the
four agents are worked on in parallel, each in its own chat and branch.

| Phase | What | Status |
|---|---|---|
| 0. Safety net | Record today's outputs (dashboard JSON, parquet columns, report names) and add smoke tests that compare against them, plus a dashboard test that loads every page's API | not started |
| 1. Rename and move | New folders, package names, routes, labels, env names with aliases, Start/Stop scripts. `git mv` so history survives. Phase 0 tests still pass | not started |
| 2. infra_core | Move the duplicated code into `shared/infra_core`; merge the duplicated catalogs | not started |
| 3. Split | Attack Detection out of Threat Intel; fix engine to `shared/remediation`; `contracts/`; dashboard adapters and progress events | not started |
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
- `uc1link.py` reads the Threat Intel folder's private fix plan; replace it with the Fix Centre in phase 3.
