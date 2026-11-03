# Infrastructure Security: architecture and work guide

This is the agreed target structure for the Infrastructure Security module and the order in which we get there.
Every chat or person working on an agent reads this first. Keep it up to date: when a phase or an agent is done,
update the status tables below in the same change.

We never use the old use-case numbers. We say **Threat Intel Agent**, **Vulnerability Agent**, **Attack Detection Agent** and
**Alert Triage Agent**. The old folder names only appear in the "comes from" notes below, to show where code came from.
Phases 0 to 3 are done (merged 31 Oct 2026); the layout below is the target, and the phase table says what is still
left of it.

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
  feeds/
  analyse.py
  prompts.py, schemas.py
  guard.py
  derive.py, inventory.py, exposure.py, scoring.py, fix_advice.py, alerts.py, report.py,
  spotcheck.py, metrics.py, demo.py, store.py
  publish.py
scripts/check_not_in_defender.py
data/out/    threats.json, iocs.json, status.json (nothing for the Attack Detection Agent)
```

### agents/attack_detection

```
config/      kql/bh_*.kql (behaviour hunts only; the IOC sweeps are the Threat Intel Agent's)
src/attack_detection/
  pipeline.py
  hunting/
  correlate.py
  resolve.py
  report.py
  store.py, publish.py
data/out/    findings.json, status.json
reads        nothing from Threat Intel: devices and the attack 12 CVE list come from Defender
```

### agents/vulnerability

```
config/      sla_policy.csv, assumptions.csv, fix_catalog.csv, setting_fix_catalog.csv (one merged copy)
src/vulnerability/
  extract.py, posture.py, load.py, transform.py, quality.py, report.py, excel.py,
  metrics.py, proof.py, status.py, retention.py
  pipeline.py
  fix_guide.py
  publish.py
lab/
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
  service.py
data/out/    queue.json, verdicts/, status.json
reads        vulnerability/data/out/fix_proposals.json via the Fix Centre
```

### shared/infra_core

```
defender_auth.py
defender_client.py
ai/azure.py, ai/gemini.py
kql_guard.py
settings.py          reads the one suite .env
run_lock.py          one run at a time per agent
progress.py          standard step events the dashboard follows
docstyle.py          ← the three identical docstyle.py copies
style.py             the one writing voice (security architect, Defender terms) every agent's AI prompts add
```

### shared/remediation (Fix Centre)

```
plan.py, state.py, runner.py, executors.py
assets/fix_app.ps1
service.py
```

### dashboard

```
config/device_names.csv
src/dashboard/                 ← Unified_Cyber_Portal/src/portal/
  agents/threat_intel.py, vulnerability.py, attack_detection.py, alert_triage.py
                               the ONLY code that reads an agent's data/out/ (alert_triage.py
  remediation.py               ← fixproxy.py
  runs.py, runner.py, summary.py, notifications.py, activity.py, audit.py, helpbot.py, helpready.py,
  services.py, app.py, auth.py, config.py
web/src/
  app/                         App.tsx, shells, Home, Login
  shared/                      ui components, kit, Chart, lib/
  agents/threat-intel/
  agents/attack-detection/
  agents/vulnerability/
  agents/alert-triage/         ← pages/Respond, RespondCase
  agents/fixes/
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

## Remediation decisions

Approve appears only where the agent has a vetted move (`fix_catalog.csv`, `setting_fix_catalog.csv`, scan-and-clean).
Otherwise the card shows No automated fix and Hand over to IT. Handed-over items show With IT for manual fix, and
items the agent tried and could not remediate show Agent could not remediate. Both close with Mark as fixed manually.
Remediations cannot be deferred; older deferred rows show as Proposed. The full list and reasons are in
[MANUAL_REMEDIATION.md](MANUAL_REMEDIATION.md).

## Sharing data in the team

`data/` and `logs/` are never in git (tenant data). To give teammates the same data, one person exports a snapshot and
the others import it, with Infrastructure Security stopped:

```
python tools\snapshot.py export [--logs] [--with-guide]   -> snapshots\infra_<time>_<user>.zip
python tools\snapshot.py show <file.zip>
python tools\snapshot.py import <file.zip>                 old data kept as data.before-import-<time>
```

A snapshot holds every agent's `data/` and the dashboard's run history; never `.env`, sign-in accounts or session
keys, feed caches or lock files, and the 400 MB GUIDE database only with `--with-guide`. Share it through private team
storage, not git. After an import, nobody else should run the agents until the next snapshot, or the copies drift.
Step-by-step guide for the team: `docs/SHARING_DATA.md`.

## Naming

The agents are named Threat Intel, Vulnerability, Attack Detection and Alert Triage everywhere: folders, routes,
settings (`THREAT_INTEL_*`, `DEFENDER_*`, `VULN_*`, `TRIAGE_*`, `DASHBOARD_*`), run keys, databases and report files.
The old use-case names and their setting-name fallbacks were removed on 31 Oct 2026; nothing reads them any more.

**One name stays on purpose** because it is a real Azure object: the lab resource group `rg-uc3-lab` (the
`FIX_RESOURCE_GROUP` default). Azure can't rename a resource group; move the VMs to a new group, then change it here.
The lab markers are `AttackLabTest` (attack test), `TRIAGELAB` (alert-triage ledger lines) and the Sentinel rule
titles `Alert Triage Lab - ...`.

## Phases

Phases 0 to 3 change the layout, not the behaviour, and are done one at a time in one place. Phase 4 is where the
four agents are worked on in parallel, each in its own chat and branch.

| Phase | What | Status |
|---|---|---|
| 0. Safety net | `tests/`: every module imports, every command line answers, each agent rebuilds its dashboard data from a copy of its database, and every read-only dashboard API keeps its shape (`tests/snapshots/`, keys and types only, no data). Run: `<dashboard venv>\Scripts\python.exe -m pytest tests -q` from this folder. When a phase moves things, update `tests/layout.py` only | done |
| 1. Rename and move | `agents/threat_intel`, `agents/vulnerability`, `agents/alert_triage` and `dashboard` with their packages; website pages in `web/src/agents/<agent>/`; routes and API paths by agent name; service headers `X-Threat-Intel`, `X-Alert-Triage`; databases and logs named after the agent; the Start script moves data out of the old folders once. Phase 0 tests pass with only the run, report and summary keys renamed | done |
| 2. infra_core | `shared/infra_core` on every part's path (`infra_core.pth`, written by the Start script); `docstyle.py` lives there once; `infra_core.settings.env()` reads settings by agent name (`THREAT_INTEL_*`, `VULN_*`, `TRIAGE_*`, `DASHBOARD_*`) and still accepts the old ones (each config's `OLD_NAMES`); the dashboard reads each agent through `dashboard/src/dashboard/agents/<agent>.py`. Also fixed: agents read the repository-root `.env` again (broken by the phase 1 move). Left for later: Defender sign-in and API clients and the AI clients still have one copy per agent (they differ; merge them in the agent chats), the two fix catalogues (phase 3, after `docs/fix_catalog_diff.md`) | done |
| 3. Split | `agents/attack_detection` is its own agent with its own database and `.venv`: each run loads Threat Intel's `data/out/hunt_inputs.json`, hunts, connects evidence, writes resolution steps and its report, publishes `data/out/findings.json`, then runs `python -m threat_intel attack-import` (re-score, alerts, dashboard data, fix proposals and auto-fix stay in Threat Intel). Threat Intel no longer hunts; its correlate step makes exposure findings only. History from before the split was copied once (`python -m attack_detection import-history`). Test: `tests/test_attack_round_trip.py`. **Left for later** (not needed for the agents to be independent): the fix engine still lives in `agents/threat_intel/fix/` (move to `shared/remediation`), the two fix catalogues stay separate (execution list vs advice cards, see `docs/fix_catalog_diff.md`), a contract test against `contracts/`, standard run-progress events | done (structure) |
| 4. Make each agent work | One chat per agent, driven by hand by a person who learns the agent and decides every change (see below) | not started |

## Working on one agent (phase 4)

Phase 4 is done by hand, not automated: in each agent's chat a person first understands how the agent works today,
then decides what to change. Claude explains, runs and edits when asked; the person decides. The same seven steps
for every agent:

1. **Understand.** Ask for a walkthrough before touching anything: the command that starts it, the four steps in
   order, which file does each step, which Defender, Graph or feed APIs it calls, what it keeps privately and what it
   publishes in `data/out/`, and which dashboard page shows what. Write a one-page "how it works today" in the agent's
   README.
2. **Watch it run.** `check`, then a real `run` against the lab. Follow it on the dashboard's run page, then open its
   `data/out/` files and its pages. Record each of the four steps in the agent's notes below: works, partly works,
   broken or not sure, with what you saw.
3. **Make it happen on purpose.** An agent with nothing to find proves nothing. Use the lab to create something it
   must catch, then check that it does:

   | Agent | Lab trigger |
   |---|---|
   | Vulnerability | old apps and weak settings on the lab VMs (`agents/vulnerability/lab/`) |
   | Threat Intel | a threat that names software installed on the lab VMs; the TEST indicators of `lab_test_iocs.csv` |
   | Attack Detection | `agents/attack_detection/scripts/lab/Test-01-…` to `Test-12-….ps1`, run from Azure Cloud Shell |
   | Alert Triage | lab incidents from the ledger tests (`TRIAGELAB` lines), whose right answers are known |

4. **Compare to the promise.** Hold what you saw against what the agent should do (the four steps above and the
   overview deck). The gaps are the backlog: write them in the agent's notes, in the order you choose.
5. **Change one thing at a time.** Small change, ask for the diff to be explained, rerun just that step, check its
   dashboard page, run the tests, commit. One change per commit, so a bad one can be undone alone.
6. **Stop at the boundary.** A change that needs something outside the agent's folder, its pages or its adapter
   (infra_core, a contract, the fix engine, the dashboard shell) is not made in that chat: write it in the agent's
   notes and decide which chat makes it, so two chats never edit shared code at once.
7. **Close out.** One full run end to end: lab trigger, the agent finds it, the dashboard shows it, approve the
   action, Defender confirms it. Then update the README, the agent's notes and its status here.

**What to look at first, per agent:**

- **Vulnerability:** does extraction really get 100% (`demo-limit` proves it)? Which quality checks WARN or FAIL? Are
  the AI fix cards right? Does a fix go proposal → approve → run → verified by Defender?
- **Threat Intel:** which feeds fail (`failed_feeds` in its last-run file)? Does the AI pull the right CVEs and
  software from the news (the spot-check gives an accuracy figure)? Does "Affects us?" match by exact CVE or only by
  product name? Do the risk scores make sense against `risk_policy.csv`?
- **Attack Detection:** do the searches for the 12 attacks run and hit on the lab? How many false positives? Does "connect evidence" link the right device, user and alerts? Are the resolution steps usable?
- **Alert Triage:** is each incident routed to the right playbook? How accurate are the verdicts (backtest and lab
  ledger)? Do the guardrails and prompt-injection checks hold? Each action (close, contain, respond, auto-resolve) is
  off by default: turn them on one at a time and test each.

**Order, when the agents are not done at the same time:** Vulnerability → Threat Intel → Attack Detection → Alert
Triage. Each one uses the previous ones' output (device and software data, then IOCs, then fixes and threat intel),
so when the earlier ones work, problems in the later ones are their own.

An agent is **done** when all four steps work on the lab, the full run in step 7 passes, the tests pass, and the
other agents' tests did not have to change.

## Agent notes

Each chat keeps its agent's section current, under the same four headings: **Today** (how it works, step 1),
**Baseline** (each step: works / partly / broken / not sure, steps 2 and 3), **Backlog** (step 4, in order), and
**Needs from outside** (step 6).

### Threat Intel Agent
- It checks both kinds of news against our devices: vulnerabilities (exposure: CVEs and products against the
  installed software) and clues (IOC sweeps: `ioc_hunt.py` with `config/kql_templates/ioc_*.kql`, then AI resolution
  steps for each hit in `resolve.py`). `python -m threat_intel hunt` runs the sweeps on their own.
- No link with the Attack Detection Agent (31 Oct 2026): it sends nothing to it (`hunt_inputs.json` and
  `hunt_inputs.py` are gone) and takes nothing back (`attack-import` and `attack_import.py` are gone). The
  behaviour hits copied in earlier still sit in its database until someone deletes them (see the Attack Detection notes).
- Its pages show news-based threats only (31 Oct 2026): Applicable threats = vulnerabilities in installed software plus
  collected indicators seen on a device. The Attack Detection Agent's behaviour hits stay in the data for its own pages.
  Remediation has its own Indicator responses tab. Auto-fix (`ATTACK_AUTO_FIX`) is removed: a person approves every fix.
- Needs from outside: the "Indicators searched" card is still on the Attack Detection hunting page; it belongs on a
  Threat Intel page.
- The fix engine still lives here (`fix/`, served by `site.py`). Moving it to `shared/remediation` is a shared change,
  not part of this agent's phase 4 work.
- Baseline: not started.

### Vulnerability Agent
- Its fix stage starts the fix engine in the Threat Intel folder (`pipeline.py`, via `fix_engine_dir`).
- The two fix catalogues stay separate on purpose (execution list vs advice cards, see `docs/fix_catalog_diff.md`).
- Baseline: not started.
- Open gaps (1 Nov 2026): no clear message when Defender has not made its first export yet (the run stops with
  "date value out of range"); "0 new" on a first run reads like a fault; the security-settings and end-of-support
  downloads come back empty; the fix flow is not yet proven end to end.
- Fix Centre change (made 1 Nov 2026, approved by the user): an app update that found nothing newer was reported as
  "failed". Seen on opcc-wks-01: Defender wanted Firefox from MFSA 2026-118, but winget's newest was the installed
  157.0.1, so `winget upgrade` said "no applicable upgrade" and the forced reinstall put 157.0.1 back. Now every
  remediation has the Remediation Agent fallback (`fix/runner.py:_remediate`, the pattern of `_respond`):
  1. The first attempt is the standard one. After a failure the AI picks the next move from `APP_MOVES` only
     (update/replace: winget, choco; remove: uninstall; setting: apply), or stop; without AI the moves follow
     `APP_LADDER`, whose length caps the attempts. It never writes or runs a command.
  2. Retries run under the original approval (the user's choice): no new approval per attempt.
  3. `fix_app.ps1` reads winget's newest published version first; when it is already installed it changes nothing
     (`no_newer`) instead of reinstalling.
  4. Outcomes: done; `awaiting_vendor` (every attempt clean, version unchanged: no source publishes a newer one;
     `plan.requeue_awaiting` sets it back to approved 24 h later); failed, with the AI's professional summary.
  5. Dashboard: status "Awaiting vendor package"; the run page lists the retries. Tests: `tests/test_remediation_agent.py`.
  Proven on VM 2 (1 Nov 2026): winget reported its newest Firefox (157.0.1) already installed and changed nothing;
  with `FIX_ALLOW_CHOCO=1` the agent retried with Chocolatey and Firefox went to 159.0.
  6. Manual handover: when the computer reported but no allowed move remediated it, the status is `manual_required`
     (`failed` is kept for remediations that never ran). The fix carries `handover` (cause, steps, owner, evidence;
     the AI's when it gave them, else `MANUAL_STEPS`), the event log records it, and the bell raises it. A person
     uses "Mark as fixed manually" (`/api/fix/manual`, with a note; `plan.mark_manual`), which is logged in the
     event log and the portal's audit log, and Defender then verifies it as usual. One panel
     (`components/ManualAction.tsx`) shows it on Fix Centre cards, the progress page, attack responses and the run pages.
     A fix waiting for a person never offers Approve, Remediate or Auto-fix (`canApprove` leaves it out).
  7. Traceability (1 Nov 2026): every fix keeps its own `trail` (the shared event list keeps only the last 400 for all
     fixes) and its earlier `attempts` (a new approval no longer overwrites the last result). `/api/fix/detail?id=`
     returns the row, full device output, the allowed package ids, attempts and trail for the record drawer
     (`components/FixRecord.tsx`, opened anywhere with `?record=<fix id>`). Remediation history starts with
     "All remediations" (`FixRegister.tsx`): quick views (waiting for a person, in progress, awaiting vendor,
     pending verification, verified, problems, deferred, proposed) and the shared filter bar. Waiting fixes stay
     pinned on the progress page and at the top of the Updates grid.

### Attack Detection Agent
- Page (31 Oct 2026): tabs Overview, Attacks detected (cards, detail dialog, Remediate opens its response in
  Remediation › Attack responses), Attack coverage (the 12 attacks from `config/attacks.csv`), Search health.
  `findings.json` carries `attacks` and, per finding, `attack`, `attack_name`, `severity`, `search`, `technique`.
- Stands alone since 31 Oct 2026: `inputs.py` pulls the devices from Defender's Machines API (`config/opco_mapping.csv`),
  `hot_cves` asks Defender for the Critical/High CVEs with an exploit, `publish.py` adds `devices` to `findings.json`, and
  the Attack detection page reads that file through `dashboard/src/dashboard/agents/attack_detection.py`
  (`/api/attack-detection/data`). The last step is `fix`: `python -m threat_intel fix-responses` (`ATTACK_FIX_ENGINE_DIR`)
  makes the fix engine (the Fix Centre, still in the Threat Intel folder) propose a scan-and-clean per behaviour hit, read
  from `findings.json`. `history.py` / `import-history` are gone. Left over: its database still holds the news threats
  loaded before, and the page still borrows UI helpers (`attackType`, `Resolve`, the header) from `web/src/agents/threat-intel/`.
- Its own agent since phase 3, with its own database and `.venv`. It searches for attacker behaviour only
  (`bh_*.kql`, the searches for the 12 attacks only); the IOC sweeps moved back to the Threat Intel Agent. It has no README yet: write it in step 1.
- The searches for the 12 attacks in the plain-language guide are written (31 Oct 2026): 106 `bh_*.kql` hunts, each
  tagged `// attack: N`. The five `// needs: domain` hunts are recorded as skipped when no device is domain-joined.
  The attack 12 hunts use `{{HOT_CVES}}` (CVEs of the Threat Intel Agent's High/Critical threats); its "any clue from
  attacks 1 to 11 in 14 days" search is `_open_doors` in `correlate.py`. Not KQL hunts: Defender's own alerts (already
  attached to every finding) and addresses on the Threat Intel bad list (the Threat Intel Agent's IOC sweep). Only
  partly tested live: Defender stopped answering partway through the check run.
- Only the 12 attacks' searches are kept: the AI-drafted hunts, `cve_exposure.kql` and the old lab script
  (`Invoke-AttackLabTest.ps1`) are gone, and its data was emptied on 31 Oct 2026.
- The 12 lab tests are `scripts/lab/Test-01-…` to `Test-12-….ps1`, one per attack, run from Azure Cloud Shell: each sends
  its steps into `opca-wks-01` (and `opcc-wks-01` for tests 5, 6, 8) through Azure Run Command, so nobody signs in.
  Slow tests schedule their later days in the VM; `-Cleanup` undoes each. Written but not yet run on the VMs.
- It can use its own Entra app registration: `ATTACK_DEFENDER_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET` in the suite
  `.env` (else the shared `DEFENDER_*` one). Needs from outside: add those three lines to `.env.example`.
- The fix engine's lab clean-up (`fix_app.ps1`) removes the same `AttackLabTest` leftovers (renamed 31 Oct 2026).
- Baseline: not started.

### Alert Triage Agent
- `fixlink.py` still reads the fix engine's private plan in the Threat Intel folder; it moves to
  the Fix Centre when the fix engine does. Its key in the triage context is `fixes`.
- Baseline: not started.

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

