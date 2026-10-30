# Phases 2 and 3: hand-off steps

Who does what for the rest of the restructure (see `ARCHITECTURE.md` for the target and the rules). The work is
split three ways:

- **Part A – Gemini, no code changes.** Writing and checking: specs, schemas, reports.
- **Part B – Claude.** Phase 2 code changes, done in parallel with Part A.
- **Part C – Claude.** Phase 3, after Part A (it uses A3, A4 and A5).

Gemini never changes code. It works in its own copy of the repository, so it and Claude never touch the same files:

| Who | Folder | Branch |
|---|---|---|
| Gemini (Part A) | `C:\Users\2862390\Desktop\PoC\SEL_Nexus_CyberSuite-docs` | `infra-docs` |
| Claude (Parts B and C) | `C:\Users\2862390\Desktop\PoC\SEL_Nexus_CyberSuite` | `infra-four-agents` |

Do the tasks in the order listed. One task per Gemini chat keeps it focused.

---

## Your steps (you, not an AI)

1. **Open the Gemini folder** `SEL_Nexus_CyberSuite-docs` in Antigravity (not the main one).
2. **Start every Gemini chat** with the "Paste this first" block below, then paste one task.
3. **After each task:** check with `git status` (in the Gemini folder) that only documentation files changed: `.md`
   files, and new `.json` files under `InfrastructureSecurity/contracts/`. If anything else changed, throw it away with
   `git checkout -- <file>`.
4. **Commit each task on its own** in the Gemini folder, with the message given in the task
   (`git add -A` then `git commit -m "..."`).
5. **Secrets:** never paste `.env` values into any chat.
6. **Signing in:** for A6 you sign in to the dashboard yourself; an AI never types your password.
7. **When A3, A4 and A5 are committed,** tell Claude "Part A is ready". Claude merges `infra-docs` and starts Part C.

---

## Paste this first (in every Gemini chat)

```
You are working in the folder SEL_Nexus_CyberSuite-docs (a copy of the repository SEL_Nexus_CyberSuite) on the git
branch infra-docs. Read InfrastructureSecurity/docs/ARCHITECTURE.md and InfrastructureSecurity/CLAUDE.md first.
Rules:
- You write documentation only. Never change a .py, .ts, .tsx, .cmd, .ps1, .csv, .yaml, .kql or .toml file, and
  never change an existing .json file. You may create or edit .md files and create new .json files under
  InfrastructureSecurity/contracts/.
- Do only the one task I give you. Do not "improve" anything else.
- Never open, print or change .env, any data/ folder, any .venv folder or node_modules.
- Never write UC1, UC3 or UC4 in new text, except the real external names listed under "Names that stay on purpose"
  in ARCHITECTURE.md.
- Another assistant is changing code in a different copy at the same time; describe the code as you find it here.
- When you finish, list every file you created or changed, and stop. Do not commit.
```

---

## Part A – Gemini, no code changes

### A1. Spec for each agent (one chat per agent)

Paste, with `<AGENT>` replaced by one of: Threat Intel Agent (folder `agents/threat_intel`), Vulnerability Agent
(`agents/vulnerability`), Alert Triage Agent (`agents/alert_triage`), Attack Detection Agent (for now inside
`agents/threat_intel`: `hunting/`, `correlate.py`, `resolve.py`, `attack_report.py`, `attack_check()` in `pipeline.py`):

```
Task A1: write a spec section for the <AGENT>. Read its code (do not change it) and add a section
"## Spec" at the end of its README.md (for the Attack Detection Agent, write a new file
InfrastructureSecurity/docs/attack_detection_spec.md instead). Use exactly these headings:
### Inputs        - every Microsoft Defender / Sentinel / Graph API, feed and file it reads, with the file:function that reads it
### Steps         - its four steps from ARCHITECTURE.md, and for each: which files and functions do it, in order
### Outputs       - every file it writes under data/, which of them the dashboard reads (look in dashboard/src/dashboard/sources.py)
### Actions that need a person - anything that changes a device or Defender, and where the approval is checked
### Settings      - every environment variable it reads, with its default
### Reads from other agents - any file it reads from another agent's folder
### Open questions - things the code does that look wrong or unclear (do not fix them)
Quote file paths and function names exactly. Do not guess: if you are not sure, put it under Open questions.
```
Commit: `Docs: spec for the <AGENT>`

### A2. Output contracts (documentation only)

```
Task A2: create the folder InfrastructureSecurity/contracts/ with one JSON Schema (draft 2020-12) per file below,
describing what the agent writes today. Base them on tests/snapshots/rebuild_*.json and tests/snapshots/dashboard_api.json
(they hold the field names and types) and on the code that writes each file. Do not change any code.
  threat_intel.dashboard_data.schema.json   <- agents/threat_intel: data/dashboard/dashboard_data.json
  threat_intel.site_data.schema.json        <- data/dashboard/site_data.json
  threat_intel.clues.schema.json            <- data/dashboard/clues.json
  threat_intel.threat_matches.schema.json   <- data/dashboard/threat_matches.json
  vulnerability.dashboard_data.schema.json  <- agents/vulnerability: data/dashboard/dashboard_data.json
  alert_triage.triage_data.schema.json      <- agents/alert_triage: data/export/triage_data.json
Each schema has "$id" = the file name, a "description" saying which agent writes it and which dashboard code reads it,
and "x-schema-version": 1. Fields the snapshots show as "str|null" are not required. Also write contracts/README.md:
one line per schema (file, writer, reader).
```
Commit: `Contracts: describe what each agent publishes today`

### A3. Who reads whose files (input for Part C)

```
Task A3: without changing code, find every place where one part of InfrastructureSecurity reads a file or database
from another part's folder (agents/threat_intel, agents/vulnerability, agents/alert_triage, dashboard). Search for
_dir, data/, "fix", "plan.json", "state.json", "dashboard_data.json", "duckdb" and settings like vuln_agent_dir,
fix_engine_dir, threat_intel_dir. Add a section "### Cross-folder reads (found <today's date>)" under
"## Agent notes" in docs/ARCHITECTURE.md: a table with reader file:line, what it reads (path), owner folder.
```
Commit: `Docs: list every cross-folder read`

### A4. Which database tables belong to Attack Detection (input for Part C)

```
Task A4: read agents/threat_intel/src/threat_intel/store.py and every caller of store.upsert / store.query /
store.fetch (search the package). Without changing code, write docs/attack_detection_split.md with a table:
table name | written by (file:function) | read by (file:function) | belongs to: Threat Intel, Attack Detection,
Fix engine or shared. "Attack Detection" = used only by hunting/, correlate.py, resolve.py, attack_report.py or
attack_check(). Mark anything used by both as shared and say by whom.
```
Commit: `Docs: map the Threat Intel database for the Attack Detection split`

### A5. Compare the two fix catalogues (you decide afterwards)

```
Task A5: compare agents/threat_intel/config/fix_catalog.csv with agents/vulnerability/config/fix_catalog.csv, and
the two setting_fix_catalog.csv files the same way. Without changing them, write docs/fix_catalog_diff.md: rows only
in one file, rows in both with different values (show both), and which code reads each file. End with a proposed
merged file as a CSV block, choosing the newer or more complete value and saying why for every choice.
```
Commit: `Docs: compare the two fix catalogues`
**You:** read the proposal and say which way to go; Claude merges it in Part C.

### A6. Click-through check of the dashboard (Gemini's browser, after you sign in)

Do this one after Claude finishes Part B, so it checks the latest code. Start the module from the **main** folder
(`InfrastructureSecurity\Start_Infrastructure_Security.cmd`), sign in yourself, then:
```
Task A6: the dashboard is open at http://127.0.0.1:8800 and I am signed in. Do not press any button that runs an
agent, approves a fix, closes or reopens an incident, or isolates a device. Open each item of the left menu in turn
(Home, Vulnerabilities, Threats, Attack detection, Alert triage, Remediation / Fix Centre, Reports, Runs, Activity log)
and on each page: note any error message, empty area that says data is missing, or a broken link; open one detail page
where there is one (a threat, a vulnerability, an incident). Report a table: page | address | what looks wrong |
screenshot. Change nothing.
```
**You:** send the table to Claude only if something looks wrong.

---

## Part B – Claude (phase 2 code changes)

Claude does these in the main folder while Gemini does Part A. They are kept here as the record of what phase 2 does.

### B1. Create `shared/infra_core`

```
Task B1: create the shared library folder, empty for now.
1. Create InfrastructureSecurity/shared/infra_core/ with: README.md (one paragraph: "Code every agent and the dashboard
   share: no security logic. See docs/ARCHITECTURE.md."), pyproject.toml (copy agents/vulnerability/pyproject.toml,
   name = "infra-core", no dependencies), and src/infra_core/__init__.py containing one docstring line.
2. In Start_Infrastructure_Security.cmd, in the :setup routine, after the line that writes %~2.pth, add a line that
   writes the path of shared\infra_core\src into "%DI%%~1\.venv\Lib\site-packages\infra_core.pth"
   (same style: (echo %DI%shared\infra_core\src)>"...").
3. In tests/test_imports.py add a test, parametrized over the parts in layout.PARTS, that runs that part's python with
   -c "import infra_core" and asserts it succeeds (skip when the .venv is missing).
Change nothing else.
```
**You, once:** the existing `.venv` folders were made before this change, so add the path file to each by hand.
In PowerShell from `InfrastructureSecurity`:
```
foreach ($d in 'dashboard','agents\threat_intel','agents\vulnerability','agents\alert_triage') { Set-Content -Encoding ascii "$d\.venv\Lib\site-packages\infra_core.pth" (Resolve-Path shared\infra_core\src).Path }
```
Commit: `infra_core: shared library folder, on every agent's path`

### B2. Move the report styling into `infra_core`

```
Task B2: the three files agents/threat_intel/src/threat_intel/docstyle.py, agents/vulnerability/src/vulnerability/docstyle.py
and agents/alert_triage/src/alert_triage/docstyle.py are identical (check it; stop and tell me if they are not).
1. git mv agents/threat_intel/src/threat_intel/docstyle.py shared/infra_core/src/infra_core/docstyle.py
2. git rm the other two copies.
3. Replace every "from threat_intel import docstyle", "from vulnerability import docstyle" and
   "from alert_triage import docstyle" with "from infra_core import docstyle" (keep "as ds" where it is used).
   There are five such lines: threat_intel/report.py, threat_intel/attack_report.py, vulnerability/report.py,
   vulnerability/excel.py, alert_triage/report.py. Also change "from vulnerability.docstyle import pdf_converter" in
   vulnerability/__main__.py to "from infra_core.docstyle import pdf_converter". Search to be sure there are no others.
Change nothing else.
```
Commit: `infra_core: one report style for every agent`

### B3. Environment settings by agent name (old names keep working)

```
Task B3: rename the environment settings; the old names must keep working.
1. Create shared/infra_core/src/infra_core/settings.py with one function:
     env(name: str, *old_names: str) -> str | None
   It returns the first non-empty value (after .strip()) of os.environ for name, then each old name. When the value
   comes from an old name it logs one warning per old name per process (logging.getLogger("infra_core.settings")):
   "<old> is an old setting name; rename it to <name> in .env". Empty or missing everywhere -> None.
2. In agents/threat_intel/src/threat_intel/config.py, agents/vulnerability/src/vulnerability/config.py and
   agents/alert_triage/src/alert_triage/config.py: change the local _env(name) to _env(name, *old) that returns
   infra_core.settings.env(name, *old). Then change every _env("OLD") call whose name is in the table below to
   _env("NEW", "OLD"). Change no other call.
3. In dashboard/src/dashboard/config.py, change each env.get("OLD", default) for the PORTAL_UC* names below to
   env.get("NEW") or env.get("OLD") or default (keep the defaults exactly).
4. In tests/layout.py, REBUILDS, use the new names in "env" (THREAT_INTEL_DATA_DIR, VULN_DATA_DIR, TRIAGE_DATA_DIR).
5. In the repository-root .env.example, rename each old name to the new one (keep values and comments) and add one
   comment line at the top of the Infrastructure Security part: "Old names (UC1_*, UC3_*, UC4_*, PORTAL_UC*) still work."
Table (old -> new):
  UC1_DATA_DIR->THREAT_INTEL_DATA_DIR  UC1_LOG_DIR->THREAT_INTEL_LOG_DIR  UC1_VULN_AGENT_DIR->THREAT_INTEL_VULN_AGENT_DIR
  UC3_<X>->VULN_<X> for X in API_BASE, CERT_PATH, CERT_THUMBPRINT, CLIENT_ID, CLIENT_SECRET, DATA_DIR, FIX_ENGINE_DIR,
    FIX_STAGE, LOG_DIR, TENANT_ID, MODE
  UC4_UC1_DIR->TRIAGE_THREAT_INTEL_DIR, and UC4_<X>->TRIAGE_<X> for every other UC4_ name
  PORTAL_UC1_DIR->DASHBOARD_THREAT_INTEL_DIR  PORTAL_UC3_DIR->DASHBOARD_VULNERABILITY_DIR
  PORTAL_UC4_DIR->DASHBOARD_ALERT_TRIAGE_DIR  PORTAL_UC1_SITE->DASHBOARD_FIX_SITE  PORTAL_UC4_SITE->DASHBOARD_TRIAGE_SITE
Also search the whole InfrastructureSecurity folder (not data/, .venv) for os.environ / os.getenv / env.get reading any
old name in the table and give it the same treatment. List them in your answer.
```
**You:** when it passes, open your real `.env` and rename the keys yourself (same table). Keep the values. Start the
module and check the dashboard still shows data. You can do this later; the old names keep working.
Commit: `Settings: environment names by agent, old names still accepted`

### B4. One adapter file per agent in the dashboard

```
Task B4: dashboard/src/dashboard/sources.py holds the classes ThreatIntelSource, VulnerabilitySource and
AlertTriageSource plus helpers. Split it, without changing any logic:
1. Create dashboard/src/dashboard/agents/__init__.py (one docstring line: "One file per agent: the only code that reads
   that agent's published files.") and move each class, with the helpers only it uses, into
   dashboard/src/dashboard/agents/threat_intel.py, vulnerability.py and alert_triage.py. Helpers used by more than one
   stay in sources.py.
2. sources.py keeps working for existing imports: at its end, import the three classes back
   (from dashboard.agents.threat_intel import ThreatIntelSource, and so on) so every "from dashboard.sources import ..."
   still works. Do not change any other file.
3. Avoid circular imports: the agents/ files may import helpers from sources.py only if sources.py imports the classes
   at the very end; if that fails, move the shared helpers into dashboard/src/dashboard/agents/common.py instead.
```
Commit: `Dashboard: one adapter file per agent`

---

## Part C – Claude (one session, after A and B)

Give Claude this, in a fresh chat:
```
Read InfrastructureSecurity/docs/ARCHITECTURE.md and docs/HANDOFF_PHASES_2_3.md. Parts A and B are done
(see git log). Do Part C of phase 3, using docs/attack_detection_split.md, docs/fix_catalog_diff.md and the
"Cross-folder reads" table: move the Attack Detection Agent into agents/attack_detection, move the fix engine into
shared/remediation, merge the fix catalogues as I decided: <your decision>, and switch the dashboard's run
progress to standard progress events. Keep the safety-net tests green; commit per step.
```
Why these stay with Claude: they change which process owns which database tables and files while scheduled runs and
the fix engine keep working, and a mistake there shows up only at run time, not in the tests.
