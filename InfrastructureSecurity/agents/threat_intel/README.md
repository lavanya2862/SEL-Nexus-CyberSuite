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
