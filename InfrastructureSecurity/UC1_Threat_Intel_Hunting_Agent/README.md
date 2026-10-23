# UC1: AI Threat Intelligence & Threat Hunting Agent

An AI agent that **collects** public threat intelligence, **understands** it with Google Gemini (every claim checked by code), **checks** it against Microsoft Defender for Endpoint ("does this affect us?"), **hunts** for attack clues and attacker behaviour, **connects** findings to computers, business units, users and Defender alerts, **rates** the risk with fixed, explainable rules, and **reports** through a Word/PDF report, a Threat Command Centre website, alerts and key metrics. A **Fix Centre** can update or remove vulnerable apps on lab computers after a person approves.

## How one run works

```
Threat feeds ─► Gemini analysis (checked by code) ─► Defender inventory ─► exposure + risk score
   ─► hunts in Defender (validated KQL) ─► connect to devices / users / alerts ─► report, dashboard, alerts
```

Feeds: CISA KEV, NVD, EPSS, MITRE ATT&CK, NCSC-NL, CERT-EU, Microsoft MSRC, ThreatFox, URLhaus, MalwareBazaar (+ AlienVault OTX, optional).

## Setup

Requires Python 3.12+ on Windows.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\pip install -e .
copy config\settings.example.env .env      # then fill in .env (never commit it)
.\.venv\Scripts\python.exe -m uc1 check
.\.venv\Scripts\python.exe -m uc1 live-test
```

What `.env` needs:

| Setting | Where it comes from |
|---|---|
| `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` | An Entra ID app registration with the WindowsDefenderATP application permissions `Machine.Read.All`, `Vulnerability.Read.All`, `AdvancedQuery.Read.All`, `Alert.Read.All` (admin consent granted) |
| `GEMINI_API_KEY` | Free key from Google AI Studio |
| `GEMINI_API_KEY_2`, `GEMINI_API_KEY_3` … (optional) | Spare Gemini keys: when one key uses up its daily quota the next takes over. Each must be from a different Google Cloud project (keys in one project share its quota) |
| `NVD_API_KEY`, `ABUSECH_AUTH_KEY`, `OTX_API_KEY` | Free keys from NVD, abuse.ch and AlienVault OTX (OTX is optional) |
| Fix loop (optional) | Azure role **Virtual Machine Contributor** on `FIX_RESOURCE_GROUP` (Run Command), and/or `Machine.LiveResponse` + `Library.Manage` (Live Response) |

Without Defender settings the agent still collects and rates public threats, but skips inventory and hunting.

## Commands

```powershell
.\.venv\Scripts\python.exe -m uc1 serve       # website: http://127.0.0.1:8700 (this computer only)
.\.venv\Scripts\python.exe -m uc1 run         # one full run: collect, inventory, analyse, hunt, report
.\.venv\Scripts\python.exe -m uc1 summary     # what's in the database
```

`python -m uc1 --help` lists every command, including the single steps (`collect`, `inventory`, `analyse`, `hunt`, `report`, `dashboard`, `alerts`, `metrics`) and the fix loop (`fix-plan`, `fix-status`, `fix-probe`, `fix-approve`, `fix-run`).

## The website

| Page | What you get |
|---|---|
| `/` | The **Threat Command Centre**, with a **Run now** button and live progress |
| `/threat/<id>` | A detail page per threat: why it is rated as it is, AI extraction vs. source, CVE scores, exposed computers and the fix, hunt hits, the exact queries |
| `/reports` | Word/PDF reports, spot-check workbook, alerts and metrics to download |
| `/fix` | The **Fix Centre**: fix plan, approve, run on the lab VMs, see each result and Defender's confirmation |

## Folder layout

| Folder | Contents |
|---|---|
| `src/uc1/` | The agent: `feeds/`, `inventory.py`, `analyse.py` + `ai/`, `exposure.py`, `scoring.py`, `hunting/`, `correlate.py`, `report.py`, `dashboard.py`, `site.py` (website), `fix/` (fix loop), `pipeline.py` |
| `config/` | Editable rules: risk points, feeds on/off, hunt queries, OpCo mapping, IOC allow-list, fix catalogue. See [config/README.md](config/README.md) |
| `data/`, `logs/` | Created at run time: database, raw feed copies, reports, logs (not in git) |

## Safety

- Read-only Defender access for analysis and hunting; every hunt query passes a validator (allowed tables, time filter, row limit).
- The AI never decides alone: its answers are checked against the source data, and risk ratings come from fixed rules.
- Fixes only run on approved items, on the lab VMs (optionally limited with `FIX_DEVICES`), using the allow-list in `config/fix_catalog.csv`.
- Secrets live only in `.env`, which is never committed or printed.
