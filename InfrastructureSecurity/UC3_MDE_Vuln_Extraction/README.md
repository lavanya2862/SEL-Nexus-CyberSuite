# UC3: Complete Defender Vulnerability Extraction (beyond KQL limits)

An automated pipeline that exports **100%** of Microsoft Defender for Endpoint vulnerability data through the **Defender Export APIs** (no KQL 100,000-row limit), stores a daily snapshot in a Parquet data lake with DuckDB, runs data-quality checks (including coverage against Defender's own count), and publishes the data behind the Unified Cyber Portal's Vulnerabilities pages, a daily Excel summary, a Word/PDF report and Power-BI-ready tables.

Each run also downloads Defender's **security-setting checks** and **end-of-support software**, and builds **fix cards**: one per vulnerable app (optionally explained by Azure AI Foundry or Google Gemini and fact-checked against the data) and one per failing security setting.

## Setup

Requires Python 3.12+ on Windows.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\pip install -e .
copy config\settings.example.env .env      # then fill in .env (never commit it)
.\.venv\Scripts\python.exe -m uc3 check     # expect RESULT: OK
.\.venv\Scripts\python.exe -m uc3 live-test
```

What `.env` needs:

| Setting | Where it comes from |
|---|---|
| `UC3_TENANT_ID`, `UC3_CLIENT_ID`, `UC3_CLIENT_SECRET` | A read-only Entra ID app registration with the WindowsDefenderATP application permissions `Vulnerability.Read.All`, `Machine.Read.All`, `Software.Read.All` (admin consent granted). A certificate (`UC3_CERT_THUMBPRINT` / `UC3_CERT_PATH`) can replace the secret |
| `AZURE_FOUNDRY_ENDPOINT`, `AZURE_FOUNDRY_API_KEY`, `AZURE_FOUNDRY_DEPLOYMENT` | Azure AI Foundry model deployment (Foundry portal -> Models + endpoints). When all three are set the fix guide uses it instead of Gemini; `AI_PROVIDER=gemini` switches back. Reasoning models such as gpt-5 work too (`AZURE_FOUNDRY_REASONING_EFFORT`, default low) |
| `GEMINI_API_KEY` (optional) | Free key from Google AI Studio, for the AI fix text when Azure AI Foundry is not set. Only app names, versions, CVE numbers and counts are sent, never device or user names |
| `GEMINI_API_KEY_2`, `GEMINI_API_KEY_3` … (optional) | Spare Gemini keys: when one key uses up its daily quota the next takes over. Each must be from a different Google Cloud project (keys in one project share its quota) |
| `UC3_FIX_STAGE`, `UC3_FIX_ENGINE_DIR` (optional) | The Fix stage at the end of every run (on by default): the Threat Intel Agent's fix engine (default `../UC1_Threat_Intel_Hunting_Agent`) lists the fixes that are new in this run, and a person presses **Fix** or **Save for later** on each one on the portal's run page. `UC3_FIX_STAGE=0` turns it off |

## Commands

```powershell
.\.venv\Scripts\python.exe -m uc3 run         # daily job: download + data lake + checks + portal data + Excel + Remediation agent + Fix stage
.\.venv\Scripts\python.exe -m uc3 publish     # rebuild the portal data, Excel and report from the last good download
.\.venv\Scripts\python.exe -m uc3 summary     # overview of the latest data
.\.venv\Scripts\python.exe -m uc3 demo-limit  # measure the KQL 100,000-row limit on the real API
.\.venv\Scripts\python.exe -m uc3 metrics     # before/after table for the key metrics
.\.venv\Scripts\python.exe -m uc3 ai-fixes    # AI fix guide per vulnerable app (also part of `run`)
```

Single steps: `extract` (download), `load` (put a downloaded day into the data lake), `quality` (checks). Each accepts `--date YYYY-MM-DD`.

## Folder layout

| Path | Purpose |
|---|---|
| `src/uc3/` | The pipeline: `config.py` settings, `auth.py` Microsoft login, `api_client.py` API calls and downloads, `extract.py`, `load.py` data lake, `transform.py` database views, `quality.py` checks, `pipeline.py` whole run |
| `src/uc3/dashboard/` | `build.py`: writes `data/dashboard/dashboard_data.json`, which the portal reads (the agent has no web pages of its own) |
| `config/` | Settings template, OpCo mapping, SLA policy, fix catalogues. See [config/README.md](config/README.md) |
| `data/` | Created at run time (not in git): `raw/<date>/` downloads, `lake/` Parquet snapshots, `uc3.duckdb`, `reporting/` Excel + report tables, `dashboard/dashboard_data.json` (portal data) |
