# UC3: Complete Defender Vulnerability Extraction (beyond KQL limits)

An automated pipeline that exports **100%** of Microsoft Defender for Endpoint vulnerability data through the **Defender Export APIs** (no KQL 100,000-row limit), stores a daily snapshot in a Parquet data lake with DuckDB, runs data-quality checks (including coverage against Defender's own count), and publishes a **Vulnerability Command Centre** dashboard, a daily Excel summary and Power-BI-ready tables.

Each run also downloads Defender's **security-setting checks** and **end-of-support software**, and builds **fix cards**: one per vulnerable app (optionally explained by Google Gemini and fact-checked against the data) and one per failing security setting.

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
| `GEMINI_API_KEY` (optional) | Free key from Google AI Studio, for the AI fix text. Only app names, versions, CVE numbers and counts are sent, never device or user names |
| `GEMINI_API_KEY_2`, `GEMINI_API_KEY_3` … (optional) | Spare Gemini keys: when one key uses up its daily quota the next takes over. Each must be from a different Google Cloud project (keys in one project share its quota) |

## Commands

```powershell
.\.venv\Scripts\python.exe -m uc3 run         # daily job: download + data lake + checks + dashboard + Excel
.\.venv\Scripts\python.exe -m uc3 serve       # live dashboard: http://127.0.0.1:8600 with "Refresh from Defender now"
.\.venv\Scripts\python.exe -m uc3 dashboard   # rebuild the dashboard and open it in the browser
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
| `src/uc3/dashboard/` | Dashboard design (`template.html`), logic (`app.js`), builder (`build.py`), ECharts (`vendor/`, Apache-2.0) |
| `config/` | Settings template, OpCo mapping, SLA policy, fix catalogues. See [config/README.md](config/README.md) |
| `data/` | Created at run time (not in git): `raw/<date>/` downloads, `lake/` Parquet snapshots, `uc3.duckdb`, `reporting/` Excel + report tables, `dashboard/UC3_Dashboard_latest.html` |
