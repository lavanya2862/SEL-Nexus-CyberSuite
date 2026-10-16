# UC4: Alert Triage Agent (SOC Monitoring)

An **AI triage assistant** for security incidents. For every new incident it collects the related logs, checks threat intelligence, history and watchlists, applies fixed safety rules, and **recommends** close / escalate / contain, with the evidence behind it. A human always decides.

## How it works (one incident)

```
Defender / Sentinel incident ─► packet (alerts, devices, accounts, files; attacker text kept apart)
   ─► playbook for its type ─► read-only searches ±24 h, threat intel, history, watchlists
   ─► safety rules (before) ─► ONE AI call, strict JSON ─► answer checker ─► safety rules (after: only more cautious)
   ─► triage queue website ─► analyst agrees / disagrees ─► metrics + accuracy
```

## Setup

Requires Python 3.12+ on Windows.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\pip install -e .
copy config\settings.example.env .env      # then fill in .env (never commit it)
.\.venv\Scripts\python.exe -m uc4 check
.\.venv\Scripts\python.exe -m uc4 live-test
```

What `.env` needs:

| Setting | Where it comes from |
|---|---|
| `UC4_TENANT_ID`, `UC4_CLIENT_ID`, `UC4_CLIENT_SECRET` | An Entra ID app registration with Microsoft Graph application permissions `SecurityIncident.Read.All`, `SecurityAlert.Read.All`, `ThreatHunting.Read.All` and WindowsDefenderATP `Machine.Read.All` (admin consent granted) |
| `GEMINI_API_KEY` | Free key from Google AI Studio |
| `ABUSECH_AUTH_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY` | Free threat-intel keys (all optional) |

Optional actions are **off** by default and need extra permissions when switched on:

| Setting | Does | Extra permission |
|---|---|---|
| `UC4_WRITEBACK=1` | Posts one "AI triage" comment on each lab incident | Graph `SecurityIncident.ReadWrite.All` |
| `UC4_RESPOND=1` | Asks Defender to scan / quarantine | WindowsDefenderATP `Machine.Scan`, `Machine.StopAndQuarantine` |
| `UC4_CONTAIN=1` | Lets an analyst approve isolating a lab device (only names in `UC4_LAB_DEVICES`) | WindowsDefenderATP `Machine.Isolate` |

## Commands

```powershell
.\.venv\Scripts\python.exe -m uc4 serve       # triage website: http://127.0.0.1:8900 (this computer only)
.\.venv\Scripts\python.exe -m uc4 run         # pick up new incidents and triage them
.\.venv\Scripts\python.exe -m uc4 backtest    # accuracy on GUIDE + lab incidents
.\.venv\Scripts\python.exe -m uc4 metrics     # MTTR, MTTC, SLA, effort (MEASURED / ASSUMPTION)
```

Backtest data: Microsoft's **GUIDE** dataset (about 1 M analyst-labelled incidents, CDLA-Permissive-2.0) from Kaggle ("Microsoft Security Incident Prediction"). Put `GUIDE_Train.csv` and `GUIDE_Test.csv` in `data/inbox/guide/`.

## Folder layout

| Path | Purpose |
|---|---|
| `src/uc4/` | The agent: incident packets, playbooks, safety rules, AI call + answer checker, threat intel, backtest, metrics, website (`site_assets/`) |
| `config/` | Settings template, playbooks, safety rules (`guardrails.yaml`), containment menu, watchlists, KQL queries, SLA policy, answer schema |
| `data/`, `logs/` | Created at run time (not in git) |

## Rules

- Recommend-only: the agent never closes, reclassifies or contains anything by itself unless an optional action above is switched on.
- Text written by an attacker (alert titles, command lines) is kept apart from the instructions and never obeyed.
- Secrets live only in `.env`; nothing prints them.
