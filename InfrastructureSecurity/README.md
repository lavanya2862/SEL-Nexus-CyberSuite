# Infrastructure Security: a SEL Nexus CyberSuite module

Four AI-assisted security agents built on Microsoft Defender for Endpoint, plus one dashboard that brings them together.
This is the **Infrastructure Security** module of SEL Nexus CyberSuite. People sign in on the suite's shared sign-in
page (`../login`, http://127.0.0.1:8000), which also leads to the other module, Application Security.

How the module is put together, its rules and the restructure status: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

| Folder | What it does |
|---|---|
| [dashboard](dashboard/README.md) | **Infrastructure Security** website (overview, notifications, help chat) for the agents below |
| [agents/threat_intel](agents/threat_intel/README.md) | **Threat Intel Agent**: collects public threat intelligence, checks it against our devices and rates risk. Until the split (phase 3) it also holds the **Attack Detection Agent** (hunts in Defender) and the fix engine |
| [agents/vulnerability](agents/vulnerability/README.md) | **Vulnerability Agent**: exports 100% of Defender vulnerability data (beyond the KQL row limit) into a data lake, the dashboard's Vulnerabilities pages and an Excel summary |
| [agents/alert_triage](agents/alert_triage/README.md) | **Alert Triage Agent**: triages Defender / Sentinel incidents and recommends close, escalate or contain, with the evidence |
| [tests](tests/layout.py) | Safety net for the whole module: every module imports, each agent rebuilds its dashboard data, every dashboard API keeps its shape |

## Getting started

1. Copy `.env.example` at the repository root to `.env` once and fill it in; every agent and the dashboard read it.
   It also points the dashboard at the shared sign-in page (`PORTAL_LOGIN_URL`) and its accounts (`PORTAL_AUTH_DIR`).
2. Double-click **../Start_All.cmd** to start the whole suite and open the sign-in page. **Start_Infrastructure_Security.cmd**
   starts only this module (and the sign-in page if it isn't running). **Stop_Infrastructure_Security.cmd** stops this module.
   The first start sets up each agent's `.venv` (a `.pth` file puts its `src` on the path, so Python 3.11 works too) and
   builds the dashboard website; later starts rebuild the website when its pages changed.
3. Check the module with `dashboard\.venv\Scripts\python.exe -m pytest tests -q` (from this folder).

Secrets (`.env`), data, logs and local accounts are never committed. Without a filled-in `.env`, an agent has nothing to show.
