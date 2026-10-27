# Infrastructure Security: a SEL Nexus CyberSuite module

Three AI-assisted security tools built on Microsoft Defender for Endpoint, plus one portal that brings them together.
This is the **Infrastructure Security** module of SEL Nexus CyberSuite. People sign in on the suite's shared sign-in
page (`../login`, http://127.0.0.1:8000), which also leads to the other module, Application Security.

| Folder | What it does |
|---|---|
| [Unified_Cyber_Portal](Unified_Cyber_Portal/README.md) | **Infrastructure Security** website (overview, notifications, help chat) for the three tools below |
| [UC1_Threat_Intel_Hunting_Agent](UC1_Threat_Intel_Hunting_Agent/README.md) | Collects public threat intelligence, checks it against our devices, hunts in Defender, rates risk, and fixes vulnerable apps after approval |
| [UC3_MDE_Vuln_Extraction](UC3_MDE_Vuln_Extraction/README.md) | Exports 100% of Defender vulnerability data (beyond the KQL row limit) into a data lake, the portal's Vulnerabilities pages and an Excel summary |
| [UC4_Alert_Triage_Agent](UC4_Alert_Triage_Agent/README.md) | Triages Defender / Sentinel incidents and recommends close, escalate or contain, with the evidence |

## Getting started

1. Set up UC1, UC3 and UC4 (each has its own `.venv`; their settings live in the one suite `.env` at the repository root, copied from `.env.example`).
2. Set up the portal (see its README). the suite `.env` points it at the shared sign-in page
   (`PORTAL_LOGIN_URL`) and its accounts (`PORTAL_AUTH_DIR`).
3. Double-click **../Start_All.cmd** to start the whole suite and open the sign-in page. **Start_Infrastructure_Security.cmd**
   starts only this module (and the sign-in page if it isn't running). **Stop_Infrastructure_Security.cmd** stops this module.
   The first start sets up each tool's `.venv` (a `.pth` file puts its `src` on the path, so Python 3.11 works too) and
   builds the portal website, and points the portal at the shared sign-in page (`PORTAL_LOGIN_URL`, `PORTAL_AUTH_DIR`).

Secrets (`.env`), data, logs and local accounts are never committed. Without a filled-in `.env`, a tool has nothing to show.
