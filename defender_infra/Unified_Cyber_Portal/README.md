# SEL Nexus CyberSuite: Unified Cyber Portal

One website for the three tools: **threat intelligence and hunting** (UC1), **vulnerabilities and fixes** (UC3, with UC1's Fix Centre) and **alert response** (UC4). It has sign-in, a home overview, a notification bell and a help chat. The portal reads each tool's own data folder and talks to the UC1 and UC4 websites in the background, starting them itself when their `.venv` exists.

## Setup

Requires Python 3.12+ and Node.js 22+ on Windows. Set up UC1, UC3 and UC4 first (see their READMEs); they are expected next to this folder.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\pip install -e .
cd web
npm ci
npm run build                               # builds web/dist, which the portal serves
cd ..
.\.venv\Scripts\python.exe -m portal serve  # http://127.0.0.1:8800 (this computer only)
```

Create an account with **Sign up** on the sign-in page. Accounts are kept locally in `data/auth/` and never committed.

## Settings (optional)

Copy `config/portal.env.example` to `config/portal.env` only when the defaults are wrong: other folder locations for UC1/UC3/UC4, another port, sign-in mode (`local`, `cognito` for Amazon Cognito, or `off`), allowed e-mail domains, session length. No secrets live in this file.

## Development

```powershell
.\.venv\Scripts\python.exe -m portal serve --reload   # API, restarts on code changes
cd web; npm run dev                                   # web app with hot reload
```

## Folder layout

| Path | Purpose |
|---|---|
| `src/portal/` | The API (FastAPI): sign-in, data from UC1/UC3/UC4, proxies to the UC1 and UC4 websites, background runs, notifications, help chat |
| `web/` | The web app (React + TypeScript + Vite) |
| `config/` | `portal.env.example` |
| `data/` | Created at run time (not in git): accounts, run history, logs |
