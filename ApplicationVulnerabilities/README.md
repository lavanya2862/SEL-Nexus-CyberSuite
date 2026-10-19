# Application Vulnerabilities: a SEL Nexus CyberSuite module

AI-powered vulnerability detection, remediation and validation for our application source code. This is the
**Application Vulnerabilities** module of SEL Nexus CyberSuite. People sign in once on the suite's shared sign-in page
(`../login`, http://127.0.0.1:8000) and pick this module there. Its website uses the same look as the suite's
Defender & Infrastructure portal.

| Path | What it is |
|---|---|
| `remediation/` | The pipeline and its API (FastAPI): agents, scanners, fixes, validation, reports |
| `web/` | The website (React + TypeScript + Vite, same components and theme as the Defender & Infrastructure portal) |
| `Start_Application_Vulnerabilities.cmd` / `Stop_…cmd` | Start or stop this module on http://127.0.0.1:8500. `../Start_All.cmd` calls them |
| `scripts/`, `examples/`, `tests/` | CodeQL installer, a GitHub Actions example, the test suite |
| `data/`, `tools/`, `.venv/`, `web/dist/` | Made on this computer, never committed: scan history and saved settings, the CodeQL install, Python packages, the built website |

## Start it

Double-click **../Start_All.cmd** (the whole suite) or **Start_Application_Vulnerabilities.cmd** (this module and the
sign-in page). The first start sets itself up: a `.venv` with the Python packages, and the website build in `web/dist`
(needs Python 3.11+ and Node.js 22+). Then sign in at http://127.0.0.1:8000 and choose **Application Vulnerabilities**.

Use `127.0.0.1`, not `localhost`, so the browser shares the suite's sign-in cookie with this module.

## The pipeline

Give it a **GitHub repository link**. Four cooperating components then do the following:
- find the security vulnerabilities
- generate fixes on an isolated Git branch
- prove that the fixes work without breaking anything
- open a pull request for **human-controlled approval**

Nothing is ever merged automatically. If validation fails, the change set is **flagged for investigation**: it becomes a draft PR labelled `needs-investigation`.

```text
 GitHub link
     │
     ▼
 Repository Ingestion ─ validate link · shallow clone · detect languages & manifests
     │
     ▼
 ① Vulnerability Analysis & Prioritization Agent
     CodeQL (primary SAST) + Trivy (deps, secrets, misconfig) + Semgrep/Bandit/OSV/built-in rules
     → normalise → de-duplicate across scanners → risk-score & rank → attach source context
     │
     ▼
 ② AI Remediation Agent              (isolated ai-remediation/* branch, one commit per fix)
     dependency upgrades · npm lockfile refresh · deterministic rewrites · secrets → env vars
     · LLM-generated patches (self-correcting search/replace edits)
     │
     ▼
 ③ Testing & Validation Agent
     static checks · security-regression guard · functional tests (sandbox, auto-rollback)
     · security rescan (fixed findings gone, nothing new introduced)  →  PASSED | FLAGGED
     │
     ▼
 ④ Reporting Component ─ report.md/json · findings.sarif · fixes.patch · per-fix diffs
     │
     ▼
 Human approval ─ PR for review (draft + needs-investigation when flagged) · never auto-merged
```

## Run it by hand (development)

```bash
pip install -e .                 # installs the `remediation` command
remediation serve                # API + website on http://127.0.0.1:8500 (no shared sign-in unless SUITE_LOGIN_URL is set)
cd web; npm ci; npm run dev      # website with hot reload on http://127.0.0.1:5174, API calls go to :8500
```

| Setting | Meaning |
|---|---|
| `SUITE_LOGIN_URL` | The shared sign-in page (http://127.0.0.1:8000). Set = only signed-in people get in. Empty = no sign-in (local use, tests) |
| `SUITE_AUTH_DIR` | The sign-in page's `data/auth` folder; its `session.key` checks the sign-in cookie (`remediation/suite_auth.py`) |
| `DATA_DIR` | Where runs, the database and saved settings live (the Start script uses `./data`) |

1. Open **Settings** and add an LLM (OpenAI-compatible endpoint or Anthropic) and a GitHub token. The token needs
   *Contents* and *Pull requests* read/write permission on the repositories you want fixed.
2. Go to **New Scan**, paste a GitHub link and press **Run pipeline**.
3. Watch the run live under **Pipeline Runs**, review the fixes, then click **Approve & open PR**. Alternatively,
   enable "Push branch & open pull request" before the scan to have the PR opened automatically.

Without an LLM, the pipeline still upgrades dependencies and applies deterministic fixes. Code findings that need
reasoning wait for an AI patch. Without a GitHub token, you can download `fixes.patch` and run `git apply`.

**CodeQL** is the primary SAST engine. To install it locally, run `scripts/install-codeql.ps1` (Windows) or
`scripts/install-codeql.sh`. The Docker image and the GitHub Actions workflow include it. If CodeQL is missing, the
Analysis Agent falls back to Semgrep, Bandit and the built-in rules, and says so in the run.

## The website

The side menu is organised around what a person responsible for security needs to do. A five-step tour opens on the
first visit (the **?** button in the top bar shows it again) and the book button opens a glossary of every term.

| Section | Page | What you get |
|---|---|---|
| Overview | **Dashboard** | *Your path* (scan → agents → approve → handle the rest), the headline numbers, the live (or latest) pipeline with a plain-English summary and *your decision*, what needs your attention, the four agents, findings by severity, recent runs |
| | **New scan** | Paste a GitHub link; shows what each agent will do with the current setup |
| Action center | **Approvals** | Fix sets waiting for a person: what is ready, why a run was flagged, *Approve & open PR*; plus PRs already opened |
| | **Fixes needed** | Issues the agents could not fix, grouped by reason (e.g. indirect dependency, AI quota, no upstream patch) with what to do about each |
| | **Errors** | Setup problems and run failures, each with *How to fix* |
| Agents | **Analysis / Remediation / Validation / Reporting Agent** | One page per agent: what it needs and delivers, its **inputs → outputs → conclusions** for any run (live while running), its detailed results, and its history across runs |
| Results | **Vulnerabilities** | Every issue from the latest scan of each repository, risk-ranked and filterable |
| | **Repositories** | Posture per repository with a findings trend and *Scan again* |
| | **Pipeline runs** / **Reports** | Run history; downloadable report, SARIF and patch for each run |
| Configure | **How it works** / **Settings** | How the agents work; AI model (Gemini, OpenAI-compatible, Anthropic) and GitHub token with connection tests |

Menu badges show the live counts for Approvals, Fixes needed, Errors and open vulnerabilities, and each agent has a
status dot (working, done, warning). The bell in the top bar sums up what needs you. Clicking any finding opens its
details in a side drawer: the code, why it ranks where it does, and the fix with its diff and checks. The **Security
Assistant** (chat button, bottom right) answers questions about the run or finding you are looking at.

## Validation in detail

| Layer | What it checks | Fails when |
|---|---|---|
| Static | Every edited file still parses (Python AST, JSON, TOML, YAML, `node --check`) | A fix breaks syntax |
| Security-regression guard | The patch itself | It adds `nosec`/`eslint-disable`-style suppressions, disables TLS verification, skips or deletes tests, removes assertions or auth/CSRF controls, hard-codes credentials, or adds `eval`/`shell=True` |
| Functional | The project's own tests, baseline vs. after, in the sandbox (`SANDBOX_MODE=docker`) | Tests that passed before now fail. The responsible commit is isolated and reverted |
| Security rescan | All scanners re-run on the fix branch | A targeted finding is still reported, or a new high/critical issue appears (e.g. an upgraded package with a new advisory) |
| Policy | Change risk | Warns on major-version upgrades |

Any failure sets the verdict to **FLAGGED**. That run's PR is opened as a draft with the `needs-investigation` label,
or held back entirely with `pr_on_flagged=skip`.

## GitHub Actions

[`examples/github-actions/ai-remediation.yml`](examples/github-actions/ai-remediation.yml) runs the official **CodeQL**
and **Trivy** actions, imports their results into the pipeline (`--codeql-sarif`, `--trivy-json`), then remediates,
validates, uploads the consolidated SARIF to code scanning, publishes the report, and opens the PR.

```bash
remediation scan https://github.com/org/repo --codeql-sarif results/*.sarif --trivy-json trivy.json \
  --create-pr --fail-on-flagged
```

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/jobs` | `{"repo_url": "https://github.com/o/r", "options": {...}}` |
| `GET` | `/api/v1/jobs`, `/api/v1/jobs/{id}` | status, live `stages` timeline, summary, artifacts |
| `GET` | `/api/v1/jobs/{id}/events?after=` | agent activity log |
| `GET` | `/api/v1/jobs/{id}/report`, `/findings?severity=` | results |
| `GET` | `/api/v1/jobs/{id}/artifacts/{report.md,report.json,findings.sarif,findings.json,fixes.patch,fixes.mbox}` | downloads |
| `POST` | `/api/v1/jobs/{id}/publish` | **human approval**: replay the fix commits onto a fresh clone, push, open the PR |
| `POST` | `/api/v1/jobs/{id}/cancel`, `/retry` | control |
| `GET` | `/api/v1/dashboard` | aggregated posture |
| `POST` | `/api/v1/assistant/chat` | `{"messages": [...], "job_id": "...", "finding_id": "..."}` |
| `GET`/`PUT` | `/api/v1/settings`, `POST /settings/test-llm`, `/settings/test-github` | runtime configuration (localhost or API key only) |

Job options: `ref`, `min_severity`, `max_findings`, `scanners`, `auto_fix`, `use_llm`, `fix_dependencies`, `run_tests`,
`test_command`, `install_command`, `verify_with_rescan`, `create_pr`, `pr_on_flagged` (`draft`|`skip`), `use_cache`.
Interactive docs are at `/docs`.

## Production and scaling

```bash
cp .env.example .env && docker compose up -d --build && docker compose up -d --scale worker=6
```

- **Workers:** stateless API replicas, plus workers that pull jobs from PostgreSQL (`FOR UPDATE SKIP LOCKED`). Each
  job holds a renewable lease, and jobs from crashed workers are re-queued.
- **Storage:** artifacts are kept in the database, so nodes share no disk.
- **Limits:** a cap on queued jobs, rate limiting, per-stage and per-job timeouts, a repository size limit, and an
  LLM concurrency limit with backoff.
- **Efficiency:** identical in-flight requests are de-duplicated, and results are cached per commit.
- **Monitoring:** `/health`, `/ready`, Prometheus `/metrics`, and JSON logs.

## Security model

- **Input:** only allow-listed Git hosts, with strict owner/repo/ref validation.
- **Git:** runs hardened (no hooks, no local transports, no submodules). The token is sent in an HTTP header, never in a URL.
- **Repository code is never executed unless you opt in.** The npm lockfile refresh uses `--ignore-scripts`, and tests
  run only in the sandbox (Docker: no network, dropped capabilities, resource limits).
- **Secrets:** credentials are stripped from the environment of every scanner and sandbox, and secrets are redacted
  from everything sent to the LLM. UI-managed keys live in `DATA_DIR/runtime_settings.json`, are never returned in
  full, and can only be changed from localhost unless `API_KEYS` is set.
- **LLM edits:** they must stay inside the repository, cannot touch `.git` or CI workflows, are applied all-or-nothing,
  and are syntax-checked.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Limitations

- Pattern rules are high-signal but not exhaustive; CodeQL and Semgrep give much deeper coverage.
- Automated lockfile regeneration covers npm. Other ecosystems get the exact command to run.
- A finding disappearing after a fix is strong evidence, not proof. The human review gate exists for that reason.
