"""Command line interface.

    python -m remediation.cli scan https://github.com/owner/repo         # run locally, write reports
    python -m remediation.cli serve                                      # API + web UI (+ embedded worker)
    python -m remediation.cli worker --concurrency 4                     # dedicated worker process
    python -m remediation.cli submit https://github.com/owner/repo --server http://host:8500 --wait
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .models import SEVERITY_ORDER, JobOptions


def _options(args) -> JobOptions:
    return JobOptions(ref=args.ref, max_findings=args.max_findings, min_severity=args.min_severity,
                      scanners=[s for s in (args.scanners or "").split(",") if s] or None,
                      auto_fix=not args.no_fix, use_llm=not args.no_llm, run_tests=args.run_tests or None,
                      test_command=args.test_command, create_pr=args.create_pr, use_cache=False,
                      pr_on_flagged=getattr(args, "pr_on_flagged", "draft"))


def _add_job_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("repo_url", help="GitHub repository link, e.g. https://github.com/owner/repo")
    p.add_argument("--ref", help="branch, tag or commit (default: repository default branch)")
    p.add_argument("--min-severity", default="low", choices=list(SEVERITY_ORDER))
    p.add_argument("--max-findings", type=int, help="max findings sent to the LLM fixer")
    p.add_argument("--scanners", help="comma-separated subset, e.g. trivy,osv,builtin-sast")
    p.add_argument("--no-fix", action="store_true", help="scan and report only")
    p.add_argument("--no-llm", action="store_true", help="deterministic fixes only")
    p.add_argument("--run-tests", action="store_true", help="run the test suite in the sandbox")
    p.add_argument("--test-command")
    p.add_argument("--create-pr", action="store_true", help="push a branch and open a pull request (needs GITHUB_TOKEN)")
    p.add_argument("--pr-on-flagged", choices=["draft", "skip"], default="draft",
                   help="when validation is flagged: open a draft PR (default) or hold it back")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 2 if unfixed findings at/above this severity remain")


def _gate(findings: list[dict], fail_on: str | None) -> int:
    if not fail_on:
        return 0
    limit = SEVERITY_ORDER[fail_on]
    bad = [f for f in findings if SEVERITY_ORDER.get(f.get("severity"), 5) <= limit
           and f.get("fix_status") not in ("verified", "fixed")]
    if bad:
        print(f"{len(bad)} unresolved finding(s) at or above '{fail_on}'.", file=sys.stderr)
        return 2
    return 0


def cmd_scan(args) -> int:
    from .config import get_settings
    from .github import RepoAccessError, RepoURLError
    from .logging_setup import setup_logging
    from .pipeline import ConsoleReporter, run_repository

    setup_logging()
    reporter = ConsoleReporter(lambda m: print(m, file=sys.stderr))
    imported = {}
    sarifs = [p for group in (args.codeql_sarif or []) for p in group]
    if sarifs:
        imported["codeql"] = [str(Path(p).resolve()) for p in sarifs]
    if args.trivy_json:
        imported["trivy"] = str(Path(args.trivy_json).resolve())
    for path in [*imported.get("codeql", []), *([imported["trivy"]] if "trivy" in imported else [])]:
        if not Path(path).is_file():
            print(f"error: report not found: {path}", file=sys.stderr)
            return 1
    try:
        result = run_repository(args.repo_url, _options(args), reporter, imported=imported or None)
    except (RepoURLError, RepoAccessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    out = Path(args.out) if args.out else get_settings().runs_dir / result.report.run_id
    from .report import write_artifacts
    write_artifacts(out, result.artifacts)
    summary = {"run_id": result.report.run_id, "output_dir": str(out.resolve()), **result.summary()}
    print(json.dumps(summary, indent=2))
    code = _gate([f.public_dict() for f in result.findings], args.fail_on)
    if not code and args.fail_on_flagged and result.report.validation_status == "flagged":
        print("Validation flagged the fixes for investigation.", file=sys.stderr)
        code = 3
    return code


def cmd_serve(args) -> int:
    import uvicorn
    uvicorn.run("remediation.api:app", host=args.host, port=args.port, workers=args.workers,
                proxy_headers=True, log_level="info")
    return 0


def cmd_worker(args) -> int:
    sys.argv = [sys.argv[0]] + (["--concurrency", str(args.concurrency)] if args.concurrency else [])
    from .worker import main
    main()
    return 0


def cmd_submit(args) -> int:
    import httpx
    headers = {"X-API-Key": args.api_key} if args.api_key else {}
    with httpx.Client(base_url=args.server.rstrip("/"), headers=headers, timeout=60) as client:
        resp = client.post("/api/v1/jobs", json={"repo_url": args.repo_url, "options": _options(args).model_dump(
            exclude={"use_cache"}) | {"use_cache": True}})
        if resp.status_code >= 400:
            print(f"error {resp.status_code}: {resp.text}", file=sys.stderr)
            return 1
        job = resp.json()["job"]
        print(f"job {job['id']} {job['status']}", file=sys.stderr)
        if not args.wait:
            print(json.dumps(job, indent=2))
            return 0
        after = 0
        while True:
            events = client.get(f"/api/v1/jobs/{job['id']}/events", params={"after": after}).json()["items"]
            for e in events:
                print(f"[{e['level']}] {e['message']}", file=sys.stderr)
                after = e["id"]
            job = client.get(f"/api/v1/jobs/{job['id']}").json()
            if job["status"] in ("completed", "failed", "cancelled"):
                break
            time.sleep(3)
        print(json.dumps(job, indent=2))
        if job["status"] != "completed":
            return 1
        findings = client.get(f"/api/v1/jobs/{job['id']}/findings").json()["items"]
        return _gate(findings, args.fail_on)


def cmd_capabilities(_args) -> int:
    from .config import get_settings
    from .sandbox import sandbox_available
    from .scanners import capabilities
    s = get_settings()
    print(json.dumps({"scanners": capabilities(), "llm_enabled": s.llm_enabled, "llm_provider": s.resolved_llm_provider,
                      "sandbox": sandbox_available(), "github_token": bool(s.github_token)}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="remediation", description="AI Vulnerability Remediation Pipeline")
    subs = parser.add_subparsers(dest="command", required=True)

    scan = subs.add_parser("scan", help="analyse and remediate a GitHub repository locally")
    _add_job_args(scan)
    scan.add_argument("--out", help="directory for report files (default: data/runs/<run_id>)")
    scan.add_argument("--codeql-sarif", nargs="+", action="append", metavar="SARIF",
                      help="import CodeQL SARIF produced elsewhere (e.g. github/codeql-action) instead of running CodeQL")
    scan.add_argument("--trivy-json", metavar="JSON", help="import a Trivy JSON report instead of running Trivy")
    scan.add_argument("--fail-on-flagged", action="store_true", help="exit 3 if validation flags the fixes")
    scan.set_defaults(func=cmd_scan)

    run = subs.add_parser("run", help="alias of scan (accepts --repo)")
    run.add_argument("--repo", dest="repo_url_opt", required=True)
    for action in scan._actions[1:]:
        if action.dest not in ("help", "repo_url"):
            run._add_action(action)
    run.set_defaults(func=lambda a: cmd_scan(argparse.Namespace(**{**vars(a), "repo_url": a.repo_url_opt})))

    serve = subs.add_parser("serve", help="start the HTTP API and web UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8500)
    serve.add_argument("--workers", type=int, default=1, help="uvicorn processes")
    serve.set_defaults(func=cmd_serve)

    worker = subs.add_parser("worker", help="start a job worker")
    worker.add_argument("--concurrency", type=int)
    worker.set_defaults(func=cmd_worker)

    submit = subs.add_parser("submit", help="submit a repository to a running server")
    _add_job_args(submit)
    submit.add_argument("--server", default="http://127.0.0.1:8500")
    submit.add_argument("--api-key")
    submit.add_argument("--wait", action="store_true")
    submit.set_defaults(func=cmd_submit)

    caps = subs.add_parser("capabilities", help="show which scanners/LLM/sandbox are available")
    caps.set_defaults(func=cmd_capabilities)

    args = parser.parse_args(argv)
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
