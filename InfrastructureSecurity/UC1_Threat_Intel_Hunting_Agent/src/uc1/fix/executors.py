"""The two "hands" that run the fix script on a lab computer.

  RunCommandExecutor     Azure Run Command (Azure Resource Manager API). Azure VMs only. Scripts may run up to
                         90 minutes. Needs the Azure role "Virtual Machine Contributor" on FIX_RESOURCE_GROUP.
  LiveResponseExecutor   Defender Live Response (Defender API). Any computer with Defender. Scripts stop after
                         10 minutes. Needs Machine.LiveResponse + Library.Manage and Live Response switched on
                         (incl. unsigned scripts) in the Defender portal.

Both send the same script (fix_assets/uc1_fix_app.ps1) with a base64 JSON spec and return its text output.
"""

from __future__ import annotations

import base64
import json
import logging
import random
import time
from collections.abc import Callable
from pathlib import Path

import requests

from uc1.auth import ARM_SCOPE, EntraTokenProvider, TokenProvider
from uc1.config import Settings

log = logging.getLogger("uc1.fix")
SCRIPT = Path(__file__).resolve().parents[1] / "fix_assets" / "uc1_fix_app.ps1"
ARM = "https://management.azure.com"
COMPUTE_API = "2024-07-01"
RETRYABLE = {429, 500, 502, 503, 504}


class FixError(RuntimeError):
    pass


def encode_spec(spec: dict) -> str:
    return base64.b64encode(json.dumps(spec, separators=(",", ":")).encode("utf-8")).decode("ascii")


def script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def runcommand_script(spec: dict) -> str:
    """Run Command takes the script text: replace the param() line with the spec value."""
    lines = script_text().splitlines()
    if not lines or not lines[0].lower().startswith("param("):
        raise FixError("fix script must start with param([string]$Spec)")
    return "\n".join([f"$Spec = '{encode_spec(spec)}'"] + lines[1:])


class _Http:
    """Small retrying HTTP helper (429/5xx/network -> back off; 401 -> new token once)."""

    def __init__(self, tokens: TokenProvider, session: requests.Session | None = None,
                 sleep: Callable[[float], None] = time.sleep, attempts: int = 6):
        self.tokens, self.session, self.sleep, self.attempts = tokens, session or requests.Session(), sleep, attempts

    def request(self, method: str, url: str, *, json_body=None, files=None, data=None, auth=True,
                timeout: float = 120) -> requests.Response:
        refreshed = False
        for attempt in range(1, self.attempts + 1):
            headers = {"Authorization": f"Bearer {self.tokens.token()}"} if auth else {}
            try:
                r = self.session.request(method, url, headers=headers, json=json_body, files=files, data=data, timeout=timeout)
            except (requests.ConnectionError, requests.Timeout) as exc:
                reason = exc.__class__.__name__
            else:
                if r.status_code < 400:
                    return r
                if r.status_code == 401 and auth and not refreshed:
                    refreshed = True
                    continue
                if r.status_code not in RETRYABLE:
                    return r                                       # caller explains 4xx errors
                reason = f"HTTP {r.status_code}"
            if attempt == self.attempts:
                raise FixError(f"Gave up after {attempt} attempts ({reason}) on {method} {url.split('?')[0]}")
            wait = min(60.0, 2 ** attempt) * random.uniform(0.8, 1.2)
            log.info("Retry %d in %.0fs: %s", attempt, wait, reason)
            self.sleep(wait)
        raise AssertionError("unreachable")


def _error_text(r: requests.Response) -> str:
    try:
        err = r.json().get("error", {})
        return f"{err.get('code', '')}: {err.get('message', '')}".strip(": ") or r.text[:300]
    except ValueError:
        return r.text[:300]


# ------------------------------------------------------------------ Azure Run Command
class AzureVMs:
    def __init__(self, settings: Settings, http: _Http, sleep: Callable[[float], None] = time.sleep):
        self.settings, self.http, self.sleep = settings, http, sleep
        self._vms: list[dict] | None = None

    def _get(self, url: str) -> dict:
        r = self.http.request("GET", url)
        if r.status_code == 403 or r.status_code == 401:
            raise FixError(f"Azure refused access ({_error_text(r)}). Give UC1-Hunting-Agent-Lab the role "
                           f"'Virtual Machine Contributor' on resource group {self.settings.fix_resource_group}.")
        if r.status_code >= 400:
            raise FixError(f"Azure error {r.status_code}: {_error_text(r)}")
        return r.json()

    def subscriptions(self) -> list[str]:
        if self.settings.azure_subscription_id:
            return [self.settings.azure_subscription_id]
        subs = [s["subscriptionId"] for s in self._get(f"{ARM}/subscriptions?api-version=2022-12-01").get("value", [])]
        if not subs:
            raise FixError("UC1 can't see any Azure subscription yet. Give UC1-Hunting-Agent-Lab the role "
                           f"'Virtual Machine Contributor' on resource group {self.settings.fix_resource_group} "
                           "(it can take a few minutes to apply).")
        return subs

    def list(self) -> list[dict]:
        if self._vms is None:
            vms = []
            rg = self.settings.fix_resource_group.lower()
            for sub in self.subscriptions():
                # list inside the lab resource group only (the role is granted there, not on the subscription)
                url = (f"{ARM}/subscriptions/{sub}/resourceGroups/{self.settings.fix_resource_group}"
                       f"/providers/Microsoft.Compute/virtualMachines?api-version={COMPUTE_API}")
                while url:
                    body = self._get(url)
                    for vm in body.get("value", []):
                        parts = vm["id"].split("/")
                        group = parts[parts.index("resourceGroups") + 1] if "resourceGroups" in parts else ""
                        if group.lower() != rg:
                            continue                                  # never outside the lab resource group
                        vms.append({"id": vm["id"], "name": vm["name"], "resource_group": group, "location": vm.get("location"),
                                    "computer_name": ((vm.get("properties") or {}).get("osProfile") or {}).get("computerName", "")})
                    url = body.get("nextLink")
            self._vms = vms
        return self._vms

    def find(self, device_name: str) -> dict:
        name = device_name.lower().split(".")[0]
        for vm in self.list():
            if name in (vm["name"].lower(), (vm["computer_name"] or "").lower()):
                return vm
        raise FixError(f"No Azure VM called {device_name} in resource group {self.settings.fix_resource_group}")

    def power_state(self, vm_id: str) -> str:
        body = self._get(f"{ARM}{vm_id}/instanceView?api-version={COMPUTE_API}")
        for s in body.get("statuses", []):
            if s.get("code", "").startswith("PowerState/"):
                return s["code"].split("/", 1)[1]
        return "unknown"

    def _wait_async(self, r: requests.Response, timeout_s: float, what: str) -> dict:
        """Follow Azure's long-running-operation headers until the job finishes."""
        poll = r.headers.get("Azure-AsyncOperation")
        location = r.headers.get("Location")
        deadline = time.monotonic() + timeout_s
        body: dict = {}
        while poll or location:
            if time.monotonic() > deadline:
                raise FixError(f"{what}: no answer from Azure after {int(timeout_s / 60)} minutes")
            self.sleep(min(15.0, max(2.0, float(r.headers.get("Retry-After") or 10))))
            if poll:
                body = self._get(poll)
                status = (body.get("status") or "").lower()
                if status in ("inprogress", "running", "accepted", ""):
                    continue
                if status != "succeeded":
                    raise FixError(f"{what} failed in Azure: {body.get('error', {}).get('message', status)}")
                output = (body.get("properties") or {}).get("output")
                if output is not None:
                    return output
                if not location:
                    return body
                poll = None
            r = self.http.request("GET", location)
            if r.status_code == 202:
                continue
            if r.status_code >= 400:
                raise FixError(f"{what}: Azure error {r.status_code}: {_error_text(r)}")
            return r.json() if r.content else {}
        return r.json() if r.content else body

    def start(self, vm_id: str) -> None:
        r = self.http.request("POST", f"{ARM}{vm_id}/start?api-version={COMPUTE_API}")
        if r.status_code >= 400:
            raise FixError(f"Could not start the VM: {_error_text(r)}")
        self._wait_async(r, 15 * 60, "Starting the VM")

    def run_script(self, vm_id: str, script: str, timeout_s: float = 95 * 60) -> str:
        r = self.http.request("POST", f"{ARM}{vm_id}/runCommand?api-version={COMPUTE_API}",
                              json_body={"commandId": "RunPowerShellScript", "script": script.splitlines()})
        if r.status_code in (401, 403):
            raise FixError(f"Azure refused Run Command ({_error_text(r)}). Give UC1-Hunting-Agent-Lab the role "
                           f"'Virtual Machine Contributor' on resource group {self.settings.fix_resource_group}.")
        if r.status_code == 409:
            raise FixError(f"The VM is busy with another Run Command ({_error_text(r)}); try again in a few minutes")
        if r.status_code >= 400:
            raise FixError(f"Run Command error {r.status_code}: {_error_text(r)}")
        result = self._wait_async(r, timeout_s, "Run Command") if r.status_code == 202 else r.json()
        parts = result.get("value", []) if isinstance(result, dict) else []
        out = [p.get("message", "") for p in parts if "StdOut" in p.get("code", "")]
        err = [p.get("message", "") for p in parts if "StdErr" in p.get("code", "")]
        return "\n".join(out + [e for e in err if e.strip()])


class RunCommandExecutor:
    name = "runcommand"
    label = "Azure Run Command"
    can_start_vms = True

    def __init__(self, settings: Settings, http: _Http | None = None, sleep: Callable[[float], None] = time.sleep):
        self.settings = settings
        self.vms = AzureVMs(settings, http or _Http(EntraTokenProvider(settings, scope=ARM_SCOPE), sleep=sleep), sleep)
        self.started: set[str] = set()                                # VMs this executor switched on (the runner warns)

    def run(self, device_name: str, device_id: str, spec: dict, say: Callable[[str], None] = log.info,
            allow_start: bool = True) -> str:
        vm = self.vms.find(device_name)
        state = self.vms.power_state(vm["id"])
        if state != "running":
            if not allow_start:
                raise FixError(f"Azure access works, but {device_name} is switched off ({state}). The read-only check "
                               "never starts a VM: start it in the Azure portal to check it, or run the remediations "
                               "(UC1 starts it then).")
            if not self.settings.fix_start_vms:
                raise FixError(f"{device_name} is {state}: start it in the Azure portal (or set FIX_START_VMS=1)")
            say(f"{device_name} is {state}: starting it")
            self.vms.start(vm["id"])
            self.started.add(device_name)
            self.vms.sleep(90)                                        # let the VM agent come up
        return self.vms.run_script(vm["id"], runcommand_script(spec))


# ------------------------------------------------------------------ Defender Live Response
class LiveResponseExecutor:
    name = "liveresponse"
    label = "Defender Live Response"
    SCRIPT_NAME = "uc1_fix_app.ps1"

    def __init__(self, settings: Settings, http: _Http | None = None, sleep: Callable[[float], None] = time.sleep):
        self.settings, self.sleep = settings, sleep
        self.http = http or _Http(EntraTokenProvider(settings), sleep=sleep)
        self.base = settings.api_base.rstrip("/")
        self._uploaded = False

    def _explain(self, r: requests.Response, what: str) -> FixError:
        text = _error_text(r)
        if r.status_code in (401, 403):
            return FixError(f"{what}: Defender refused ({text}). Add WindowsDefenderATP application permissions "
                            "Machine.LiveResponse and Library.Manage to UC1-Hunting-Agent-Lab and grant admin consent.")
        if "LiveResponse" in text and ("disabled" in text.lower() or "not enabled" in text.lower()):
            return FixError(f"{what}: {text}. Turn on Live Response and 'Live Response unsigned script execution' "
                            "in Defender: Settings > Endpoints > Advanced features.")
        return FixError(f"{what}: Defender error {r.status_code}: {text}")

    def ensure_script(self) -> None:
        if self._uploaded:
            return
        files = {"file": (self.SCRIPT_NAME, script_text().encode("utf-8"), "application/octet-stream")}
        data = {"Description": "UC1 fix loop: update/remove a vulnerable app (spec from config/fix_catalog.csv)",
                "ParametersDescription": "-Spec <base64 JSON>", "HasParameters": "true", "OverrideIfExists": "true"}
        r = self.http.request("POST", f"{self.base}/api/libraryfiles", files=files, data=data)
        if r.status_code >= 400:
            raise self._explain(r, "Uploading the fix script to the Live Response library")
        self._uploaded = True

    def run(self, device_name: str, device_id: str, spec: dict, say: Callable[[str], None] = log.info) -> str:
        self.ensure_script()
        body = {"Commands": [{"type": "RunScript", "params": [{"key": "ScriptName", "value": self.SCRIPT_NAME},
                                                              {"key": "Args", "value": f"-Spec {encode_spec(spec)}"}]}],
                "Comment": f"UC1 fix {spec.get('id')}: {spec.get('action')} {spec.get('winget') or ','.join(spec.get('remove', []))}"}
        r = self.http.request("POST", f"{self.base}/api/machines/{device_id}/runliveresponse", json_body=body)
        if r.status_code == 400 and "ActiveRequestAlreadyExists" in r.text:
            raise FixError(f"{device_name} is already running a Live Response action; try again in a few minutes")
        if r.status_code >= 400:
            raise self._explain(r, "Starting Live Response")
        action_id = r.json()["id"]
        deadline = time.monotonic() + 2.5 * 3600                     # Defender queues for up to 2 h if the PC is off
        while True:
            self.sleep(10)
            a = self.http.request("GET", f"{self.base}/api/machineactions/{action_id}")
            if a.status_code >= 400:
                raise self._explain(a, "Checking the Live Response action")
            status = a.json().get("status")
            if status in ("Succeeded", "Failed", "TimeOut", "Cancelled"):
                break
            if time.monotonic() > deadline:
                raise FixError(f"Live Response still '{status}' after 2.5 hours (is {device_name} switched on?)")
        link = self.http.request("GET", f"{self.base}/api/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index=0)")
        if link.status_code >= 400:
            errors = "; ".join(e for c in a.json().get("commands", []) for e in (c.get("errors") or []))
            raise FixError(f"Live Response {status}: {errors or _error_text(link)}"
                           + (" (scripts stop after 10 minutes: use Azure Run Command for big apps)" if status == "TimeOut" else ""))
        result = self.http.request("GET", link.json()["value"], auth=False).json()
        return "\n".join(x for x in (result.get("script_output") or "", result.get("script_errors") or "") if x)


def make_executor(method: str, settings: Settings):
    if method == "runcommand":
        return RunCommandExecutor(settings)
    if method == "liveresponse":
        return LiveResponseExecutor(settings)
    raise ValueError(f"unknown fix method {method}")
