"""Read-only check before a Threat Intel run: does Defender see the new OpenVPN version on opca-wks-01 yet, and has it
listed the new OpenVPN holes? Run from the Threat Intel folder:

    .venv\\Scripts\\python.exe scripts\\check_not_in_defender.py

Ready = Defender's inventory shows OpenVPN 2.6.x. Then `python -m threat_intel run` puts every hole Defender hasn't listed
under "Not in Defender yet" (Threat news > Affects us).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_intel.api_client import DefenderClient  # noqa: E402
from threat_intel.auth import EntraTokenProvider  # noqa: E402
from threat_intel.config import load_settings  # noqa: E402

DEVICE = "opca-wks-01"
CVES = ["CVE-2026-84471", "CVE-2026-84790", "CVE-2026-88964"]   # OpenVPN holes in the news, 13-14 Oct 2026


def main() -> int:
    settings = load_settings()
    client = DefenderClient(settings.api_base, EntraTokenProvider(settings))
    software = client.run_query(f"""DeviceTvmSoftwareInventory
        | where DeviceName startswith "{DEVICE}" and SoftwareName has "openvpn"
        | distinct SoftwareName, SoftwareVersion""")
    listed = client.run_query(f"""DeviceTvmSoftwareVulnerabilities
        | where DeviceName startswith "{DEVICE}" and CveId in ({", ".join(f'"{c}"' for c in CVES)})
        | distinct CveId, SoftwareVersion""")
    versions = [r["SoftwareVersion"] for r in software]
    print(f"OpenVPN on {DEVICE} in Defender's inventory: {', '.join(versions) or 'none'}")
    for cve in CVES:
        hit = [r for r in listed if r["CveId"] == cve]
        print(f"  {cve}: " + (f"listed by Defender ({hit[0]['SoftwareVersion']}) -> 'Confirmed by Defender'" if hit
                             else "not listed by Defender yet"))
    if any(v.startswith("2.6.") for v in versions):
        print("\nReady: run  .venv\\Scripts\\python.exe -m threat_intel run  and open Threat news > Affects us.")
        return 0
    print("\nNot yet: Defender still reports the old version. Check again in an hour or two.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
