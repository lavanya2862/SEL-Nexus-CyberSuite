# Contracts

Data contracts (JSON Schema, draft 2020-12) describing files published by agents and consumed by the dashboard:

- `threat_intel.dashboard_data.schema.json`: written by Threat Intel Agent (`agents/threat_intel`), read by dashboard (`dashboard/src/dashboard/sources.py:ThreatIntelSource.dashboard`)
- `threat_intel.site_data.schema.json`: written by Threat Intel Agent (`agents/threat_intel`), read by dashboard (`dashboard/src/dashboard/sources.py:ThreatIntelSource.threat`)
- `threat_intel.clues.schema.json`: written by Threat Intel Agent (`agents/threat_intel`), read by dashboard (`dashboard/src/dashboard/sources.py:ThreatIntelSource.clues`)
- `threat_intel.threat_matches.schema.json`: written by Threat Intel Agent (`agents/threat_intel`), read by dashboard (`dashboard/src/dashboard/sources.py:ThreatIntelSource._matches`)
- `vulnerability.dashboard_data.schema.json`: written by Vulnerability Agent (`agents/vulnerability`), read by dashboard (`dashboard/src/dashboard/sources.py:VulnerabilitySource.dashboard`)
- `alert_triage.triage_data.schema.json`: written by Alert Triage Agent (`agents/alert_triage`), read by dashboard (`dashboard/src/dashboard/sources.py:AlertTriageSource.queue`)
