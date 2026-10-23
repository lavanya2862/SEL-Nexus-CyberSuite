# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Security analysts across the operating companies (OpCos) work in the portal every day: reading new threats, checking exposure, approving fixes and triaging Defender alerts. The same screens are shown to managers and leadership in demos, so the first impression matters as much as day-to-day scanning speed.

## Product Purpose
SEL Nexus CyberSuite is one signed-in website that brings three AI-assisted security tools built on Microsoft Defender for Endpoint together: threat intelligence and hunting (UC1), complete vulnerability extraction and fixing (UC3, with UC1's Fix Centre), and alert triage (UC4). Success is an analyst knowing, within seconds of opening it, what matters most today and acting on it from the same place.

## Positioning
It does not stop at a dashboard: public threat intel is checked against the organisation's own devices, 100% of Defender vulnerability data is exported beyond the KQL row limit, and the agents recommend (and after approval perform) the fix or the triage verdict with the evidence attached.

## Operating Context
- Runs locally on Windows (`Start_SEL_Nexus_CyberSuite.cmd`, http://127.0.0.1:8800); FastAPI backend serving a React + Vite web app.
- Sign-in is local accounts, Amazon Cognito, or off.
- Pages: Dashboard, Vulnerabilities, Threat news, Attack hunting, Fix vulnerabilities, Alert triage, Data quality, Reports, Agents; a notification bell, a guided tour and a help chat on every screen.

## Capabilities and Constraints
- Proof of concept; data comes from each tool's own data folder.
- Dark is the default theme; a light mode stays available (confirmed 2026-10-13).
- No "forgot password" flow exists; do not show one.

## Brand Commitments
- Name: SEL Nexus CyberSuite (wordmark "SEL NEXUS" + "CyberSuite").
- Visual reference pinned by the user on 2026-10-13: a dark slate-navy enterprise sign-in screen with a faint dot grid, a clean bordered card, white headings with a blue second line, solid blue primary buttons, and a rounded-square bot button with a blue glow outline.

## Evidence on Hand
Real pipeline output in UC1/UC3/UC4 `data/` folders (vulnerabilities, threats, verdicts, run history). No customer quotes, benchmarks or external claims exist; do not invent them.

## Product Principles
1. Today's priority first: the most urgent finding is visible without scrolling.
2. Evidence with every recommendation.
3. One look across all tools, so moving between UC1, UC3 and UC4 never feels like changing apps.
4. Plain language over security jargon in labels and help.
