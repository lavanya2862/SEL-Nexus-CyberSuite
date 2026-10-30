# Infrastructure Security

Read `docs/ARCHITECTURE.md` before changing anything here. It holds the target structure, the rules, the phase status
and the notes for each agent.

- Say Threat Intel Agent, Vulnerability Agent, Attack Detection Agent and Alert Triage Agent. Never UC1, UC3 or UC4
  in code, labels, routes, file names or messages.
- When working on one agent, change only that agent's folder, its dashboard pages and its dashboard adapter. Anything
  outside that (infra_core, contracts, the Fix Centre, the dashboard shell, Start/Stop scripts) is a separate small
  change: describe it in the agent's notes in `docs/ARCHITECTURE.md` and ask before making it.
- Agents never import each other and never read each other's private data; they share only `data/out/`.
- Nothing changes on a device or in Defender without a person approving it.
- When a phase or an agent's work is done, update its status and notes in `docs/ARCHITECTURE.md` in the same change.
