# infra_core

Code every Infrastructure Security agent and the dashboard share. No security logic lives here: that belongs in the
agent that does it (see [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md), rule 4).

| Module | What it does |
|---|---|
| `docstyle.py` | The look of every Word/PDF report and chart (fonts, colours, tables, PDF conversion) |
| `settings.py` | `env(name, *old_names)`: reads a setting by its agent name and still accepts the old name, with a warning |

It has no `.venv` of its own. The Start script puts `src` on each agent's and the dashboard's path (an
`infra_core.pth` file in their `.venv`), so every part imports it as `infra_core`. Its dependencies (python-docx,
matplotlib) are in the requirements of the agents that write reports.

A change here can affect every agent: run the safety net (`tests/`) before committing.
