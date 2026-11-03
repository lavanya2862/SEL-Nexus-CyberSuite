# Sharing Infrastructure Security data in the team

The agents keep their data on the computer that runs them: databases, published files, reports, the remediation plan
and the dashboard's run history. This data is **never pushed to GitHub** (`data/` and `logs/` are in `.gitignore`),
because it contains tenant information: device names, accounts, IP addresses and Microsoft Defender evidence.

To give every team member the same data, one person (the **data owner**) runs the agents and exports a **snapshot**.
The others **import** that snapshot. The tool is `InfrastructureSecurity/tools/snapshot.py`.

---

## What a snapshot contains

| Included | Left out |
|---|---|
| Every agent's `data/` folder: Threat Intel, Vulnerability, Attack Detection, Alert Triage | `.env` and every other secret |
| The dashboard's run history and audit log (`dashboard/data/`) | Sign-in accounts and session keys (`auth/` folders, `*.key`) |
| Reports (Word, PDF, Excel) and the remediation plan and state | Feed caches (`cache/`): each computer rebuilds them |
| A manifest: who made it, when, on which computer, at which git commit, and each agent's last run | Lock and temporary files |
| Each agent's `logs/` folder, only with `--logs` | The GUIDE backtest database (about 400 MB), unless `--with-guide` is given |

---

## Part 1: data owner, exporting a snapshot

Do this after the agents have run and the data looks right in the portal.

1. **Stop Infrastructure Security.** The databases must not be open while they are copied.
   Double-click `InfrastructureSecurity\Stop_Infrastructure_Security.cmd`, or run it in a terminal.

2. **Open a terminal in the `InfrastructureSecurity` folder.**

   ```
   cd C:\path\to\SEL_Nexus_CyberSuite\InfrastructureSecurity
   ```

3. **Export the snapshot.**

   ```
   dashboard\.venv\Scripts\python.exe tools\snapshot.py export
   ```

   Options:
   - `--logs` also includes each agent's logs (useful when someone needs to investigate a run).
   - `--with-guide` also includes the GUIDE backtest database (about 400 MB).
   - `--all` includes everything except secrets: logs, feed caches and the GUIDE database (about 470 MB). Use it
     when a teammate's runs fail and they need an exact copy of yours.
   - `--out <path>` writes the zip somewhere else.

   The tool prints where it wrote the file and what it contains, for example:

   ```
   Snapshot written: ...\InfrastructureSecurity\snapshots\infra_20261101_0830_2862390.zip (3.9 MB)
     threat_intel         22 files   last run 2026-10-31T18:59:27
     vulnerability        32 files   last run 2026-10-31T17:12:05
     attack_detection      5 files   last run 2026-10-31T18:59:31
     alert_triage          9 files   last run 2026-11-01T00:21:37
     dashboard            16 files   last run -
   ```

4. **Share the zip through private team storage only**: the team's Teams channel files, SharePoint or OneDrive
   folder. Never attach it to e-mail, never put it in git, never upload it to a public location.

5. **Tell the team** which snapshot is current (file name and time), and that you have stopped running the agents
   until the next snapshot, if that is the agreement (see "Rules").

6. **Start Infrastructure Security again** with `Start_Infrastructure_Security.cmd`.

---

## Part 2: team member, importing a snapshot

1. **Get the latest code first**, so your code matches the code that produced the data.

   ```
   cd C:\path\to\SEL_Nexus_CyberSuite
   git pull
   ```

2. **Download the snapshot zip** from the team storage, for example to your Downloads folder.

3. **Stop Infrastructure Security** with `InfrastructureSecurity\Stop_Infrastructure_Security.cmd`.

4. **Open a terminal in the `InfrastructureSecurity` folder.**

5. **Check the snapshot before importing it.**

   ```
   dashboard\.venv\Scripts\python.exe tools\snapshot.py show C:\Users\<you>\Downloads\infra_20261101_0830_2862390.zip
   ```

   It shows who made it, when, the git commit, and each agent's last run. If it prints
   `Note: your code is at ...; run git pull first`, go back to step 1.

6. **Import it.**

   ```
   dashboard\.venv\Scripts\python.exe tools\snapshot.py import C:\Users\<you>\Downloads\infra_20261101_0830_2862390.zip
   ```

   Your current data is **not deleted**: each folder is moved aside as `data.before-import-<time>` (and
   `logs.before-import-<time>` when the snapshot has logs). Your feed caches and sign-in data are carried over.

7. **Start Infrastructure Security** with `Start_Infrastructure_Security.cmd` and open the portal. Every page now
   shows the same data as the data owner's portal.

8. **Clean up later.** Once the imported data looks right, delete the `data.before-import-<time>` folders to save
   space. They are ignored by git.

### First time on a new computer

If you have never started Infrastructure Security on your computer:

1. Clone the repository and create `.env` at the repository root from `.env.example`, with the values the team
   shares through its password manager or Azure Key Vault (never through git or chat).
2. Run `InfrastructureSecurity\Start_Infrastructure_Security.cmd` once. The first start creates each agent's Python
   environment and builds the website. Then run `Stop_Infrastructure_Security.cmd`.
3. Continue with Part 2 above. `dashboard\.venv\Scripts\python.exe` only exists after that first start.

---

## Rules

1. **One data owner runs the agents.** When several people run the agents, each copy drifts away from the others
   until the next snapshot. Agree who the data owner is; everybody else imports.
2. **Never approve remediation or triage decisions on an imported copy** unless the team agrees that you are the
   one acting this time. Approvals act on the real devices and on Defender, whichever copy they came from.
3. **Treat a snapshot as confidential.** It contains tenant data. Delete old snapshots you no longer need.
4. **Stop the services before export and import.** The tool refuses to run while they are up.

---

## Troubleshooting

| Message | What to do |
|---|---|
| `Infrastructure Security is running (ports 8800, ...)` | Run `Stop_Infrastructure_Security.cmd`, then try again. If a port stays in use, close the "Infrastructure Security (keep open)" windows. |
| `Not an Infrastructure Security snapshot (no manifest.json)` | The file is not a snapshot made by this tool, or it was damaged while downloading. Download it again. |
| `Snapshot format ... is not supported` | The snapshot was made with a different version of the tool. Run `git pull` and try again. |
| `Refusing a snapshot with an unexpected path` | The zip was changed after export. Do not import it; ask the data owner for a new one. |
| `dashboard\.venv\Scripts\python.exe` is not found | Infrastructure Security has never started on this computer: see "First time on a new computer". |
| The portal shows old data after the import | Make sure you started Infrastructure Security again after the import, then refresh the browser. |

### Going back to your previous data

1. Stop Infrastructure Security.
2. In each agent folder (for example `agents\threat_intel`), delete or rename `data`, then rename
   `data.before-import-<time>` back to `data`. Do the same for `dashboard`.
3. Start Infrastructure Security again.
