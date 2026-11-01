# Fresh start: clearing the old lab data from SEL Nexus CyberSuite

> Written 31 Oct 2026. Use this once, after moving to the new Microsoft account, so the website shows **only the
> new account's data**. Follow the steps in order and tick each box.
>
> **Folder used everywhere below** (we call it *the suite folder*):
> `C:\Users\2862390\Desktop\PoC\SEL_Nexus_CyberSuite`
>
> **Nothing here touches Microsoft, Azure or the VMs.** It only clears files on this PC.

---

## Step 1. Stop the suite (1 min)

1. Open **File Explorer** (Windows key + E).
2. Go to the suite folder: paste `C:\Users\2862390\Desktop\PoC\SEL_Nexus_CyberSuite` into the address bar at the top and press **Enter**.
3. Double-click **`Stop_All.cmd`**.
4. A black window opens and closes by itself. Wait about 10 seconds.

✅ **Check:** open http://127.0.0.1:8000 in your browser. It should say the page **can't be reached**. That means everything is stopped.

- [ ] Done

---

## Step 2. Switch off the two automatic runs in Task Scheduler (3 min)

### What this is
**Task Scheduler** is a built-in Windows program that starts things automatically at set times, like an alarm
clock for programs. Earlier in the project we set up two "alarms" that run our tools on their own:

| Task name | What it runs | When |
|---|---|---|
| **UC1 Threat Hunting Agent** | The **old** threat-intel tool in the `11. cyber` folder | Every 4 hours |
| **UC3 Defender Run** | The **old** vulnerability tool in the `11. cyber` folder | Every 6 hours |

Both still point to the **old** `11. cyber` copy and the **old** account. We don't use them any more, so we
switch them off. (They don't write into the SEL Nexus folder, but they keep calling the old account.)

### How to switch them off
1. Press the **Windows key**, type **`Task Scheduler`**, and click **Task Scheduler** in the results.
2. A window opens. On the **left**, click **Task Scheduler Library** (the top item in the tree).
3. The **middle** of the window now shows a list of tasks. Find **`UC1 Threat Hunting Agent`**.
   (If the list is long, click the **Name** column header to sort it A–Z.)
4. **Right-click** `UC1 Threat Hunting Agent` → click **Disable**.
5. The **Status** column for it changes from *Ready* to **Disabled**.
6. Do the same for **`UC3 Defender Run`**: right-click → **Disable**.
7. Close Task Scheduler.

✅ **Check:** both tasks show **Disabled** in the Status column.

> **Disable, don't delete.** Disabling is like pausing an alarm, so you can switch it back on later
> (right-click → **Enable**). If one of them is running right now (Status *Running*), right-click → **End** first,
> then **Disable**.

- [ ] UC1 Threat Hunting Agent disabled
- [ ] UC3 Defender Run disabled

---

## Step 3. Make a backup folder (1 min)

Instead of deleting straight away, we **move** the old files into a backup folder. If anything goes wrong, you can
move them back. Delete the backup a week later when everything works.

1. In File Explorer go to `C:\Users\2862390\Desktop\PoC`.
2. Right-click an empty area → **New → Folder** → name it **`old_lab_backup`** → **Enter**.
3. Inside it, make 5 more folders the same way: **`vulnerability`**, **`threat_intel`**, **`attack_detection`**,
   **`alert_triage`**, **`dashboard`**.

**How to move files in the next steps:** select the items (hold **Ctrl** and click each one), press **Ctrl + X**
(cut), open the matching backup folder, press **Ctrl + V** (paste).

- [ ] Done

---

## Step 4. Clear the Vulnerability tool (Weak spots tab) (3 min)

Folder: `C:\Users\2862390\Desktop\PoC\SEL_Nexus_CyberSuite\InfrastructureSecurity\agents\vulnerability`

1. Open the **`data`** folder inside it.
2. Select **everything** inside `data` (**Ctrl + A**) and move it to `old_lab_backup\vulnerability`.
   That's: `vulnerability.duckdb`, `lake`, `raw`, `dashboard`, `reporting`, `status`, `old_reports`,
   `reference`, `ai`.
   - *Optional:* leave **`ai`** where it is. It holds the AI fix texts already written, which saves AI usage.
     It refreshes itself when apps change.
3. Go back up one level. Move the folder **`data.before-restore`** to the backup too (if it's there).
4. Open the **`logs`** folder → select all files (**Ctrl + A**) → move them to the backup.

✅ **Check:** `data` and `logs` are now **empty** (or `data` only has `ai`).

> Leave `config`, `.venv`, `src`, `lab` and the **`.env`** file alone.

- [ ] Done

---

## Step 5. Clear the Threat intel tool (Threat news, Fix Centre) (3 min)

Folder: `...\InfrastructureSecurity\agents\threat_intel`

1. Open **`data`**. Move these to `old_lab_backup\threat_intel`:

   | Move | What it is |
   |---|---|
   | `threat_intel.duckdb` | The tool's database |
   | `raw`, `out`, `dashboard`, `reports`, `old_reports` | Old downloads, results, website data, reports |
   | **`fix`** | The old Fix Centre plan, with the **old computers**. **This one must go** |
   | `alerts.jsonl`, `last_run.json`, `last_attack_check.json`, `metrics.json` | Old alerts, last-run status, numbers |

2. **Keep** (don't move):
   - **`cache`**: public threat news (CISA, NVD, etc.). Not tied to any account, and it makes the first run much faster.
   - **`demo_notes.md`**: your notes.
3. Go up one level → move **`data.before-restore`** to the backup (if it's there).
4. Open **`logs`** → select all → move to the backup.

- [ ] Done

---

## Step 6. Clear the Attack detection tool (Attack hunting tab) (2 min)

Folder: `...\InfrastructureSecurity\agents\attack_detection`

1. Open **`data`** → select **everything** (**Ctrl + A**) → move to `old_lab_backup\attack_detection`.
   That's: `attack_detection.duckdb`, `out`, `raw`, `reports`, `cache`, `last_run.json`.
2. Open **`logs`** → select all → move to the backup.

- [ ] Done

---

## Step 7. Clear the Alert triage tool (Alert response tab) (3 min) ⚠️ one big file stays

Folder: `...\InfrastructureSecurity\agents\alert_triage`

1. Open **`data`**. Move these to `old_lab_backup\alert_triage`:
   `alert_triage.duckdb`, `export`, `verdicts`, `raw`, `packets`, `reports`, `feedback`, `cache`, `last_run.json`
2. ⚠️ **KEEP these two, don't move them:**
   - **`guide.duckdb`** (about 400 MB): Microsoft's public practice dataset that measures the agent's accuracy.
     It isn't lab data, and rebuilding it takes very long.
   - **`inbox`**: where the lab answer sheet and practice data go.
3. Go up one level → move **`data.before-restore`** to the backup (if it's there).
4. Open **`logs`** → select all → move to the backup.

✅ **Check:** `data` now only has `guide.duckdb` and `inbox`.

- [ ] Done

---

## Step 8. Clear the website's history (2 min)

Folder: `...\InfrastructureSecurity\dashboard`

1. Open **`data`** → move **`runs`**, **`audit`** and **`help`** to `old_lab_backup\dashboard`.
   (Old run history, the audit trail and old chat questions.)
2. Go up one level → move **`data.before-restore`** to the backup (if it's there).

- [ ] Done

---

## Step 9. Update the friendly computer names (2 min)

The website shows computers as **VM 1 / VM 2** instead of their real names. That list still has the old names.

1. Open `...\InfrastructureSecurity\dashboard\config\device_names.csv` with **Notepad**
   (right-click → **Open with → Notepad**).
2. On 31 Oct it looked like this:
   ```
   real_name,show_as
   opca-wks-01,VM 1
   opcc-wks-01,VM 2
   opcb-wks-01,VM 3
   opcd-wks-01,VM 4
   OpCo A,VM 1
   OpCo C,VM 2
   OpCo B,VM 3
   UNMAPPED,VM 4
   Unassigned,VM 4
   ```
3. Delete the **two old computer lines** (`opca-wks-01,VM 1` and `opcc-wks-01,VM 2`). Leave the other lines as they are.
   Your new computers then show as **VM 3** (opcb) and **VM 4** (opcd).
   - Want them shown as **VM 1 / VM 2** instead? Don't change it by hand: the `OpCo …` lines must change at the
     same time. Ask Claude to do it.
4. **File → Save**, close Notepad.

- [ ] Done

---

## Step 10. Things you must NOT delete

| Keep | Where | Why |
|---|---|---|
| Every **`.env`** file | in each agent folder | Your keys for the new account |
| Every **`config`** folder | in each agent folder and `dashboard` | Settings and rules |
| Every **`.venv`** folder | in each agent folder, `dashboard`, `login` | The installed Python for each part. Deleting it means a long reinstall |
| **`login\data\auth\users.json`** and **`session.key`** | `SEL_Nexus_CyberSuite\login\data\auth` | The website's login accounts. Deleting them **locks everyone out** (`signins.jsonl` is only a log and can go) |
| `guide.duckdb` and `inbox` | `agents\alert_triage\data` | See step 7 |

---

## Step 11. Start again and fill it with new data (about 30 min, mostly waiting)

1. In the suite folder double-click **`Start_All.cmd`**. The browser opens http://127.0.0.1:8000. Sign in.
2. Open **Infrastructure Security**. Most pages say **"no data yet"**. That's expected.
3. In the menu open **Agents** and run them **one at a time, in this order**, waiting for each to finish:
   1. **Vulnerability** (a few minutes)
   2. **Threat intel** (10–20 minutes the first time)
   3. **Attack detection**
   4. **Alert triage**
4. Check the pages: Weak spots, Threat news, Attack hunting, Alert response should now show **only the new
   computers** (VM 1 / VM 2 = your new names).

| If you see | Do this |
|---|---|
| An agent fails with "401" / "unauthorized" | The `.env` keys for the new account are wrong, or the secret was copied as the *Secret ID*. Tell Claude (never paste the key itself) |
| Weak spots shows 0 vulnerabilities | Defender hasn't assessed the new computers yet. Wait a few hours after onboarding and run Vulnerability again |
| Old computer names still appear | Step 9 not saved, or an old device is still reporting in that account. Tell Claude |
| A page says the tool is "starting" for minutes | Run `Stop_All.cmd`, then `Start_All.cmd` |

- [ ] All 4 agents ran
- [ ] Pages show only the new computers

---

## Step 12. A week later

When everything has worked for a few days, delete `C:\Users\2862390\Desktop\PoC\old_lab_backup`
(right-click → **Delete**). Until then it's your undo button.

**Undo (if needed):** run `Stop_All.cmd`, move the files from `old_lab_backup` back into the same folders, run
`Start_All.cmd`.
