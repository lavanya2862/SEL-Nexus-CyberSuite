# Review: the proposed "True Alarm" scoring rules

*13 Oct 2026. A review of the colleague's proposal (IOC match +20, several sources agree +15, malicious behaviour +15, alert repeats +10, plus severity and critical-asset signals), compared with industry practice and with what the Alert triage agent already does.*

## Verdict in one line

**The ideas are good. The rules as written are not safe to use as they stand.** They pick the right signals, but they have no pass mark, no "this is harmless" side, and no hard "always escalate" rules. They also mix up "is it real?" with "how bad would it be?". We should merge them into the current design, not swap the design for them.

## What is good about it

- **These are the signals real analysts use.** Matches against known-bad lists, several tools agreeing, attacker-like behaviour, repeats and important assets are all standard.
- **Scoring is an accepted industry method.** Splunk's "Risk-Based Alerting" and Microsoft Sentinel's entity risk scores add up points in the same way.
- **It is easy to explain.** "This scored 45 because..." is easy for an auditor to follow.
- **Most of it is already in the agent** (see the mapping table at the end).

## The problems

### 1. There is no pass mark
"Most conditions met" plus points, but no number that means "true alarm". Is 30 enough? 45? Without a threshold, two people will score the same alert differently.

### 2. It only looks for reasons to say "attack"
There are no minus points for innocent explanations:
- an approved IT admin account running a script from the IT folder
- a known company vulnerability scanner
- a service account locking itself out
- a harmless antivirus test file (EICAR)
- planned work with a change ticket

It also has no "harmless but expected" answer, which Microsoft Defender calls *Informational, expected activity*. That is one of Defender's three official answers. In Microsoft's GUIDE dataset of real incidents, it is a large share of all incidents.

**Example: a false alarm the rules would call an attack.** IT pushes a PowerShell update script to 50 servers.
- PowerShell use: +15
- Many hosts: +10
- Defender plus sign-in logs: +15
- Production servers count as a critical asset

That totals 40 or more, so it is marked **True alarm**. It is really planned admin work.

### 3. Adding up points can miss the most dangerous attacks
Some single facts are serious on their own, whatever the score. Here is an attacker using a brand-new IP address (on no threat list) who steals passwords on one computer, once:
- No match against known-bad lists: 0
- Only one tool saw it: 0
- Malicious behaviour: +15
- No repeats: 0

That totals **15**, which is probably "not a true alarm". In reality it is one of the most serious alerts there is. Industry practice, and our agent, use **hard rules** for these cases: password theft, ransomware, a correct password after many wrong ones, or the security log being wiped. A points total must never be able to outvote those rules.

### 4. A match against known-bad lists (+20) is weaker than it looks
- **IP addresses change hands.** Attackers rent cloud servers, VPN and Tor addresses for a few hours. Next week the same address may belong to an innocent company. An old entry on a list gives a false alarm.
- **One antivirus out of 70 flagging a file is not proof.** You need a minimum number of detections, or a high-confidence source.
- **No match does not mean safe.** A new attack is on no list yet.
- Security experts rank IP addresses and file fingerprints as the weakest kind of evidence; attacker behaviour is the strongest. (This ranking is called the "Pyramid of Pain".)
- **Licensing:** VirusTotal's free API may not be used in commercial work, so we cannot use it for a real company. We already use free sources that allow this: abuse.ch, AlienVault OTX, AbuseIPDB and GreyNoise. MISP is free, but someone has to run it and feed it data.

### 5. Repeats can mean the opposite of an attack
The same alert firing again and again is very often a **noisy detection rule** catching the same harmless software every day. Industry practice is to *tune* such rules, not to treat them as more dangerous. An alert on many hosts at once can be a worm, or a normal software rollout. What matters is **what we decided last time** for the same alert, account and device. The agent already checks the last 90 days of decisions.

### 6. "Is it real?" and "how bad would it be?" are different questions
NIST SP 800-61 and every SOC keep these apart:
- **Is it real?** (true or false alarm): decided by the evidence.
- **How urgent?** (priority): decided by severity and how important the asset is.

A false alarm on the CEO's laptop is still a false alarm. If "critical asset" and "high severity" add points toward *true alarm*, VIP alerts get marked as attacks just for being VIP. The right use is: **critical asset means never auto-close, and handle it first.** That is what our "privileged account" and "high severity" rules already do.

### 7. Points are counted twice
- "Multiple evidence sources agree" (+15) and "multiple security tools detected the same activity" (in the summary) are the same thing.
- Microsoft Defender already groups alerts from different tools into one incident. So most incidents would get the +15 automatically, just by being an incident.

### 8. We do not have all the data the rules ask for
The example "Firewall saw C2 traffic" needs firewall logs. The agent currently reads:
- Defender endpoint data, including the network connections each computer makes
- Entra sign-ins
- Office 365 activity
- Windows security events

**It does not read firewall logs.** "Data exfiltration" also needs data-volume logs we do not collect. A rule we cannot measure always scores zero.

### 9. The weights are guesses
Why is a known-bad match worth 20 and behaviour worth 15? In industry, weights are **tested against incidents already labelled by analysts** and adjusted until the missed-attack rate is acceptable. We have the tool to do this: the GUIDE backtest.

### 10. Some "malicious behaviours" are often harmless
- **Impossible travel** (sign-ins from two distant countries close together) is most often a VPN or a mobile network.
- **PowerShell** is used by IT all day.

These need the context checks our playbooks already do: who ran it, from which folder, and whether the account is on our approved list.

### 11. A yes/no answer is not enough
There must be a **"not sure, a person must look"** answer. Forcing every alert into true or false is how real attacks get closed.

## Can we write our own rules?

**Yes. In fact everyone has to.** No standard publishes a ready-made list of "true alarm rules":
- **NIST SP 800-61** says *what* to do: analyse, use evidence, prioritise by impact. It leaves the rules to each organisation.
- **MITRE ATT&CK** gives a catalogue of attacker behaviours, not decisions.
- **Microsoft** gives the answer labels and sample playbooks. Every company adapts them.

So writing our own rules is normal. Using them *blindly* is not. Our own rules are only acceptable if they are:
1. **Based on standard ideas.** Use MITRE technique codes and Defender's labels, and keep "is it real?" separate from "how urgent?".
2. **Balanced.** Signals for "attack" *and* signals for "harmless", plus a "not sure" answer.
3. **Protected by hard safety rules** that a score cannot outvote.
4. **Tested against labelled data** before use: the GUIDE backtest, plus our lab incidents.
5. **Owned and signed off** by the SHV security team, and reviewed after real incidents.
6. **Written down and version-controlled**, so we can explain any decision later.

## Recommendation

Do not replace the current design. **Add the colleague's score as one more piece of evidence:**

1. Calculate a points score for every incident, with minus points for innocent explanations.
2. Show the score card on the incident page ("Score 45: known-bad IP +20, ...").
3. Give the score to the AI as evidence, next to the logs.
4. Keep the hard safety rules on top. A score can never close password theft or ransomware.
5. Use critical asset and severity for **priority** and **no auto-close**, not as proof of attack.
6. Run the GUIDE backtest with and without the score. Keep it only if it lowers missed attacks or closes more false alarms safely. Set the pass mark from that test, not by guessing.

## How the proposal maps onto what the agent already does

| Colleague's rule | Already in the agent? | Where |
|---|---|---|
| Match against known-bad lists | Yes, and stronger: a confirmed-malicious match forces escalation | `high_ti_match` rule; threat-intel lookups (`tools/ti.py`) |
| Several sources agree | Partly: Defender's grouping into incidents, plus log searches across endpoint, sign-in and Office data | Playbook log searches; Q09 "other alerts on the same device" |
| Malicious behaviour | Yes: one playbook per behaviour, with context checks | 13 playbooks; MITRE codes |
| Repeats over time | Yes, as history of past decisions (not as plus points) | 90-day history; Q09 |
| High severity | Yes: never auto-closed | `high_no_close` rule |
| Critical asset (admin, VIP) | Yes: escalated, never auto-closed | `privileged_account` rule; VIP watchlist |
| Firewall evidence | **No.** Firewall logs are not connected. | Would need a firewall log source in Sentinel |
| Points total and pass mark | **No.** This is the genuinely new part. | Could be added as a score card |
| Minus points for harmless causes | Yes, through watchlists (approved admins, scanners, service accounts) | `config/watchlists/` |
