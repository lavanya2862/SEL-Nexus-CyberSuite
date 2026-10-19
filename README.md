# SEL Nexus CyberSuite

One sign-in page in front of the suite's two domains. People pick a domain on the sign-in form and go straight there.

| Folder | What it is | Address |
|---|---|---|
| [login](login/README.md) | Shared sign-in and sign-up page. Holds the one account list for the whole suite, with the domains each account may open | http://127.0.0.1:8000 |
| [defender_infra](defender_infra/README.md) | **Defender & Infrastructure**: threat intelligence, vulnerabilities, fixes and alert triage from Microsoft Defender | http://127.0.0.1:8800 |
| [ApplicationVulnerabilities](ApplicationVulnerabilities/README.md) | **Application Vulnerabilities**: AI agents find security flaws in our application source code, fix them on a branch, validate the fixes and open a pull request for approval | http://127.0.0.1:8500 |

## Start and stop

- **Start_All.cmd** starts the sign-in page and every module, then opens http://127.0.0.1:8000. The first start sets
  everything up by itself (a Python `.venv` per part and the two websites), which takes a few minutes. It needs
  Python 3.11+ and Node.js 22+. Each Defender tool still needs its own `.env` to show data (see `defender_infra`).
- **Stop_All.cmd** stops all of them.

## How the shared sign-in works

1. A person creates an account and ticks the domains they need (Defender & Infrastructure, Application
   Vulnerabilities). When signing in they pick one of them and go straight there.
2. The page sets a signed `portal_session` cookie with the account's domains. Browsers share cookies between ports on
   the same host, so every module on `127.0.0.1` receives it, and each module refuses accounts without its domain.
   The **Switch** button in each module's side menu moves between a person's domains without signing in again.
3. Each module checks that cookie with the key in `login/data/auth/session.key`. Defender & Infrastructure reads it via
   `PORTAL_AUTH_DIR` in `defender_infra/Unified_Cyber_Portal/config/portal.env`.
4. A module that finds nobody signed in sends the visitor to `http://127.0.0.1:8000/?next=<its address>`. After sign-in
   they go straight back.
5. Signing out anywhere clears the cookie, which signs the person out of every module.

Always use `127.0.0.1` (not `localhost`) in addresses, so the browser treats every module as the same host.

## Moving to a server later

When the suite moves behind one HTTPS address, put each module under its own path or subdomain of one domain and
set `LOGIN_COOKIE_SECURE=on` and `PORTAL_COOKIE_SECURE=on`. If you use subdomains, the cookie also needs a `Domain`.
