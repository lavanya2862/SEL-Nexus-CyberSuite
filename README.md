# SEL Nexus CyberSuite

One sign-in page in front of the suite's modules. People sign in once and choose where to work.

| Folder | What it is | Address |
|---|---|---|
| [login](login/README.md) | Shared sign-in page and module chooser. Holds the one account list for the whole suite | http://127.0.0.1:8000 |
| [defender_infra](defender_infra/README.md) | **Defender & Infrastructure**: threat intelligence, vulnerabilities, fixes and alert triage from Microsoft Defender | http://127.0.0.1:8800 |
| [ApplicationVulnerabilities](ApplicationVulnerabilities/README.md) | **Application Vulnerabilities**: AI agents find security flaws in our application source code, fix them on a branch, validate the fixes and open a pull request for approval | http://127.0.0.1:8500 |

## Start and stop

- **Start_All.cmd** starts the sign-in page and every module, then opens http://127.0.0.1:8000.
- **Stop_All.cmd** stops all of them.

## How the shared sign-in works

1. A person signs in (or creates an account) on the login page.
2. The page sets a signed `portal_session` cookie. Browsers share cookies between ports on the same host, so every
   module on `127.0.0.1` receives it.
3. Each module checks that cookie with the key in `login/data/auth/session.key`. Defender & Infrastructure reads it via
   `PORTAL_AUTH_DIR` in `defender_infra/Unified_Cyber_Portal/config/portal.env`.
4. A module that finds nobody signed in sends the visitor to `http://127.0.0.1:8000/?next=<its address>`. After sign-in
   they go straight back.
5. Signing out anywhere clears the cookie, which signs the person out of every module.

Always use `127.0.0.1` (not `localhost`) in addresses, so the browser treats every module as the same host.

## Moving to a server later

When the suite moves behind one HTTPS address, put each module under its own path or subdomain of one domain and
set `LOGIN_COOKIE_SECURE=on` and `PORTAL_COOKIE_SECURE=on`. If you use subdomains, the cookie also needs a `Domain`.
