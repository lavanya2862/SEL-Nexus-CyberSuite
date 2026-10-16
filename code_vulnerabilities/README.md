# Code Vulnerabilities (placeholder)

This folder is for the **Code Vulnerabilities** module of SEL Nexus CyberSuite: security flaws found in our
application source code. The project is still to be added.

## Plugging the project in

1. Put the project's files in this folder.
2. Pick a port that no other module uses (8000, 8600, 8700, 8800 and 8900 are taken), for example **8500**.
3. In `../login/config/login.env`, set `CODE_VULN_URL=http://127.0.0.1:8500`. The button on the sign-in page then
   becomes active.
4. Add `Start_Code_Vulnerabilities.cmd` and `Stop_Code_Vulnerabilities.cmd` here. `../Start_All.cmd` and
   `../Stop_All.cmd` call them automatically when they exist. `../defender_infra/Start_Defender_Infra.cmd` is an
   example.

## Optional: use the shared sign-in

Without this step, the button just opens the site, and the site's own login (if it has one) still applies.

To sign people in once for the whole suite, the site checks the `portal_session` cookie and sends signed-out visitors
to `http://127.0.0.1:8000/?next=<page address>`. `../login/README.md` describes the cookie, and
`../login/accounts.py` (`Sessions.read`) has the code to copy. Serve the site on `127.0.0.1`, not `localhost`, so it
receives the cookie.
