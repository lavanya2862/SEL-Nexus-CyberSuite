# SEL Nexus CyberSuite sign-in page

The one place people sign in. At sign-up people tick the domains they need (Defender & Infrastructure, Application
Vulnerabilities); at sign-in they pick one and go straight there. `/?switch=1` lists a signed-in person's domains to
move between (each module's **Switch** button opens it). It also holds the suite's accounts.

## Set up (once)

```
py -3.14 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

## Run

```
.\.venv\Scripts\python.exe server.py      # http://127.0.0.1:8000
```

Usually you don't run it by hand: `..\Start_All.cmd` starts it with every module.

## Settings: `config/login.env`

| Key | Meaning |
|---|---|
| `LOGIN_PORT` | Port of this page (8000) |
| `DEFENDER_INFRA_URL` | Where the Defender & Infrastructure button goes |
| `APP_VULN_URL` | Where the Application Vulnerabilities button goes (http://127.0.0.1:8500). Empty = shown as "Not connected yet" |
| `LOGIN_SIGNUP` | `off` = nobody can create a new account |
| `LOGIN_ALLOWED_EMAIL_DOMAINS` | Only these email domains may sign up |
| `LOGIN_SESSION_HOURS` | How long a sign-in lasts (12) |

## Files in `data/auth/` (never committed)

| File | What |
|---|---|
| `users.json` | Accounts. Passwords are stored only as scrypt hashes |
| `session.key` | Key that signs the session cookie. Every module checks cookies with it. Deleting it signs everybody out |
| `signins.jsonl` | Sign-in, sign-up and sign-out log (never a password) |

## For a module: checking who is signed in

Read the `portal_session` cookie. It is `<body>.<signature>`:

- `body` is base64url JSON: `{"sub": email, "name": ..., "via": "local", "domains": [...], "domain": ..., "iat": ..., "exp": ...}`.
  `domains` are the module ids the account may open (`defender_infra`, `application_vulnerabilities`); `domain` is
  the one picked at sign-in. Accounts made before domains existed have no list and may open every module.
- `signature` is base64url HMAC-SHA256 of `body`, keyed with the base64url-decoded `data/auth/session.key`.

Accept the cookie only if the signature matches, `exp` is in the future and (when there is a `domains` list) your
module's id is in it. Otherwise redirect to
`http://127.0.0.1:8000/?next=<the page's full address>`. `accounts.py` (`Sessions.read`) is the reference code;
Defender & Infrastructure does the same in `defender_infra/Unified_Cyber_Portal/src/portal/auth.py`.
