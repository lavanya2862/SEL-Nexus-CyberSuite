"""How to resolve a finding the agents left open: a concrete suggestion per kind of problem."""
from __future__ import annotations

from dataclasses import dataclass

from .detect import is_vendored
from .models import Finding


@dataclass(frozen=True)
class Advice:
    key: str        # groups findings that share one action
    action: str     # short title of what to do
    how: str        # the concrete steps
    who: str        # "The Remediation Agent on the next scan" or "A person"


def _cwe(f: Finding) -> set[str]:
    return {str(c).upper().removeprefix("CWE-") for c in f.cwe}


def advise(f: Finding) -> Advice:
    """The suggested way to resolve ``f``; most specific match first."""
    rule = (f.rule_id or f.advisory_id or "").lower()
    cwe, cat, title = _cwe(f), (f.category or "").lower(), (f.title or "").lower()
    path = f.file_path or ""
    name = path.rsplit("/", 1)[-1]

    if f.is_dependency:
        if f.fixed_version:
            return Advice("dep-upgrade", f"Upgrade {f.package_name}",
                          f"Upgrade {f.package_name} from {f.installed_version} to {f.fixed_version} or later, update "
                          "the lock file, and run the tests.", "Remediation Agent on the next scan, or a person")
        return Advice("dep-nofix", f"No patched {f.package_name} yet",
                      f"No fixed version of {f.package_name} is published. Check whether the vulnerable feature is used, "
                      "limit exposure, watch the advisory, or replace the package.", "A person")
    if path and is_vendored(path):
        return Advice(f"vendored:{name}", f"Update the bundled library {name}",
                      f"{path} is a copy of a third-party library. Replace it with the library's current release (or "
                      "install it through npm / a pinned CDN link with Subresource Integrity). Do not edit the library "
                      "itself: the next update would undo the change.", "A person")
    if f.remediation_type == "secret_removal" or "798" in cwe or cat == "secret":
        return Advice("secret", "Remove and rotate the exposed secret",
                      "Rotate the credential first, remove it from the code (and Git history), and load it from an "
                      "environment variable or a secret store.", "A person")
    if "weak-sensitive-data-hashing" in rule or cwe & {"327", "328", "916"} or cat == "weak-crypto":
        return Advice("weak-hash", "Hash passwords with a slow, salted algorithm",
                      "Replace the fast hash (MD5/SHA) with argon2 (argon2-cffi), bcrypt, or hashlib.scrypt / "
                      "pbkdf2_hmac with a random salt. Re-hash existing passwords when users next sign in.",
                      "The Remediation Agent on the next scan")
    if rule == "ds-0002" or "user should not be 'root'" in title:
        return Advice("docker-root", "Run the container as a non-root user",
                      "In the Dockerfile, create a user (RUN adduser -D app on Alpine, or useradd -r app) and add "
                      "USER app before CMD/ENTRYPOINT. Make sure the app's files are readable by that user.",
                      "The Remediation Agent on the next scan")
    if rule == "ds-0005" or "add instead of copy" in title:
        return Advice("docker-add", "Use COPY instead of ADD",
                      "Replace ADD with COPY for local files. ADD also unpacks archives and downloads URLs, which can "
                      "bring unexpected content into the image.", "The Remediation Agent on the next scan")
    if "89" in cwe or "sql" in cat:
        return Advice("sqli", "Use parameterised SQL queries",
                      "Pass user values as query parameters (placeholders) instead of building the SQL string; use the "
                      "ORM's query builder where possible.", "The Remediation Agent on the next scan")
    if cwe & {"78", "77"} or "command" in cat:
        return Advice("cmdi", "Run commands without a shell",
                      "Call subprocess with an argument list and without shell=True, and check user input against an "
                      "allow-list of expected values.", "The Remediation Agent on the next scan")
    if "918" in cwe or "ssrf" in cat or "request forgery" in title:
        return Advice("ssrf", "Restrict outbound requests",
                      "Allow only known hosts and the http/https schemes, resolve the address and block private and "
                      "internal IP ranges, and do not follow redirects to them.", "The Remediation Agent on the next scan")
    if "22" in cwe or "path" in cat:
        return Advice("path", "Keep file paths inside the allowed folder",
                      "Resolve the full path and reject it unless it stays inside the intended directory.",
                      "The Remediation Agent on the next scan")
    if "502" in cwe or "deserial" in cat:
        return Advice("deserialize", "Do not deserialise untrusted data unsafely",
                      "Use yaml.safe_load, JSON, or a schema-checked format instead of pickle / yaml.load on data "
                      "that can come from users.", "The Remediation Agent on the next scan")
    if "95" in cwe or "eval" in rule or "code-injection" in cat:
        return Advice("eval", "Remove eval() / new Function()",
                      "Parse data with JSON.parse (or the language's safe parser) and call functions directly instead of "
                      "evaluating strings as code.", "The Remediation Agent on the next scan")
    if "incomplete-sanitization" in rule or ("116" in cwe and "79" not in cwe):
        return Advice("escaping", "Escape every occurrence, not just the first",
                      "Use a replace with the global flag (and escape backslashes too), or a well-tested escaping "
                      "function, so no special character slips through.", "The Remediation Agent on the next scan")
    if "79" in cwe or cat == "xss":
        return Advice("xss", "Stop inserting untrusted text as HTML",
                      "Set text with textContent / innerText or build elements with DOM methods; if HTML is really "
                      "needed, clean it with DOMPurify first. Template engines should keep auto-escaping on.",
                      "The Remediation Agent on the next scan")
    if "overly-large-range" in rule:
        return Advice("regex-range", "Tighten the regular expression range",
                      "Fix the character class so it covers only the intended characters (for example [A-Za-z] "
                      "instead of [A-z]).", "The Remediation Agent on the next scan")
    if "misconfiguration" in cat:
        return Advice(f"config:{rule or title}", "Fix the configuration setting",
                      "Change the setting the scanner names (see the finding's description and references) and "
                      "rebuild.", "The Remediation Agent on the next scan")
    return Advice(f"other:{rule or title}", "Review and fix the code",
                  "Read the finding's description and references, change the code, and scan again. The Security "
                  "Assistant in the app can suggest a patch for this finding.", "The Remediation Agent on the next scan")
