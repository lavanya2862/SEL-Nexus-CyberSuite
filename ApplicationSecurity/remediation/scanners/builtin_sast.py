"""Lightweight built-in pattern SAST so the pipeline produces useful results with zero tooling.

The rules are deliberately high-signal. Rules with an ``autofix`` are rewritten
deterministically (no LLM); the rest are handed to the LLM fixer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..detect import TEST_PATH, iter_files
from ..models import Finding
from .base import Scanner

PY = {".py"}
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
JAVA = {".java", ".kt"}
GO = {".go"}
PHP = {".php"}
RB = {".rb"}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    suffixes: set[str]
    pattern: re.Pattern
    unless: re.Pattern | None = None
    autofix: tuple[re.Pattern, str] | None = None
    guidance: str = ""
    confidence: str = "medium"
    references: list[str] = field(default_factory=list)


def R(rule_id, title, severity, category, cwe, suffixes, pattern, unless=None, autofix=None, guidance="",
      confidence="medium"):
    return Rule(rule_id, title, severity, category, cwe, suffixes, re.compile(pattern),
                re.compile(unless) if unless else None,
                (re.compile(autofix[0]), autofix[1]) if autofix else None, guidance, confidence,
                [f"https://cwe.mitre.org/data/definitions/{cwe}.html"])


RULES: list[Rule] = [
    # ---------------- Python
    R("PY-EVAL", "Use of eval() on dynamic input", "high", "code-injection", "95", PY,
      r"(?<![\w.])eval\s*\((?!\s*['\"][^'\"]*['\"]\s*\))", guidance="Use ast.literal_eval for literals or an explicit parser."),
    R("PY-EXEC", "Use of exec()", "medium", "code-injection", "95", PY, r"(?<![\w.])exec\s*\((?!\s*['\"])"),
    R("PY-SUBPROCESS-SHELL", "subprocess call with shell=True", "high", "command-injection", "78", PY,
      r"subprocess\.\w+\(.*shell\s*=\s*True", guidance="Pass an argument list and shell=False."),
    R("PY-OS-SYSTEM", "Command execution via os.system/os.popen", "high", "command-injection", "78", PY,
      r"\bos\.(system|popen)\s*\((?!\s*['\"][^'\"{}%+]*['\"]\s*\))", guidance="Use subprocess.run([...]) without a shell."),
    R("PY-PICKLE", "Deserialisation of untrusted data with pickle", "high", "deserialization", "502", PY,
      r"\b(c?pickle|dill|shelve)\.(loads?|open)\s*\(", guidance="Use a safe format such as JSON."),
    R("PY-YAML-LOAD", "yaml.load without a safe Loader", "high", "deserialization", "502", PY,
      r"\byaml\.(load|load_all)\s*\(", unless=r"Loader\s*=\s*(yaml\.)?(Safe|CSafe|Base)Loader",
      autofix=(r"\byaml\.load(_all)?\s*\(", r"yaml.safe_load\1("), guidance="Use yaml.safe_load.", confidence="high"),
    R("PY-SQL-FORMAT", "SQL query built with string formatting", "high", "sql-injection", "89", PY,
      r"\.(execute|executemany|raw|executescript)\s*\(\s*(f['\"]|['\"][^'\"]*['\"]\s*(%|\.format\(|\+)|\w+\s*\+)",
      guidance="Use parameterised queries (placeholders + parameters tuple)."),
    R("PY-REQUESTS-VERIFY", "TLS certificate verification disabled", "medium", "tls-verification", "295", PY,
      r"\b(requests|httpx|session|client)\.?\w*\(.*verify\s*=\s*False",
      autofix=(r"verify\s*=\s*False", "verify=True"), confidence="high"),
    R("PY-UNVERIFIED-SSL", "Unverified SSL context", "medium", "tls-verification", "295", PY,
      r"ssl\._create_unverified_context|CERT_NONE",
      autofix=(r"ssl\._create_unverified_context\(", "ssl.create_default_context("), confidence="high"),
    R("PY-WEAK-HASH", "Weak hash algorithm (MD5/SHA1)", "low", "weak-crypto", "327", PY,
      r"hashlib\.(md5|sha1)\s*\(", unless=r"usedforsecurity\s*=\s*False"),
    R("PY-FLASK-DEBUG", "Flask/Werkzeug debug mode enabled", "medium", "debug-enabled", "489", PY,
      r"\.run\(.*debug\s*=\s*True", autofix=(r"debug\s*=\s*True", 'debug=os.environ.get("FLASK_DEBUG") == "1"'),
      guidance="Read debug flag from the environment; never enable in production."),
    R("PY-MKTEMP", "Insecure temporary file (mktemp)", "medium", "insecure-temp-file", "377", PY,
      r"\btempfile\.mktemp\s*\(", guidance="Use tempfile.mkstemp() or NamedTemporaryFile().", confidence="high"),
    R("PY-JWT-NOVERIFY", "JWT decoded without signature verification", "high", "missing-auth", "347", PY,
      r"jwt\.decode\(.*(verify\s*=\s*False|['\"]verify_signature['\"]\s*:\s*False)"),
    R("PY-BIND-ALL", "Server bound to all interfaces", "low", "information-exposure", "200", PY,
      r"\.run\(.*host\s*=\s*['\"]0\.0\.0\.0['\"]", confidence="low"),
    R("PY-TEMPLATE-STRING", "Server-side template rendered from a dynamic string", "high", "template-injection", "1336",
      PY, r"render_template_string\s*\((?!\s*['\"])"),
    R("PY-MARKUPSAFE", "Unescaped HTML via Markup()/|safe", "medium", "xss", "79", PY, r"\bMarkup\s*\((?!\s*['\"])"),
    # ---------------- JavaScript / TypeScript
    R("JS-EVAL", "Use of eval() / new Function()", "high", "code-injection", "95", JS,
      r"(?<![\w.$])(eval\s*\((?!\s*['\"`][^'\"`]*['\"`]\s*\))|new\s+Function\s*\()"),
    R("JS-CHILD-EXEC", "Shell command built from dynamic input", "high", "command-injection", "78", JS,
      r"\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+|\w+\s*\+)"),
    R("JS-INNERHTML", "Assignment to innerHTML/outerHTML", "medium", "xss", "79", JS,
      r"\.(innerHTML|outerHTML)\s*\+?=\s*(?!\s*['\"`][^'\"`$]*['\"`]\s*;?\s*$)"),
    R("JS-DOCWRITE", "document.write with dynamic content", "medium", "xss", "79", JS,
      r"document\.write(ln)?\s*\((?!\s*['\"][^'\"]*['\"]\s*\))"),
    R("JS-DANGEROUS-HTML", "React dangerouslySetInnerHTML", "medium", "xss", "79", JS, r"dangerouslySetInnerHTML",
      confidence="low"),
    R("JS-SQL-CONCAT", "SQL query built by concatenation/template", "high", "sql-injection", "89", JS,
      r"\.(query|execute|raw)\s*\(\s*(`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|['\"][^'\"]*(SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*\+)",
      unless=None),
    R("JS-TLS-OFF", "TLS verification disabled", "medium", "tls-verification", "295", JS,
      r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\]?\s*=\s*['\"]?0",
      autofix=(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true"), confidence="high"),
    R("JS-WEAK-HASH", "Weak hash algorithm (MD5/SHA1)", "low", "weak-crypto", "327", JS,
      r"createHash\(\s*['\"](md5|sha1)['\"]"),
    R("JS-MATH-RANDOM-TOKEN", "Math.random used for security token", "low", "weak-random", "338", JS,
      r"(token|secret|password|nonce|salt)\w*\s*[:=].*Math\.random\(", confidence="low"),
    # ---------------- Java / Kotlin
    R("JAVA-SQL-CONCAT", "SQL statement built by concatenation", "high", "sql-injection", "89", JAVA,
      r"\.(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery)\s*\(\s*(\"[^\"]*\"\s*\+|\w+\s*\+)"),
    R("JAVA-RUNTIME-EXEC", "Runtime.exec with dynamic input", "medium", "command-injection", "78", JAVA,
      r"Runtime\.getRuntime\(\)\.exec\((?!\s*\"[^\"]*\"\s*\))"),
    R("JAVA-DESERIALIZE", "Java native deserialisation", "medium", "deserialization", "502", JAVA,
      r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)"),
    R("JAVA-WEAK-HASH", "Weak hash/cipher algorithm", "low", "weak-crypto", "327", JAVA,
      r"getInstance\(\s*\"(MD5|SHA-?1|DES|RC4|DESede)(/[^\"]*)?\""),
    R("JAVA-XXE", "XML parser without XXE protection", "medium", "xxe", "611", JAVA,
      r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)", confidence="low"),
    # ---------------- Go
    R("GO-SQL-FMT", "SQL query built with fmt.Sprintf", "high", "sql-injection", "89", GO,
      r"\.(Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*(ctx\s*,\s*)?fmt\.Sprintf"),
    R("GO-TLS-SKIP", "TLS InsecureSkipVerify enabled", "medium", "tls-verification", "295", GO,
      r"InsecureSkipVerify\s*:\s*true", autofix=(r"InsecureSkipVerify\s*:\s*true", "InsecureSkipVerify: false"),
      confidence="high"),
    R("GO-SHELL", "Shell invocation with exec.Command", "medium", "command-injection", "78", GO,
      r"exec\.Command\(\s*\"(sh|bash|cmd)\"\s*,\s*\"(-c|/c)\""),
    # ---------------- PHP / Ruby
    R("PHP-EVAL", "Dynamic code/command execution", "high", "code-injection", "95", PHP,
      r"\b(eval|assert|system|exec|shell_exec|passthru|popen)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)"),
    R("PHP-SQL", "SQL built from request input", "high", "sql-injection", "89", PHP,
      r"(mysqli?_query|->query)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)"),
    R("PHP-UNSERIALIZE", "unserialize() of request data", "high", "deserialization", "502", PHP,
      r"unserialize\s*\(.*\$_(GET|POST|REQUEST|COOKIE)"),
    R("RB-EVAL", "Ruby eval/system with interpolation", "high", "code-injection", "95", RB,
      r"\b(eval|system|exec|`)[\s(]*[\"'].*#\{"),
    R("RB-YAML", "Unsafe YAML.load", "high", "deserialization", "502", RB, r"YAML\.load\s*\(",
      autofix=(r"YAML\.load\s*\(", "YAML.safe_load("), confidence="high"),
]

_COMMENT = re.compile(r"^\s*(#|//|\*|/\*|<!--)")
_TEST_PATH = TEST_PATH


def looks_minified(lines: list[str]) -> bool:
    sample = [l for l in lines[:200] if l.strip()]
    if not sample:
        return False
    longest = max(len(l) for l in sample)
    average = sum(len(l) for l in sample) / len(sample)
    return longest > 1000 or average > 200


def rules_by_id() -> dict[str, Rule]:
    return {r.id: r for r in RULES}


class BuiltinSastScanner(Scanner):
    name, kind, setting = "builtin-sast", "sast", "enable_builtin_sast"
    description = "Built-in high-signal pattern rules (Python, JS/TS, Java, Go, PHP, Ruby)"
    redundant_with: set[str] = set()

    def scan(self, root: Path, workdir: Path) -> list[Finding]:
        findings: list[Finding] = []
        suffixes = set().union(*(r.suffixes for r in RULES))
        for path in iter_files(root, max_bytes=1_000_000):
            if path.suffix.lower() not in suffixes or path.name.endswith((".min.js", ".bundle.js")):
                continue
            rel = path.relative_to(root).as_posix()
            in_tests = bool(_TEST_PATH.search(rel))
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            if looks_minified(lines):
                continue  # bundled/minified vendor code: pattern rules only produce noise here
            rules = [r for r in RULES if path.suffix.lower() in r.suffixes]
            for no, line in enumerate(lines, 1):
                if len(line) > 2000 or _COMMENT.match(line) or "nosec" in line or "nosemgrep" in line:
                    continue
                for rule in rules:
                    if not rule.pattern.search(line) or (rule.unless and rule.unless.search(line)):
                        continue
                    severity = rule.severity
                    if in_tests:
                        severity = {"critical": "medium", "high": "low", "medium": "low"}.get(severity, "info")
                    findings.append(Finding(
                        finding_id=f"BUILTIN-{rule.id}-{len(findings) + 1}", scanner="Builtin-SAST",
                        category=rule.category, severity=severity, title=rule.title,
                        description=(f"{rule.title} detected at {rel}:{no}. {rule.guidance}").strip(),
                        file_path=rel, line=no, snippet=line.strip()[:300], rule_id=rule.id, cwe=[rule.cwe],
                        confidence=rule.confidence, remediation_type="source_code_fix", references=rule.references,
                        raw={"autofix": bool(rule.autofix), "in_tests": in_tests}))
        return findings
