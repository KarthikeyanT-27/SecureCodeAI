import os
import re
from typing import List, Set


# ===================== DATA MODEL =====================
class Vulnerability:
    def __init__(
        self,
        file_path: str,
        line: int,
        vuln_type: str,
        severity: str,
        score: float,
        explanation: str,
        recommendation: str,
        lang: str,
        code_snippet: str,
        cwe: str
    ):
        self.file_path = file_path
        self.line = line
        self.vuln_type = vuln_type
        self.severity = severity
        self.score = score
        self.explanation = explanation
        self.recommendation = recommendation
        self.lang = lang
        self.code_snippet = code_snippet
        self.cwe = cwe

    def to_dict(self):
        return self.__dict__


# ===================== LANGUAGE DETECTION =====================
EXT_LANG = {
    ".php": "php",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".js": "javascript",
    ".py": "python",
    ".html": "html"
}


def get_lang(filename: str) -> str:
    return EXT_LANG.get(os.path.splitext(filename)[1].lower(), "unknown")


# ===================== UNIVERSAL TAINT SOURCES =====================
TAINT_SOURCES = [
    r"\$_(GET|POST|REQUEST|COOKIE)",
    r"request\.getParameter",
    r"\binput\s*\(",
    r"\bargv\s*\[",
    r"document\.location",
    r"window\.location",
    r"document\.cookie"
]


# ===================== TAINT COLLECTION =====================
def collect_taint(lines: List[str]) -> Set[str]:
    tainted = set()
    for line in lines:
        for src in TAINT_SOURCES:
            if re.search(src, line, re.IGNORECASE):
                m = re.search(r"(\$?\w+)\s*=", line)
                if m:
                    tainted.add(m.group(1).replace("$", ""))
                if "argv" in line:
                    tainted.add("argv")
    return tainted


def propagate_taint(lines: List[str], tainted: Set[str]) -> Set[str]:
    """
    SAFE taint propagation:
    - No regex crashes
    - Works with quoted SQL strings
    - Stable fixpoint loop
    """
    changed = True
    while changed:
        changed = False
        for line in lines:
            line = line.strip()

            # Skip comments / HTML
            if not line or line.startswith(("//", "#", "<", "/*", "*")):
                continue

            m = re.search(r"(\$?\w+)\s*=\s*(.+)", line)
            if not m:
                continue

            left = m.group(1).replace("$", "")
            rhs = m.group(2)

            for t in list(tainted):
                safe_t = re.escape(t)
                if re.search(rf"\${safe_t}\b|\b{safe_t}\b", rhs):
                    if left not in tainted:
                        tainted.add(left)
                        changed = True
    return tainted


# ===================== RULES (UNCHANGED) =====================
RULES = [

    {
        "name": "SQL Injection",
        "sink": r"(mysqli_query|executeQuery|executeUpdate|cursor\.execute|query\()",
        "taint": True,
        "severity": "Critical",
        "score": 9.8,
        "cwe": "CWE-89",
        "fix": "Use prepared / parameterized queries"
    },

    {
        "name": "Command Injection",
        "sink": r"(system|exec|shell_exec|os\.system|Runtime\.getRuntime)",
        "taint": True,
        "severity": "Critical",
        "score": 9.7,
        "cwe": "CWE-78",
        "fix": "Avoid OS command execution"
    },

    {
        "name": "Reflected XSS",
        "sink": r"(echo|print|<\?=)",
        "taint": True,
        "severity": "High",
        "score": 8.5,
        "cwe": "CWE-79",
        "fix": "Escape output properly"
    },

    {
        "name": "DOM-based XSS",
        "sink": r"(innerHTML|document\.write|script\.src)",
        "taint": False,
        "severity": "Critical",
        "score": 9.2,
        "cwe": "CWE-79",
        "fix": "Validate DOM assignments"
    },

    {
        "name": "Buffer Overflow",
        "sink": r"\b(sprintf|strcpy|gets)\b",
        "taint": False,
        "severity": "Critical",
        "score": 9.6,
        "cwe": "CWE-120",
        "fix": "Use bounded memory functions"
    },

    {
        "name": "Format String Vulnerability",
        "sink": r"printf\s*\([^\"].*%",
        "taint": False,
        "severity": "High",
        "score": 8.7,
        "cwe": "CWE-134",
        "fix": "Use static format strings"
    },

    {
        "name": "Path Traversal",
        "sink": r"\.\./",
        "taint": True,
        "severity": "High",
        "score": 8.3,
        "cwe": "CWE-22",
        "fix": "Normalize and validate paths"
    },

    {
        "name": "File Inclusion",
        "sink": r"(include|require)",
        "taint": True,
        "severity": "High",
        "score": 8.4,
        "cwe": "CWE-98",
        "fix": "Use allow-listed paths"
    },

    {
        "name": "Hardcoded Secret",
        "sink": r"(api_key|secret|token|AKIA[0-9A-Z]{16})",
        "taint": False,
        "severity": "Critical",
        "score": 9.1,
        "cwe": "CWE-798",
        "fix": "Store secrets securely"
    },

    {
        "name": "Hardcoded Database Credential",
        "sink": r"\$password\s*=\s*['\"]",
        "taint": False,
        "severity": "Medium",
        "score": 6.0,
        "cwe": "CWE-798",
        "fix": "Move DB credentials out of code"
    },

    {
        "name": "Insecure Hash Algorithm",
        "sink": r"(md5|sha1)\(",
        "taint": False,
        "severity": "Medium",
        "score": 6.8,
        "cwe": "CWE-327",
        "fix": "Use modern hashing algorithms"
    },

    {
        "name": "Open Redirect",
        "sink": r"(sendRedirect|location\.href)",
        "taint": True,
        "severity": "Medium",
        "score": 6.5,
        "cwe": "CWE-601",
        "fix": "Validate redirect destinations"
    },

    {
        "name": "Use of eval()",
        "sink": r"\beval\s*\(",
        "taint": False,
        "severity": "High",
        "score": 8.6,
        "cwe": "CWE-95",
        "fix": "Avoid dynamic code execution"
    },

    {
        "name": "Information Disclosure",
        "sink": r"(phpinfo|print_r|var_dump|debug)",
        "taint": False,
        "severity": "Low",
        "score": 4.8,
        "cwe": "CWE-200",
        "fix": "Disable debug output in production"
    }
]


# ===================== MAIN ENGINE =====================
def analyze_code(code: str, filename: str) -> List[dict]:
    lines = code.splitlines()
    lang = get_lang(filename)

    tainted = collect_taint(lines)
    tainted = propagate_taint(lines, tainted)

    vulns: List[Vulnerability] = []

    for i, line in enumerate(lines, 1):
        for rule in RULES:
            if not re.search(rule["sink"], line, re.IGNORECASE):
                continue

            if rule["taint"]:
                if not any(
                    re.search(rf"\b{re.escape(t)}\b", line)
                    for t in tainted
                ):
                    continue

            vulns.append(Vulnerability(
                filename,
                i,
                rule["name"],
                rule["severity"],
                rule["score"],
                f"{rule['name']} detected due to unsafe data flow or operation",
                rule["fix"],
                lang,
                line.strip(),
                rule["cwe"]
            ))

    # Deduplicate
    unique = {(v.file_path, v.line, v.vuln_type): v for v in vulns}
    return [v.to_dict() for v in unique.values()]


if __name__ == "__main__":
    pass
