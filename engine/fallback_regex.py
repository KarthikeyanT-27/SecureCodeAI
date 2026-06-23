"""
Last-resort fallback engine.

If tree-sitter can't parse a file at all (e.g. severely malformed/truncated
source), we fall back to the original line-based regex approach rather than
silently skipping the file. Findings from this path are always marked
confidence="Low" so the UI can make clear they're less reliable than the
structural (tree-sitter) results.
"""

import re
from typing import List
from .models import Finding

_FALLBACK_RULES = [
    ("SQL Injection", r"(mysqli_query|executeQuery|executeUpdate|cursor\.execute|\.execute\()", True, "Critical", 9.8, "CWE-89"),
    ("Command Injection", r"(\bsystem\(|\bexec\(|shell_exec|os\.system|Runtime\.getRuntime)", True, "Critical", 9.7, "CWE-78"),
    ("Reflected XSS", r"(^echo|^print|<\?=)", True, "High", 8.5, "CWE-79"),
    ("DOM-based XSS", r"(innerHTML|document\.write|script\.src)", False, "Critical", 9.2, "CWE-79"),
    ("Buffer Overflow", r"\b(sprintf|strcpy|gets)\b", False, "Critical", 9.6, "CWE-120"),
    ("Path Traversal", r"\.\./", True, "High", 8.3, "CWE-22"),
    ("File Inclusion", r"(include|require)", True, "High", 8.4, "CWE-98"),
    ("Hardcoded Secret", r"(api_key|secret|token|AKIA[0-9A-Z]{16})", False, "Critical", 9.1, "CWE-798"),
    ("Insecure Hash Algorithm", r"(md5|sha1)\(", False, "Medium", 6.8, "CWE-327"),
    ("Use of eval()", r"\beval\s*\(", False, "High", 8.6, "CWE-95"),
    ("Information Disclosure", r"(phpinfo|print_r|var_dump|debug)", False, "Low", 4.8, "CWE-200"),
]

_TAINT_SOURCES = [
    r"\$_(GET|POST|REQUEST|COOKIE)", r"request\.getParameter", r"\binput\s*\(",
    r"\bargv\s*\[", r"document\.location", r"window\.location", r"document\.cookie",
]


def _collect_taint(lines):
    tainted = set()
    for line in lines:
        for src in _TAINT_SOURCES:
            if re.search(src, line, re.IGNORECASE):
                m = re.search(r"(\$?\w+)\s*=", line)
                if m:
                    tainted.add(m.group(1).replace("$", ""))
                if "argv" in line:
                    tainted.add("argv")
    return tainted


def _propagate_taint(lines, tainted):
    changed = True
    while changed:
        changed = False
        for line in lines:
            line = line.strip()
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


def analyze_with_regex_fallback(code: str, filename: str, lang: str) -> List[Finding]:
    lines = code.splitlines()
    tainted = _collect_taint(lines)
    tainted = _propagate_taint(lines, tainted)

    findings = []
    for i, line in enumerate(lines, 1):
        for name, pattern, requires_taint, severity, score, cwe in _FALLBACK_RULES:
            if not re.search(pattern, line, re.IGNORECASE):
                continue
            if requires_taint and not any(re.search(rf"\b{re.escape(t)}\b", line) for t in tainted):
                continue
            findings.append(Finding(
                file_path=filename, line=i, vuln_type=name, severity=severity, score=score,
                cwe=cwe, confidence="Low", category="Fallback",
                explanation=f"{name} detected via fallback regex scan (file could not be fully "
                            f"parsed - review manually, this result is lower-confidence).",
                recommendation="Review manually; structural analysis was unavailable for this file.",
                lang=lang, code_snippet=line.strip()[:200], rule_id="FALLBACK-" + name.replace(" ", "_"),
            ))
    return findings
