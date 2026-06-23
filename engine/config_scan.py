"""
Config-flag scanner.

Some security-relevant settings are simple top-level assignments or object
literal keys (TLS verification disabled, debug mode enabled, wildcard CORS,
JWT "none" algorithm) rather than a single consistent function call shape
across languages. Rather than force these into the call-sink taint model,
this scans the raw source text directly - the same approach real tools like
gitleaks/semgrep's "metavariable-less" rules use for this kind of check.
"""

import re
from typing import List
from .models import Finding

CONFIG_PATTERNS = [
    ("Disabled TLS/Certificate Verification", "CWE-295", "High", 8.0,
     r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*[:=]\s*true|"
     r"ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\([^)]*ALLOW_ALL)",
     "Never disable TLS certificate validation in production code; fix the underlying "
     "certificate/trust-store issue instead.",
     "TLS certificate verification has been explicitly disabled, allowing man-in-the-middle "
     "attacks against the connection."),

    ("Debug Mode Enabled", "CWE-489", "Medium", 6.1,
     r"(^\s*DEBUG\s*=\s*True\b|display_errors\s*=\s*1\b|app\.debug\s*=\s*[Tt]rue)",
     "Ensure debug mode is disabled in production deployments.",
     "The application appears to run with debug mode enabled, which can expose stack traces, "
     "source code, and an interactive debugger to end users."),

    ("Overly Permissive CORS Policy (raw config)", "CWE-942", "High", 7.4,
     r"(allow_origins\s*=\s*\[?[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"'])",
     "Restrict CORS to a specific, known list of trusted domains instead of \"*\".",
     "The CORS policy allows requests from any origin (\"*\"), which can expose the API to "
     "cross-origin attacks, particularly if credentials are also allowed."),

    ("JWT 'none' Algorithm Accepted", "CWE-347", "Critical", 9.0,
     r"algorithm[s]?\s*=\s*\[?[\"']none[\"']",
     "Always verify JWT signatures with an explicit allow-list of algorithms; never accept "
     "the 'none' algorithm.",
     "Configuration accepts the JWT 'none' algorithm, allowing an attacker to forge tokens "
     "with no signature at all."),
]

_COMPILED = [(name, cwe, sev, score, re.compile(pat, re.IGNORECASE | re.MULTILINE), fix, expl)
             for name, cwe, sev, score, pat, fix, expl in CONFIG_PATTERNS]


def scan_config_patterns(code: str, filename: str, lang: str) -> List[Finding]:
    findings = []
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        for name, cwe, severity, score, regex, fix, expl in _COMPILED:
            if regex.search(line):
                findings.append(Finding(
                    file_path=filename, line=i, vuln_type=name, severity=severity, score=score,
                    cwe=cwe, confidence="Medium", category="Config",
                    explanation=expl, recommendation=fix, lang=lang,
                    code_snippet=line.strip()[:200],
                    rule_id="CONFIGSCAN-" + name.replace(" ", "_"),
                ))
    return findings
