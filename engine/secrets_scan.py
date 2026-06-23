"""
Dedicated secret-scanning pass.

Real-world secret scanners (gitleaks, truffleHog, etc.) work directly on raw
text rather than needing a parsed AST, because secrets have very distinctive
shapes (key prefixes, base64-ish blobs, PEM headers). This module replicates
that approach as a language-agnostic supplement to the taint engines.
"""

import re
from typing import List
from .models import Finding

SECRET_PATTERNS = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "Critical", 9.5),
    ("AWS Secret Access Key", r"(?i)aws_secret_access_key\s*[=:]\s*[\"\']?[A-Za-z0-9/+=]{40}[\"\']?", "Critical", 9.5),
    ("GitHub Personal Access Token", r"gh[pousr]_[A-Za-z0-9]{36,}", "Critical", 9.3),
    ("Slack Token", r"xox[baprs]-[A-Za-z0-9-]{10,}", "High", 8.5),
    ("Stripe API Key", r"sk_live_[A-Za-z0-9]{24,}", "Critical", 9.4),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "High", 8.2),
    ("Generic Private Key Block", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "Critical", 9.6),
    ("Slack Webhook URL", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}", "Medium", 6.5),
    ("JSON Web Token (hardcoded)", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "High", 7.8),
    ("Generic High-Entropy Secret Assignment",
     r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[=:]\s*[\"\'][A-Za-z0-9_\-]{20,}[\"\']",
     "High", 8.0),
]

_COMPILED = [(name, re.compile(pat), sev, score) for name, pat, sev, score in SECRET_PATTERNS]


def scan_secrets(code: str, filename: str, lang: str) -> List[Finding]:
    findings = []
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        for name, regex, severity, score in _COMPILED:
            m = regex.search(line)
            if m:
                findings.append(Finding(
                    file_path=filename,
                    line=i,
                    vuln_type=f"Hardcoded Secret: {name}",
                    severity=severity,
                    score=score,
                    cwe="CWE-798",
                    confidence="High",
                    category="Secrets",
                    explanation=f"A pattern matching a {name} was found directly in source code.",
                    recommendation="Revoke this credential immediately if it is real, remove it "
                                   "from source control history, and load secrets from environment "
                                   "variables or a secrets manager instead.",
                    lang=lang,
                    code_snippet=line.strip()[:200],
                    rule_id="SECRETSCAN-" + name.replace(" ", "_"),
                ))
    return findings
