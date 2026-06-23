"""
Shared data model for vulnerability findings.

Every engine (Python AST engine, tree-sitter engine, secrets scanner,
regex fallback) produces Finding objects so the rest of the pipeline
(dedup, sorting, JSON serialization) is engine-agnostic.
"""

from dataclasses import dataclass, field


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


@dataclass
class Finding:
    file_path: str
    line: int
    vuln_type: str
    severity: str
    score: float
    cwe: str
    explanation: str
    recommendation: str
    lang: str
    code_snippet: str
    confidence: str = "Medium"          # High / Medium / Low
    category: str = ""
    end_line: int = field(default=0)
    taint_source: str = ""              # human readable description of where tainted data came from
    rule_id: str = ""

    def __post_init__(self):
        if not self.end_line:
            self.end_line = self.line

    def dedup_key(self):
        return (self.file_path, self.line, self.vuln_type)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "end_line": self.end_line,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "score": self.score,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "category": self.category,
            "reason": "",                       # kept for backward compatibility with old UI
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "lang": self.lang,
            "code_snippet": self.code_snippet,
            "taint_source": self.taint_source,
            "rule_id": self.rule_id,
        }


def sort_and_dedupe(findings):
    """Dedupe on (file, line, vuln_type) keeping the highest-confidence entry,
    then sort by severity (desc), score (desc), file, line."""
    best = {}
    conf_rank = {"High": 3, "Medium": 2, "Low": 1}
    for f in findings:
        key = f.dedup_key()
        if key not in best or conf_rank.get(f.confidence, 0) > conf_rank.get(best[key].confidence, 0):
            best[key] = f
    out = list(best.values())
    out.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -f.score, f.file_path, f.line))
    return out
