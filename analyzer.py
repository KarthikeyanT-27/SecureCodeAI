"""
SecureCode AI - analysis orchestrator.

Public interface is unchanged from the original project so main.py and app.py
don't need to change: analyze_code(code, filename) -> List[dict].

Pipeline per file:
  1. Detect language from extension.
  2. Run the tree-sitter structural taint engine (or the HTML handler, which
     extracts <script> blocks and recurses into the JS engine).
  3. If structural parsing fails outright, fall back to the regex engine so
     the file still gets *some* coverage (flagged as low confidence).
  4. Always run the standalone secret-pattern scanner on the raw text.
  5. Dedupe + sort all findings together.
"""

import os
from typing import List

from engine.ts_engine import analyze_with_treesitter, analyze_html
from engine.fallback_regex import analyze_with_regex_fallback
from engine.secrets_scan import scan_secrets
from engine.config_scan import scan_config_patterns
from engine.models import sort_and_dedupe

EXT_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",   # treated with the JS grammar; good enough for taint patterns
    ".tsx": "javascript",
    ".php": "php",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".html": "html",
    ".htm": "html",
}


def get_lang(filename: str) -> str:
    return EXT_LANG.get(os.path.splitext(filename)[1].lower(), "unknown")


def analyze_code(code: str, filename: str) -> List[dict]:
    lang = get_lang(filename)
    findings = []

    if lang == "html":
        result = analyze_html(code, filename)
    elif lang in ("python", "javascript", "php", "java", "c", "cpp"):
        result = analyze_with_treesitter(code, filename, lang)
    else:
        result = None  # unknown extension - regex fallback only

    if result is not None:
        findings.extend(result)
    else:
        findings.extend(analyze_with_regex_fallback(code, filename, lang if lang != "unknown" else "unknown"))

    findings.extend(scan_secrets(code, filename, lang if lang != "unknown" else "unknown"))
    findings.extend(scan_config_patterns(code, filename, lang if lang != "unknown" else "unknown"))

    findings = sort_and_dedupe(findings)
    return [f.to_dict() for f in findings]


if __name__ == "__main__":
    pass
