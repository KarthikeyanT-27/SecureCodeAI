"""
Generic, language-agnostic taint-tracking engine built on tree-sitter.

Rather than matching regex against raw source lines (which can't tell a
comment from real code, and breaks on multi-line statements), this walks the
real syntax tree: assignments, calls, and object-creation expressions are
located structurally, taint is tracked per-variable across the file in
document order, and sanitizer calls clear taint on their result.

This is intraprocedural and whole-file (no cross-function-call taint passing,
no branch-sensitive control flow) - see README for the documented limitations
of this approach. It is, however, a large step up in precision over line-based
regex matching.
"""

import re
from typing import List, Optional

from tree_sitter_languages import get_parser

from .models import Finding
from .rules import (
    RULES, TAINT_SOURCES, SANITIZERS, SOURCE_LEAF_NODE_TYPES, rules_for_language,
)

RULE_BY_ID = {r.id: r for r in RULES}

PLACEHOLDER_LITERALS = {
    "", "todo", "changeme", "change_me", "xxx", "example", "your_api_key",
    "your_api_key_here", "none", "null", "undefined", "placeholder", "fixme",
    "test", "dummy", "<secret>", "***",
}

LANG_CONFIG = {
    "python": {
        "grammar": "python",
        "assign_types": {
            "assignment": ("left", "right"),
            "augmented_assignment": ("left", "right"),
        },
        "call_types": {"call"},
        "comment_types": {"comment"},
        "literal_types": {"string", "integer", "float"},
        "identifier_types": {"identifier"},
    },
    "javascript": {
        "grammar": "javascript",
        "assign_types": {
            "variable_declarator": ("name", "value"),
            "assignment_expression": ("left", "right"),
            "augmented_assignment_expression": ("left", "right"),
        },
        "call_types": {"call_expression", "new_expression"},
        "comment_types": {"comment"},
        "literal_types": {"string", "template_string", "number"},
        "identifier_types": {"identifier"},
    },
    "php": {
        "grammar": "php",
        "assign_types": {
            "assignment_expression": ("left", "right"),
            "augmented_assignment_expression": ("left", "right"),
        },
        "call_types": {
            "function_call_expression", "member_call_expression",
            "object_creation_expression", "scoped_call_expression",
        },
        "comment_types": {"comment"},
        "literal_types": {"string", "encapsed_string"},
        "identifier_types": {"variable_name"},
        "echo_types": {"echo_statement", "print_intrinsic"},
    },
    "java": {
        "grammar": "java",
        "assign_types": {
            "variable_declarator": ("name", "value"),
            "assignment_expression": ("left", "right"),
        },
        "call_types": {"method_invocation", "object_creation_expression"},
        "comment_types": {"line_comment", "block_comment"},
        "literal_types": {"string_literal"},
        "identifier_types": {"identifier"},
    },
    "c": {
        "grammar": "c",
        "assign_types": {
            "init_declarator": ("declarator", "value"),
            "assignment_expression": ("left", "right"),
        },
        "call_types": {"call_expression"},
        "comment_types": {"comment"},
        "literal_types": {"string_literal", "number_literal"},
        "identifier_types": {"identifier"},
    },
    "cpp": {
        "grammar": "cpp",
        "assign_types": {
            "init_declarator": ("declarator", "value"),
            "assignment_expression": ("left", "right"),
        },
        "call_types": {"call_expression"},
        "comment_types": {"comment"},
        "literal_types": {"string_literal", "number_literal"},
        "identifier_types": {"identifier"},
    },
}


# ---------------------------------------------------------------------------
# Low level helpers
# ---------------------------------------------------------------------------
def _text(node, src) -> str:
    if node is None:
        return ""
    return src[node.start_byte:node.end_byte].decode("utf8", errors="ignore")


def _get_args_node(call_node):
    n = call_node.child_by_field_name("arguments")
    if n is not None:
        return n
    for c in call_node.children:
        if c.type in ("arguments", "argument_list"):
            return c
    return None


def _callee_text(call_node, args_node, src) -> str:
    if args_node is None:
        return _text(call_node, src).strip()
    # Include the opening "(" itself, since many sink patterns end in "\(" to
    # require a real call (e.g. r"\beval\(") rather than a bare identifier.
    end = min(args_node.start_byte + 1, call_node.end_byte)
    return src[call_node.start_byte:end].decode("utf8", errors="ignore").strip()


def _matches_any(text: str, patterns) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _is_source(text: str, lang: str) -> bool:
    return _matches_any(text, TAINT_SOURCES.get(lang, ()))


def _is_sanitizer(text: str, lang: str) -> bool:
    return _matches_any(text, SANITIZERS.get(lang, ()))


def _looks_like_redos(args_text: str) -> bool:
    """Very small heuristic for catastrophic-backtracking regex shapes:
    nested quantifiers like (x+)+ , (x*)+ , (.+)* etc."""
    return bool(re.search(r"\([^()]*[+*]\)[+*]", args_text)) or bool(
        re.search(r"\([^()]*[+*][^()]*\)\{?\d*,?\}?[+*]", args_text)
    )


# ---------------------------------------------------------------------------
# Taint check (recursive, generic across grammars)
# ---------------------------------------------------------------------------
def _is_tainted(node, src, lang, cfg, tainted, depth=0) -> bool:
    if node is None or depth > 100:
        return False
    t = node.type

    if t in cfg["call_types"]:
        args_node = _get_args_node(node)
        ctext = _callee_text(node, args_node, src)
        if _is_sanitizer(ctext, lang):
            return False
        # Check both the bare callee name (for exact-anchored source patterns
        # like r"^input$") and the full call text (for sources that span both
        # the function name and a literal argument, e.g. php://input checks).
        if _is_source(ctext.rstrip("("), lang) or _is_source(_text(node, src), lang):
            return True
        if args_node is not None:
            return _is_tainted(args_node, src, lang, cfg, tainted, depth + 1)
        return False

    if t in SOURCE_LEAF_NODE_TYPES.get(lang, set()):
        txt = _text(node, src)
        if _is_source(txt, lang):
            return True
        if t in cfg["identifier_types"]:
            name = txt.lstrip("$")
            return name in tainted
        # fall through to recurse into children (e.g. attribute/subscript bases)

    for c in node.children:
        if _is_tainted(c, src, lang, cfg, tainted, depth + 1):
            return True
    return False


def _callee_text_if_call(node, src, cfg) -> Optional[str]:
    if node is not None and node.type in cfg["call_types"]:
        args = _get_args_node(node)
        return _callee_text(node, args, src)
    return None


def _make_finding(rule, filename, line, lang, snippet, confidence=None) -> Finding:
    return Finding(
        file_path=filename,
        line=line,
        vuln_type=rule.name,
        severity=rule.severity,
        score=rule.score,
        cwe=rule.cwe,
        confidence=confidence or rule.confidence,
        category=rule.category,
        explanation=rule.explanation,
        recommendation=rule.fix,
        lang=lang,
        code_snippet=snippet.strip()[:200],
        rule_id=rule.id,
    )


# ---------------------------------------------------------------------------
# Main per-language walk
# ---------------------------------------------------------------------------
def analyze_with_treesitter(code: str, filename: str, lang: str, line_offset: int = 0) -> Optional[List[Finding]]:
    cfg = LANG_CONFIG.get(lang)
    if cfg is None:
        return None

    src = code.encode("utf8", errors="ignore")
    php_wrapped = False
    if lang == "php" and b"<?php" not in src and b"<?=" not in src:
        src = b"<?php\n" + src
        php_wrapped = True

    try:
        parser = get_parser(cfg["grammar"])
        tree = parser.parse(src)
    except Exception:
        return None

    root = tree.root_node
    findings: List[Finding] = []
    tainted = set()
    rules = rules_for_language(lang)
    call_rules = [r for r in rules if r.kind in ("call_taint", "call_always", "missing_flag")]
    assign_taint_rules = [r for r in rules if r.kind == "assign_taint"]
    assign_literal_rules = [r for r in rules if r.kind == "assign_literal"]
    lhs_random_rules = [r for r in rules if r.kind == "lhs_random"]
    php_offset = 1 if php_wrapped else 0

    def line_of(node) -> int:
        return node.start_point[0] + 1 - php_offset + line_offset

    def handle_assignment(node, left_field, right_field):
        left = node.child_by_field_name(left_field)
        right = node.child_by_field_name(right_field)
        if left is None or right is None:
            return

        is_simple_lhs = left.type in cfg["identifier_types"]
        rhs_tainted = _is_tainted(right, src, lang, cfg, tainted)

        if is_simple_lhs:
            varname = _text(left, src).lstrip("$")
            if rhs_tainted:
                tainted.add(varname)
            else:
                tainted.discard(varname)

            # hardcoded literal secret check
            if right.type in cfg["literal_types"]:
                lit_clean = _text(right, src).strip("\"'").strip().lower()
                if lit_clean not in PLACEHOLDER_LITERALS and len(lit_clean) >= 4:
                    for rule in assign_literal_rules:
                        if re.search(rule.lhs_name_pattern, varname, re.IGNORECASE):
                            findings.append(_make_finding(rule, filename, line_of(node), lang, _text(node, src)))

            # weak randomness assigned to a sensitive variable name
            rhs_callee = _callee_text_if_call(right, src, cfg)
            if rhs_callee:
                for rule in lhs_random_rules:
                    if re.search(rule.lhs_name_pattern, varname, re.IGNORECASE) and _matches_any(rhs_callee, rule.sink_patterns):
                        findings.append(_make_finding(rule, filename, line_of(node), lang, _text(node, src)))
        else:
            # complex LHS (member/subscript access) - check assign_taint sinks
            # e.g. el.innerHTML = <tainted>, location.href = <tainted>
            lhs_text = _text(left, src)
            if rhs_tainted:
                for rule in assign_taint_rules:
                    if _matches_any(lhs_text, rule.sink_patterns):
                        findings.append(_make_finding(rule, filename, line_of(node), lang, _text(node, src)))

    def handle_call(node):
        args_node = _get_args_node(node)
        ctext = _callee_text(node, args_node, src)
        args_text = _text(args_node, src) if args_node is not None else ""

        for rule in call_rules:
            if not _matches_any(ctext, rule.sink_patterns):
                continue

            if rule.kind == "call_taint":
                if args_node is not None and _is_tainted(args_node, src, lang, cfg, tainted):
                    findings.append(_make_finding(rule, filename, line_of(node), lang, _text(node, src)))

            elif rule.kind == "call_always":
                if rule.args_pattern and not re.search(rule.args_pattern, args_text, re.IGNORECASE):
                    continue
                if rule.id == "REDOS-1" and not _looks_like_redos(args_text):
                    continue
                findings.append(_make_finding(rule, filename, line_of(node), lang, _text(node, src)))

            elif rule.kind == "missing_flag":
                if rule.args_must_match and not re.search(rule.args_must_match, args_text, re.IGNORECASE):
                    findings.append(_make_finding(rule, filename, line_of(node), lang, _text(node, src)))

    def handle_echo(node):
        # PHP echo/print are language constructs, not calls - special-cased.
        rule = RULE_BY_ID.get("XSS-1")
        if rule and _is_tainted(node, src, lang, cfg, tainted):
            findings.append(_make_finding(rule, filename, line_of(node), lang, _text(node, src)))

    def walk(node):
        t = node.type
        if t in cfg["assign_types"]:
            handle_assignment(node, *cfg["assign_types"][t])
        if t in cfg["call_types"]:
            handle_call(node)
        if t in cfg.get("echo_types", ()):
            handle_echo(node)
        for c in node.children:
            walk(c)

    walk(root)
    return findings


# ---------------------------------------------------------------------------
# HTML: extract <script> blocks (analyzed as JS) + scan attributes directly
# ---------------------------------------------------------------------------
def analyze_html(code: str, filename: str) -> Optional[List[Finding]]:
    src = code.encode("utf8", errors="ignore")
    try:
        parser = get_parser("html")
        tree = parser.parse(src)
    except Exception:
        return None

    findings: List[Finding] = []
    xss4_rule = RULE_BY_ID.get("XSS-4")

    def walk(node):
        if node.type == "script_element":
            raw = next((c for c in node.children if c.type == "raw_text"), None)
            if raw is not None:
                js_code = src[raw.start_byte:raw.end_byte].decode("utf8", errors="ignore")
                line_offset = raw.start_point[0]
                sub = analyze_with_treesitter(js_code, filename, "javascript", line_offset=line_offset)
                if sub:
                    for f in sub:
                        f.lang = "html (inline <script>)"
                        findings.append(f)
        elif node.type == "attribute" and xss4_rule:
            text = _text(node, src)
            if re.search(r"javascript:", text, re.IGNORECASE):
                findings.append(_make_finding(xss4_rule, filename, node.start_point[0] + 1, "html", text.strip()[:200]))
        for c in node.children:
            walk(c)

    walk(tree.root_node)
    return findings
