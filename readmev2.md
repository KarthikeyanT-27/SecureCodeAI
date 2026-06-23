# SecureCodeAI
### Unified Static Code & Dependency Security Analyzer — v2 (structural engine)

SecureCode AI is a **Static Application Security Testing (SAST) platform** that detects
security vulnerabilities in application source code and third-party dependencies using
**parser-based taint analysis** and a **CWE-mapped rule engine**.

---

## What changed in v2

The original engine matched regex patterns against raw lines of code. That approach can't
tell a comment from real code, breaks on multi-line statements, and can't reliably tell
whether a variable actually came from tainted user input. v2 replaces it with a structural
engine:

- **Real parsing, not line regex.** Python, JavaScript, PHP, Java, C, and C++ are parsed
  with [tree-sitter](https://tree-sitter.github.io/tree-sitter/) into a real syntax tree.
  Assignments and function calls are located structurally, so comments, string contents,
  and multi-line statements are handled correctly instead of being scanned line-by-line.
- **Sanitizer-aware taint tracking.** If tainted data passes through a recognized
  sanitizer (`htmlspecialchars`, `escape`, `DOMPurify.sanitize`, parameterized queries,
  etc.), the result is no longer treated as tainted — this is the single biggest source of
  false positives in the old engine and is now handled explicitly.
- **~45 rules across 13 categories**, up from 14 rules in one category. See the table below.
- **HTML is handled properly**: `<script>` blocks are extracted and analyzed with the same
  JavaScript engine, and dangerous inline patterns (`javascript:` URIs) are flagged
  directly.
- **A dedicated secrets scanner** (`engine/secrets_scan.py`) looks for AWS keys, GitHub/
  Stripe/Slack/Google tokens, PEM private key blocks, and hardcoded JWTs directly in raw
  text — the same approach tools like gitleaks use, since secrets have a distinctive shape
  regardless of language.
- **A config-pattern scanner** (`engine/config_scan.py`) catches security-relevant settings
  that aren't a single consistent function call across languages (TLS verification
  disabled, debug mode enabled, wildcard CORS, JWT `none` algorithm).
- **Regex fallback, not silent skipping.** If a file fails to parse at all, it's still
  scanned with the original line-based engine rather than skipped — those findings are
  marked `confidence: "Low"` so the UI can show they're less reliable.
- **CWE ID, severity, score, and a confidence rating** are now reported on every finding.

The public interface (`analyze_code(code, filename) -> List[dict]`) is unchanged, so
`main.py` and `app.py` work without modification beyond a small UI tweak to surface the
new CWE/confidence fields.

---

## Rule coverage (engine/rules.py)

| Category | Examples |
|---|---|
| Injection | SQL Injection, OS Command Injection, SSTI, NoSQL Injection, LDAP Injection, HTTP Header/CRLF Injection |
| XSS | Reflected XSS, DOM-based XSS (`innerHTML`/`outerHTML`), `document.write`, `javascript:` URIs |
| Memory / Native | Buffer overflow (`strcpy`/`gets`/`sprintf`), format string vulns, dangerous memory functions, integer overflow in allocation |
| Path / Files | Path Traversal, Local/Remote File Inclusion |
| Deserialization / XML | Insecure Deserialization (`pickle`, `unserialize`, `ObjectInputStream`), risky XML parser defaults (XXE) |
| SSRF | Tainted URLs reaching `requests.get`, `fetch`, `HttpClient`, etc. |
| Redirect | Open Redirect (server-side and `location.href`) |
| Code Execution | `eval`/`exec`/`new Function`, Prototype Pollution |
| ReDoS | Heuristic detection of nested-quantifier regexes |
| Crypto | MD5/SHA-1, weak cipher modes (DES/ECB), hardcoded keys/IVs, insecure randomness for tokens, disabled TLS verification |
| Secrets | Hardcoded credentials by variable name, AWS/GitHub/Stripe/Slack/Google key patterns, PEM blocks, hardcoded JWTs |
| Auth | JWT `none` algorithm / disabled signature verification |
| Config | Wildcard CORS, cookies missing `Secure`/`HttpOnly`, debug mode enabled, mass assignment |
| Info Disclosure | Debug output (`var_dump`, `print_r`, stack traces) left in code |

Every rule carries a CWE ID, a severity (Critical/High/Medium/Low), a numeric score, and a
confidence rating (High/Medium/Low) reflecting how reliable that specific pattern is.

---

## How the taint engine actually works

For each supported language, `engine/ts_engine.py` walks the syntax tree in document order:

1. **Taint sources** — recognized per-language (HTTP request objects, `input()`,
   superglobals, `argv`, etc.) via `engine/rules.py::TAINT_SOURCES`.
2. **Assignments** — when a variable is assigned a tainted expression, it's added to the
   tainted set; if reassigned something clean (or the result of a sanitizer call), it's
   removed.
3. **Sinks** — every function call and certain assignment targets (`el.innerHTML = ...`)
   are checked against the rule sink patterns; if the rule requires taint, the call's
   arguments are checked against the current tainted set.
4. **Sanitizers** — a sanitizer call's result is never considered tainted, regardless of
   what was passed into it.

### Honest limitations

No static analyzer — commercial or open source — catches every vulnerability or has zero
false positives, and this project is no exception. Specifically:

- **Intraprocedural only.** Taint is tracked within a single file, front-to-back. It does
  **not** follow data across function calls, so `def f(x): sink(x)` won't be flagged just
  because some caller passes tainted data to `f`.
- **No real control-flow analysis.** An `if` branch that fully sanitizes a value before a
  sink is not distinguished from one that doesn't — taint, once set, persists for the rest
  of the file unless explicitly cleared by a recognized sanitizer call.
- **Single-file scans.** Each file is analyzed independently; vulnerabilities that only
  exist because of how two files interact won't be found.
- **Regex-matched sink/source names.** A wrapper function or unusual import alias around a
  sink (e.g. `from os import system as run`) can evade detection.
- **ReDoS, mass-assignment, NoSQL-injection, and a few other rules are heuristic** (lower
  `confidence`) by nature — they're good leads to investigate manually, not certainties.

If you need guarantees beyond this, pair it with a commercial SAST tool and/or manual
review for anything security-critical — that's true of every SAST tool, not a gap unique
to this one.

---

## 🏗️ System Architecture

```
User
  ↓
Streamlit Frontend (app.py)
  ↓
FastAPI Backend (main.py)
  ↓
analyzer.py (orchestrator)
  ├── engine/ts_engine.py      - tree-sitter structural taint engine (Python/JS/PHP/Java/C/C++)
  ├── engine/ts_engine.py      - HTML handler (extracts <script>, scans attributes)
  ├── engine/fallback_regex.py - last-resort line-regex engine if parsing fails
  ├── engine/secrets_scan.py   - raw-text secret/credential pattern scanner
  ├── engine/config_scan.py    - raw-text security-config pattern scanner
  └── engine/rules.py          - the CWE-mapped rule library + taint source/sanitizer lists
  ↓
engine/models.py (dedupe + sort) → JSON report
```

---

## 🧰 Tech Stack

### Frontend
- **Streamlit**

### Backend
- **FastAPI**

### Core Language
- **Python**

### Key Libraries
- `tree-sitter` / `tree-sitter-languages` — multi-language structural parsing
- `re` — pattern matching for sink/source/sanitizer names and the secret/config scanners
- `requests` — package vulnerability lookups against the [OSV.dev](https://osv.dev) API

---

## 📁 Project Structure

```
SecureCode-AI/
│
├── app.py                   # Streamlit frontend
├── main.py                  # FastAPI backend
├── analyzer.py               # Orchestrator - same analyze_code(code, filename) interface as v1
├── requirements.txt
├── README.md
│
└── engine/
    ├── models.py             # Finding dataclass, dedupe/sort
    ├── rules.py              # Rule library, taint sources, sanitizers
    ├── ts_engine.py           # tree-sitter taint engine + HTML handling
    ├── secrets_scan.py        # standalone secret-pattern scanner
    ├── config_scan.py         # standalone config-pattern scanner
    └── fallback_regex.py      # regex fallback for unparseable files
```

## ▶️ Getting Started

### 1️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note:** `tree-sitter` is pinned to `0.21.3` deliberately — `tree-sitter-languages`'
> bundled grammars are compiled against the pre-0.22 `Language()` constructor and will
> raise `TypeError: __init__() takes exactly 1 argument` on newer `tree-sitter` releases.

### 2️⃣ Start Backend (FastAPI)

```bash
uvicorn main:app --reload
```

Backend runs at `http://localhost:8000`.

### 3️⃣ Start Frontend (Streamlit)

```bash
streamlit run app.py
```

Frontend runs at `http://localhost:8501`.

---

## 🎯 Use Cases

* Academic cybersecurity projects
* Secure coding education
* Developer security awareness
* Early vulnerability detection in small teams
* Research on static analysis & taint tracking

## 🔮 Future Enhancements

* Interprocedural taint tracking (cross-function-call)
* CI/CD pipeline integration (SARIF output)
* Authentication & user dashboards
* Control-flow-sensitive analysis (branch-aware sanitization)
* Cloud-based SaaS deployment

## ⚠️ Ethical Use

This tool is intended **only for educational and authorized security analysis**.
Unauthorized scanning of third-party or proprietary code is strictly discouraged.

## 📜 License

This project is released for **educational and research purposes**.

## 👤 Author

**Karthikeyan**
Cybersecurity & Secure Software Engineering

