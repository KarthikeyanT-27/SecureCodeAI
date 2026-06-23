"""
Rule library for SecureCode AI.

A Rule describes ONE vulnerability pattern. `kind` controls how the engine
evaluates it:

  call_taint     - a call to something matching `sink_patterns` whose arguments
                    contain tainted data.
  call_always    - a call to something matching `sink_patterns`, flagged
                    regardless of taint (optionally gated by `args_pattern`
                    which must also match the call's argument text).
  assign_taint   - an assignment whose LHS text matches `sink_patterns` and
                    whose RHS is tainted (e.g. `el.innerHTML = <tainted>`).
  assign_literal - an assignment whose LHS *name* matches `lhs_name_pattern`
                    and whose RHS is a literal (not a variable/call) - used
                    for hardcoded secrets/credentials.
  missing_flag   - a call matching `sink_patterns` whose argument text does
                    NOT match `args_must_match` (e.g. cookie set without
                    Secure/HttpOnly).
  lhs_random     - an assignment whose LHS name matches `lhs_name_pattern`
                    and whose RHS call matches `sink_patterns` (weak RNG).

Every rule lists which languages it applies to. ALL_LANGS means every
supported language (php, java, c, cpp, javascript, python, html).
"""

from dataclasses import dataclass
from typing import Tuple, Optional


@dataclass
class Rule:
    id: str
    name: str
    cwe: str
    severity: str
    score: float
    category: str
    languages: Tuple[str, ...]
    kind: str
    sink_patterns: Tuple[str, ...] = ()
    args_pattern: Optional[str] = None
    args_must_match: Optional[str] = None
    lhs_name_pattern: Optional[str] = None
    confidence: str = "Medium"
    fix: str = ""
    explanation: str = ""


ALL_LANGS = ("python", "javascript", "php", "java", "c", "cpp", "html")

# ---------------------------------------------------------------------------
# Taint sources: regex matched against callee text (for calls) or against
# leaf node text (identifiers / member access / superglobals).
# ---------------------------------------------------------------------------
TAINT_SOURCES = {
    "python": [
        r"^input$",
        r"request\.(args|form|values|json|GET|POST|COOKIES|data|headers|files)\b",
        r"\bsys\.argv\b",
        r"\.get_json\b",
        r"flask\.request\b",
    ],
    "javascript": [
        r"req\.(query|body|params|headers|cookies)\b",
        r"document\.location\b",
        r"window\.location\b",
        r"document\.cookie\b",
        r"location\.(hash|search)\b",
        r"process\.argv\b",
        r"\.searchParams\b",
    ],
    "php": [
        r"^\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b",
        r"\bfile_get_contents\(\s*['\"]php://input",
    ],
    "java": [
        r"request\.getParameter",
        r"request\.getHeader",
        r"request\.getQueryString",
        r"request\.getCookies",
        r"request\.getInputStream",
        r"\bSystem\.getenv\b",
        r"\bSystem\.in\b",
    ],
    "c": [r"\bargv\b", r"\bgetenv\(", r"\bscanf\(", r"\bgets\("],
    "cpp": [r"\bargv\b", r"\bgetenv\(", r"\bscanf\(", r"\bgets\(", r"\bcin\b"],
    "html": [r"document\.location", r"document\.cookie", r"location\.hash"],
}

# ---------------------------------------------------------------------------
# Sanitizers: a call matching one of these clears taint on its result.
# ---------------------------------------------------------------------------
SANITIZERS = {
    "python": [
        r"\bescape\b", r"bleach\.clean", r"markupsafe\.escape",
        r"shlex\.quote", r"secure_filename", r"\bquote_plus\b",
        r"html\.escape",
    ],
    "javascript": [
        r"escapeHtml", r"DOMPurify\.sanitize", r"encodeURIComponent",
        r"encodeURI", r"validator\.escape", r"sanitize-html", r"\.escape\(",
    ],
    "php": [
        r"htmlspecialchars", r"htmlentities", r"filter_var",
        r"escapeshellarg", r"real_escape_string", r"mysqli_real_escape_string",
        r"\bbasename\(", r"intval\(", r"\(int\)",
    ],
    "java": [
        r"escapeHtml", r"StringEscapeUtils", r"Encode\.forHtml",
        r"\bsanitize\b",
    ],
    "c": [r"\bsnprintf\b"],
    "cpp": [r"\bsnprintf\b"],
    "html": [],
}

# Node types treated as "leaf-ish" per language when checking whether a small
# identifier/member-access expression matches a taint source directly
# (as opposed to being passed as a call argument).
SOURCE_LEAF_NODE_TYPES = {
    "python": {"identifier", "attribute", "subscript"},
    "javascript": {"identifier", "member_expression", "subscript_expression"},
    "php": {"variable_name", "subscript_expression", "member_access_expression"},
    "java": {"identifier", "field_access"},
    "c": {"identifier"},
    "cpp": {"identifier", "field_expression"},
}


def _r(*args, **kwargs) -> Rule:
    return Rule(*args, **kwargs)


RULES = [
    # ================= INJECTION =================
    _r("SQLI-1", "SQL Injection", "CWE-89", "Critical", 9.8, "Injection",
       ALL_LANGS, "call_taint",
       sink_patterns=(r"mysqli_query", r"\bquery\(", r"executeQuery", r"executeUpdate",
                      r"cursor\.execute", r"\.execute\(", r"createStatement", r"raw\(",
                      r"PDO::query", r"->query\(", r"db\.query"),
       confidence="High",
       fix="Use parameterized queries / prepared statements (e.g. PDO with bound params, "
           "psycopg2 placeholders, PreparedStatement) instead of building SQL from strings.",
       explanation="User-controlled input flows into a SQL statement without parameterization, "
                   "allowing an attacker to alter query logic or exfiltrate/modify data."),

    _r("CMDI-1", "OS Command Injection", "CWE-78", "Critical", 9.7, "Injection",
       ALL_LANGS, "call_taint",
       sink_patterns=(r"\bsystem\(", r"\bexec\(", r"shell_exec", r"popen\(",
                      r"os\.system", r"os\.popen", r"subprocess\.(call|run|Popen|check_output)",
                      r"Runtime\.getRuntime\(\)\.exec", r"ProcessBuilder",
                      r"child_process", r"exec_sync", r"execSync"),
       confidence="High",
       fix="Avoid invoking a shell with user input. Use APIs that take an argument array "
           "(e.g. subprocess.run([...], shell=False)) and validate/allow-list input.",
       explanation="Tainted data reaches a function that executes an OS command, allowing "
                   "arbitrary command execution on the host."),

    _r("SSTI-1", "Server-Side Template Injection", "CWE-1336", "Critical", 9.3, "Injection",
       ("python", "javascript", "java", "php"), "call_taint",
       sink_patterns=(r"render_template_string", r"\bTemplate\(", r"Jinja2", r"\bpug\.render\(",
                      r"\.render\(.*\)", r"Velocity\.evaluate", r"twig.*render"),
       confidence="Medium",
       fix="Never build a template string from user input. Pass user data as template "
           "variables/context, not as the template source itself.",
       explanation="User input is used to construct a template that is then rendered, which "
                   "can let an attacker execute arbitrary code on the server."),

    _r("NOSQLI-1", "NoSQL Injection", "CWE-943", "Critical", 9.1, "Injection",
       ("javascript", "python"), "call_taint",
       sink_patterns=(r"\.find\(", r"\.findOne\(", r"\.aggregate\(", r"\.update\(",
                      r"\.updateOne\(", r"\.deleteMany\("),
       confidence="Low",
       fix="Avoid passing raw user-supplied objects/operators (e.g. $where, $gt) into "
           "database queries. Validate and whitelist query fields and operators.",
       explanation="Tainted data flows into a NoSQL query call, which may allow operator "
                   "injection (e.g. $where, $ne) to bypass query logic."),

    _r("LDAPI-1", "LDAP Injection", "CWE-90", "High", 8.2, "Injection",
       ("java", "python", "php"), "call_taint",
       sink_patterns=(r"\bsearch\(", r"ldap_search", r"DirContext", r"\.bind\("),
       confidence="Low",
       fix="Escape special LDAP filter characters in user input before building filters.",
       explanation="Unescaped user input is used to build an LDAP query/filter."),

    _r("HEADERI-1", "HTTP Header / CRLF Injection", "CWE-93", "High", 7.5, "Injection",
       ("python", "javascript", "java", "php"), "call_taint",
       sink_patterns=(r"setHeader", r"\.header\(", r"add_header", r"setRequestProperty"),
       confidence="Low",
       fix="Strip CR/LF characters from any user input before placing it in an HTTP header value.",
       explanation="Tainted data is written into an HTTP response/request header, which can "
                   "allow header/response splitting if newline characters are not stripped."),

    # ================= XSS =================
    _r("XSS-1", "Reflected Cross-Site Scripting (XSS)", "CWE-79", "High", 8.5, "XSS",
       ("php", "java", "python"), "call_taint",
       sink_patterns=(r"^echo$", r"^print$", r"\bprintln\b", r"getWriter\(\)\.print",
                      r"render_template_string"),
       confidence="Medium",
       fix="HTML-escape output before writing it into the response (e.g. htmlspecialchars, "
           "Jinja2 autoescaping, StringEscapeUtils.escapeHtml4).",
       explanation="Tainted user input is written directly into the HTTP response without "
                   "output encoding, allowing script injection in the victim's browser."),

    _r("XSS-2", "DOM-based Cross-Site Scripting (XSS)", "CWE-79", "Critical", 9.2, "XSS",
       ("javascript", "html"), "assign_taint",
       sink_patterns=(r"\.innerHTML$", r"\.outerHTML$", r"\.insertAdjacentHTML"),
       confidence="High",
       fix="Use `.textContent`/`.innerText` for plain text, or sanitize HTML with DOMPurify "
           "before assigning to innerHTML.",
       explanation="Tainted data is assigned to a DOM sink that renders raw HTML, allowing "
                   "script execution in the browser."),

    _r("XSS-3", "DOM XSS via document.write", "CWE-79", "Critical", 9.0, "XSS",
       ("javascript", "html"), "call_taint",
       sink_patterns=(r"document\.write", r"document\.writeln"),
       confidence="High",
       fix="Avoid document.write with dynamic data; use safe DOM APIs (createElement/textContent).",
       explanation="Tainted data flows into document.write(), enabling script injection."),

    _r("XSS-4", "javascript: URI Scheme", "CWE-79", "Medium", 6.1, "XSS",
       ("html", "javascript"), "call_always",
       sink_patterns=(r"javascript:",),
       confidence="Low",
       fix="Do not allow user-controlled values to set href/src to a javascript: URI.",
       explanation="A javascript: URI scheme was found, which executes script when the "
                   "link/element is activated."),

    # ================= MEMORY / NATIVE =================
    _r("MEM-1", "Buffer Overflow (unsafe memory function)", "CWE-120", "Critical", 9.6, "Memory",
       ("c", "cpp"), "call_always",
       sink_patterns=(r"\bstrcpy\(", r"\bstrcat\(", r"\bgets\(", r"\bsprintf\("),
       confidence="High",
       fix="Use bounded variants: strncpy/strlcpy, strncat/strlcat, fgets, snprintf.",
       explanation="Use of a function with no bounds checking can overflow the destination "
                   "buffer if input length is not controlled."),

    _r("MEM-2", "Format String Vulnerability", "CWE-134", "High", 8.7, "Memory",
       ("c", "cpp"), "call_always",
       sink_patterns=(r"\bprintf\(", r"\bfprintf\(", r"\bsyslog\("),
       args_pattern=r"^\([^\"]*$",  # first token is not a string literal -> dynamic format string
       confidence="Medium",
       fix="Always use a constant format string, e.g. printf(\"%s\", input) not printf(input).",
       explanation="A non-literal value is used as the format string itself, letting an "
                   "attacker control memory reads/writes via format specifiers."),

    _r("MEM-3", "Use of Dangerous Memory Function", "CWE-676", "Medium", 6.4, "Memory",
       ("c", "cpp"), "call_always",
       sink_patterns=(r"\balloca\(", r"\bmemcpy\(", r"\bstrncpy\("),
       confidence="Low",
       fix="Verify size arguments are bounds-checked and cannot be influenced by attacker input.",
       explanation="Use of a memory function that is safe only if size arguments are correct; "
                   "verify the length is properly bounded."),

    _r("INTOVF-1", "Potential Integer Overflow in Allocation", "CWE-190", "Medium", 6.0, "Memory",
       ("c", "cpp"), "call_taint",
       sink_patterns=(r"\bmalloc\(", r"\bcalloc\(", r"\brealloc\("),
       confidence="Low",
       fix="Validate/bound user-controlled values used in size calculations before allocating.",
       explanation="A tainted value influences a memory allocation size, which can overflow "
                   "and lead to under-allocation."),

    # ================= PATH / FILES =================
    _r("PATH-1", "Path Traversal", "CWE-22", "High", 8.3, "Path",
       ("python", "javascript", "php", "java"), "call_taint",
       sink_patterns=(r"\bopen\(", r"fopen\(", r"readFile", r"createReadStream",
                      r"\bFile\(", r"Paths\.get", r"new FileInputStream"),
       confidence="Medium",
       fix="Normalize the path and verify it stays within an allowed base directory "
           "(e.g. os.path.realpath + startswith check) before opening.",
       explanation="Tainted data is used to build a filesystem path without validation, "
                   "allowing access to files outside the intended directory via '../' sequences."),

    _r("LFI-1", "Local/Remote File Inclusion", "CWE-98", "High", 8.4, "Path",
       ("php",), "call_taint",
       sink_patterns=(r"\binclude\(", r"\binclude_once\(", r"\brequire\(", r"\brequire_once\("),
       confidence="Medium",
       fix="Use an allow-list of known filenames; never pass user input directly to include/require.",
       explanation="Tainted data controls which file gets included/executed by PHP."),

    _r("DESERIAL-1", "Insecure Deserialization", "CWE-502", "Critical", 9.4, "Deserialization",
       ("python", "java", "php"), "call_taint",
       sink_patterns=(r"pickle\.loads?\(", r"yaml\.load\((?!.*SafeLoader)", r"\.readObject\(",
                      r"\bunserialize\(", r"ObjectInputStream"),
       confidence="High",
       fix="Avoid deserializing untrusted data. Use safe formats (JSON) or yaml.safe_load, "
           "and validate/sign serialized payloads.",
       explanation="Untrusted data is passed to a deserialization function, which can lead to "
                   "arbitrary code execution depending on the gadget chain available."),

    _r("XXE-1", "XML External Entity (XXE) - risky parser default", "CWE-611", "High", 8.2, "XML",
       ("python", "java", "php"), "call_always",
       sink_patterns=(r"etree\.parse\(", r"minidom\.parse\(", r"xml\.sax", r"DocumentBuilderFactory",
                      r"SAXParserFactory", r"simplexml_load_string", r"simplexml_load_file"),
       confidence="Low",
       fix="Disable external entity & DTD resolution explicitly (e.g. defusedxml in Python, "
           "setFeature(...EXTERNAL_GENERAL_ENTITIES, false) in Java, libxml_disable_entity_loader "
           "in PHP < 8).",
       explanation="An XML parser is used with defaults that may resolve external entities, "
                   "enabling XXE attacks (file disclosure, SSRF) if the parser isn't hardened."),

    # ================= SSRF =================
    _r("SSRF-1", "Server-Side Request Forgery (SSRF)", "CWE-918", "High", 8.6, "SSRF",
       ("python", "javascript", "java", "php"), "call_taint",
       sink_patterns=(r"requests\.(get|post|put|delete)\(", r"urllib\.request\.urlopen",
                      r"urlopen\(", r"\baxios\.(get|post)\(", r"\bfetch\(",
                      r"curl_exec", r"HttpClient", r"\.openConnection\("),
       confidence="Medium",
       fix="Validate/allow-list the destination host before making the request; block requests "
           "to internal/private IP ranges and the cloud metadata endpoint.",
       explanation="A tainted URL/host is used to make an outbound HTTP request, which can let "
                   "an attacker reach internal services or cloud metadata endpoints."),

    # ================= REDIRECT =================
    _r("REDIR-1", "Open Redirect", "CWE-601", "Medium", 6.5, "Redirect",
       ("python", "javascript", "java", "php"), "call_taint",
       sink_patterns=(r"sendRedirect", r"redirect\(", r"RedirectResponse"),
       confidence="Medium",
       fix="Validate the redirect target against an allow-list of known paths/domains.",
       explanation="A tainted value controls the redirect destination, allowing attackers to "
                   "redirect users to an arbitrary external site (phishing)."),

    _r("REDIR-2", "Open Redirect via location assignment", "CWE-601", "Medium", 6.3, "Redirect",
       ("javascript", "html"), "assign_taint",
       sink_patterns=(r"location\.href$", r"window\.location$", r"\.href$"),
       confidence="Low",
       fix="Validate the value against an allow-list before assigning to location/href.",
       explanation="Tainted data is assigned to a navigation sink, allowing redirect to an "
                   "attacker-controlled destination."),

    # ================= CODE EXECUTION =================
    _r("EVAL-1", "Use of eval() / Dynamic Code Execution", "CWE-95", "High", 8.6, "CodeExec",
       ("python", "javascript", "php"), "call_always",
       sink_patterns=(r"\beval\(", r"\bexec\(", r"new Function\(", r"\bcreate_function\("),
       confidence="High",
       fix="Avoid dynamic code execution entirely. Use explicit parsers/whitelisted operations instead.",
       explanation="Dynamic code execution functions are dangerous even with seemingly-safe "
                   "input, since they execute arbitrary code at runtime."),

    _r("PROTOPOLLUTE-1", "Prototype Pollution", "CWE-1321", "High", 7.8, "CodeExec",
       ("javascript",), "call_taint",
       sink_patterns=(r"Object\.assign\(", r"_\.merge\(", r"_\.extend\(", r"\bmerge\("),
       confidence="Low",
       fix="Avoid merging untrusted objects into trusted ones; use Object.create(null) or "
           "a library with prototype-pollution protections, and validate keys (block __proto__).",
       explanation="Tainted data is deep-merged into an object, which can let an attacker "
                   "pollute Object.prototype and affect application-wide behaviour."),

    # ================= REDOS =================
    _r("REDOS-1", "Potential ReDoS (catastrophic backtracking)", "CWE-1333", "Medium", 6.2, "ReDoS",
       ("python", "javascript", "php", "java"), "call_always",
       sink_patterns=(r"re\.(match|search|compile|fullmatch)\(", r"preg_match\(",
                      r"Pattern\.compile\(", r"\.test\(", r"\.match\("),
       confidence="Low",
       fix="Avoid nested quantifiers like (a+)+ or (.*)+ on attacker-controlled strings; "
           "use a regex engine with backtracking limits or rewrite the pattern.",
       explanation="A regular expression with nested/overlapping quantifiers can take "
                   "exponential time on certain inputs, causing denial of service."),

    # ================= CRYPTO =================
    _r("CRYPTO-1", "Insecure Hash Algorithm", "CWE-327", "Medium", 6.8, "Crypto",
       ALL_LANGS, "call_always",
       sink_patterns=(r"\bmd5\(", r"\bsha1\(", r"hashlib\.md5", r"hashlib\.sha1"),
       confidence="High",
       fix="Use SHA-256 or stronger (or a password hashing function like bcrypt/argon2/PBKDF2 "
           "for password storage).",
       explanation="MD5/SHA-1 are cryptographically broken and unsuitable for security purposes "
                   "such as password hashing or integrity verification."),

    _r("CRYPTO-1B", "Insecure Hash Algorithm (MessageDigest)", "CWE-327", "Medium", 6.8, "Crypto",
       ("java",), "call_always",
       sink_patterns=(r"MessageDigest\.getInstance\(",),
       args_pattern=r"(MD5|SHA-?1)\b",
       confidence="High",
       fix="Use SHA-256 or stronger (e.g. MessageDigest.getInstance(\"SHA-256\")), or a "
           "password hashing function like bcrypt/argon2 for password storage.",
       explanation="MD5/SHA-1 are cryptographically broken and unsuitable for security purposes "
                   "such as password hashing or integrity verification."),

    _r("CRYPTO-2", "Weak Cipher / Insecure Mode (DES or ECB)", "CWE-327", "High", 8.1, "Crypto",
       ("java", "python", "php"), "call_always",
       sink_patterns=(r"Cipher\.getInstance\(", r"DES\.new\(", r"\bcreate_cipher\("),
       args_pattern=r"(DES(?!ede)|ECB)",
       confidence="Medium",
       fix="Use AES-256 in GCM mode (authenticated encryption) instead of DES or ECB mode.",
       explanation="DES is a broken cipher and ECB mode leaks structural information about "
                   "plaintext; both should be replaced with AES-GCM."),

    _r("CRYPTO-3", "Hardcoded Cryptographic Key or IV", "CWE-321", "High", 7.9, "Crypto",
       ALL_LANGS, "call_always",
       sink_patterns=(r"SecretKeySpec\(", r"IvParameterSpec\("),
       args_pattern=r"[\"']",
       confidence="Low",
       fix="Generate keys/IVs randomly per-operation and load keys from a secrets manager, "
           "not from source code.",
       explanation="A cryptographic key or IV appears to be a literal value embedded in source "
                   "code rather than generated/loaded securely."),

    _r("RAND-1", "Insecure Randomness for Security-Sensitive Value", "CWE-330", "Medium", 6.5, "Crypto",
       ("python", "javascript", "php", "java"), "lhs_random",
       sink_patterns=(r"Math\.random\(", r"\brandom\.random\(", r"\brandom\.randint\(",
                      r"\brand\(", r"\bmt_rand\(", r"new Random\("),
       lhs_name_pattern=r"(token|secret|password|session|otp|reset|api[_-]?key|nonce|csrf)",
       confidence="Medium",
       fix="Use a cryptographically secure RNG: secrets module (Python), crypto.randomBytes "
           "(Node), random_bytes()/random_int() (PHP), SecureRandom (Java).",
       explanation="A non-cryptographic random number generator is used to produce a "
                   "security-sensitive value (token/session id/etc.), making it potentially "
                   "predictable."),

    # NOTE: TLS/certificate-verification-disabled checks and bare debug-flag
    # assignments (DEBUG = True, etc.) aren't tied to one consistent call
    # shape across languages - they're handled by engine/config_scan.py,
    # which scans raw text directly instead of forcing them into the
    # call-sink model.

    # ================= SECRETS / CONFIG =================
    _r("SECRET-1", "Hardcoded Secret / Credential", "CWE-798", "Critical", 9.1, "Secrets",
       ALL_LANGS, "assign_literal",
       lhs_name_pattern=r"(api[_-]?key|secret|token|passwd|password|access[_-]?key|private[_-]?key|client[_-]?secret)",
       confidence="Medium",
       fix="Move secrets to environment variables or a secrets manager (Vault, AWS Secrets "
           "Manager, etc.); never commit them to source code.",
       explanation="A variable named like a credential is assigned a hardcoded literal value."),

    _r("SECRET-2", "Hardcoded Database Credential", "CWE-798", "Medium", 6.0, "Secrets",
       ("php", "python", "java", "javascript"), "assign_literal",
       lhs_name_pattern=r"(db[_-]?password|database[_-]?password|db[_-]?pass|mysql[_-]?password)",
       confidence="Medium",
       fix="Load DB credentials from environment variables or a secrets manager.",
       explanation="Database credentials appear hardcoded directly in source code."),

    _r("CORS-1", "Overly Permissive CORS Policy", "CWE-942", "High", 7.4, "Config",
       ("python", "javascript", "java"), "call_always",
       sink_patterns=(r"CORSMiddleware", r"\bcors\(", r"Access-Control-Allow-Origin"),
       args_pattern=r"\*",
       confidence="High",
       fix="Restrict allow_origins to a specific, known list of trusted domains; avoid \"*\", "
           "especially when allow_credentials is also enabled.",
       explanation="The CORS policy allows requests from any origin (\"*\"), which can expose "
                   "the API to cross-origin attacks, particularly if credentials are allowed."),

    _r("COOKIE-1", "Cookie Missing Secure/HttpOnly Flag", "CWE-614", "Medium", 5.4, "Config",
       ("php", "javascript", "python"), "missing_flag",
       sink_patterns=(r"setcookie\(", r"res\.cookie\(", r"set_cookie\("),
       args_must_match=r"(secure\s*[:=]\s*true|httponly\s*[:=]\s*true|httponly\s*[:=]\s*True|secure\s*[:=]\s*True)",
       confidence="Low",
       fix="Set the Secure and HttpOnly flags on session/auth cookies to reduce theft risk over "
           "XSS or unencrypted connections.",
       explanation="A cookie is set without visible Secure/HttpOnly flags; verify these are set "
                   "to protect the cookie from theft via XSS or network sniffing."),

    _r("JWT-1", "JWT 'none' Algorithm or Disabled Verification", "CWE-347", "Critical", 9.0, "Auth",
       ("python", "javascript", "java", "php"), "call_always",
       sink_patterns=(r"jwt\.decode\(", r"jwt\.verify\(", r"JWT::decode\("),
       args_pattern=r"(algorithm[s]?\s*=\s*\[?[\"']none|verify\s*=\s*False|verify_signature\s*=\s*False)",
       confidence="High",
       fix="Always verify JWT signatures with an explicit allow-list of algorithms; never accept "
           "'none' or skip verification.",
       explanation="JWT verification is disabled or the 'none' algorithm is accepted, allowing "
                   "an attacker to forge tokens."),

    _r("MASSASSIGN-1", "Mass Assignment", "CWE-915", "Medium", 6.7, "Config",
       ("python", "javascript"), "call_taint",
       sink_patterns=(r"\.create\(", r"\.save\(", r"Model\(", r"new \w+\("),
       confidence="Low",
       fix="Use an explicit allow-list of fields when binding request data to a model, rather "
           "than spreading the entire request body/JSON into it.",
       explanation="The full request body/JSON appears to be passed directly into a model "
                   "constructor or update call, allowing attackers to set unintended fields."),

    # ================= INFO DISCLOSURE / DEBUG =================
    _r("DEBUG-1", "Information Disclosure (debug output)", "CWE-200", "Low", 4.8, "InfoLeak",
       ("php", "python", "javascript", "java"), "call_always",
       sink_patterns=(r"\bphpinfo\(", r"\bprint_r\(", r"\bvar_dump\(", r"console\.log\(.*password",
                      r"\.printStackTrace\("),
       confidence="Medium",
       fix="Disable debug output and verbose stack traces in production builds.",
       explanation="Debug/diagnostic output left in code can leak sensitive internals "
                   "(configuration, stack traces, variable state) to end users."),

    _r("DEBUG-2", "Debug Mode Enabled", "CWE-489", "Medium", 6.1, "InfoLeak",
       ("python",), "call_always",
       sink_patterns=(r"app\.run\(",),
       args_pattern=r"debug\s*=\s*True",
       confidence="Medium",
       fix="Ensure debug mode is disabled in production deployments.",
       explanation="The application appears to run with debug mode enabled, which can expose "
                   "stack traces, source code, and an interactive debugger to end users."),
]


def rules_for_language(lang: str):
    return [r for r in RULES if lang in r.languages or "all" in r.languages]
