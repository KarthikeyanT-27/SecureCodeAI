import streamlit as st
import requests
import zipfile
import tempfile
import os
import json
from datetime import datetime
from collections import defaultdict

# ================= CONFIG =================
BACKEND_URL = "http://localhost:8000"

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".java", ".php", ".c", ".cpp", ".html", ".htm"
}

# ================= PAGE SETUP =================
st.set_page_config(
    page_title="SecureCode AI",
    layout="wide",
    page_icon="🛡️"
)

st.markdown("""
# 🛡️ SecureCode AI
### Unified Code & Global Package Security Scanner  
_SAST (Code Review) • CVE Search (All Ecosystems)_
""")

# ================= SESSION STATE =================
if "results" not in st.session_state:
    st.session_state.results = []

if "scanned" not in st.session_state:
    st.session_state.scanned = False

# ================= SIDEBAR =================
st.sidebar.title("⚙️ Scan Type")

scan_type = st.sidebar.radio(
    "Choose scan mode",
    ["🔐 Code Security Check", "📦 Package Security Check"]
)

# Clear results when switching scan type
if "last_scan_type" not in st.session_state:
    st.session_state.last_scan_type = scan_type

if st.session_state.last_scan_type != scan_type:
    st.session_state.results = []
    st.session_state.scanned = False
    st.session_state.last_scan_type = scan_type

# ================= CODE SECURITY =================
if scan_type == "🔐 Code Security Check":
    st.header("🔐 Code Security Check (SAST)")

    scan_mode = st.radio(
        "Select input type",
        ["Paste Code", "Upload File", "Upload ZIP Project"]
    )

    code = ""
    filename = ""

    if scan_mode == "Paste Code":
        code = st.text_area("Paste your source code", height=350)
        filename = "code.py"

        if st.button("🚀 Run Code Scan", use_container_width=True):
            if not code.strip():
                st.error("Please paste some code.")
            else:
                with st.spinner("🔍 Scanning code..."):
                    res = requests.post(
                        f"{BACKEND_URL}/analyze/single",
                        json={"code": code, "filename": filename},
                        timeout=30
                    )
                    if res.status_code == 200:
                        st.session_state.results = res.json()
                        st.session_state.scanned = True

    elif scan_mode == "Upload File":
        uploaded = st.file_uploader("Upload source file", type=list(SUPPORTED_EXTENSIONS))
        if uploaded:
            code = uploaded.read().decode("utf-8", errors="ignore")
            filename = uploaded.name
            st.subheader("📄 File Preview")
            st.code(code, language=filename.split(".")[-1])

            if st.button("🚀 Run Code Scan", use_container_width=True):
                with st.spinner("🔍 Scanning file..."):
                    res = requests.post(
                        f"{BACKEND_URL}/analyze/single",
                        json={"code": code, "filename": filename},
                        timeout=30
                    )
                    if res.status_code == 200:
                        st.session_state.results = res.json()
                        st.session_state.scanned = True

    elif scan_mode == "Upload ZIP Project":
        zip_file = st.file_uploader("Upload ZIP project", type="zip")

        if zip_file and st.button("🚀 Run Code Scan", use_container_width=True):
            findings = []
            with tempfile.TemporaryDirectory() as tmp:
                with zipfile.ZipFile(zip_file) as z:
                    z.extractall(tmp)

                for root, _, files in os.walk(tmp):
                    for file in files:
                        if os.path.splitext(file)[1].lower() in SUPPORTED_EXTENSIONS:
                            path = os.path.join(root, file)
                            try:
                                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                                    code = f.read()
                                res = requests.post(
                                    f"{BACKEND_URL}/analyze/single",
                                    json={"code": code, "filename": file},
                                    timeout=10
                                )
                                if res.status_code == 200:
                                    findings.extend(res.json())
                            except:
                                pass

            st.session_state.results = findings
            st.session_state.scanned = True

# ================= PACKAGE SECURITY (GLOBAL) =================
elif scan_type == "📦 Package Security Check":
    st.header("📦 Global Package Security Check (CVE Search)")

    package_name = st.text_input(
        "Package / Library name",
        placeholder="openssl, log4j, glibc, django, lodash"
    )

    package_type = st.selectbox(
        "Package Type",
        [
            "Python Package",
            "Node.js Package",
            "Java Package",
            "Go Package",
            "C / C++ Library",
            "Linux Package (Debian/Ubuntu)",
            "Alpine Linux Package"
        ]
    )

    # Map UI selection → OSV ecosystem
    ecosystem_map = {
        "Python Package": "PyPI",
        "Node.js Package": "npm",
        "Java Package": "Maven",
        "Go Package": "Go",
        "C / C++ Library": "Debian",
        "Linux Package (Debian/Ubuntu)": "Debian",
        "Alpine Linux Package": "Alpine"
    }

    if st.button("🚀 Run Package Scan", use_container_width=True):
        if not package_name.strip():
            st.error("Please enter a package name.")
        else:
            with st.spinner("📦 Searching global vulnerability database..."):
                res = requests.post(
                    f"{BACKEND_URL}/analyze/package",
                    json={
                        "package_name": package_name,
                        "ecosystem": ecosystem_map[package_type]
                    },
                    timeout=30
                )

                if res.status_code == 200:
                    st.session_state.results = res.json()
                    st.session_state.scanned = True
                else:
                    st.error("Backend error during package scan.")

# ================= RESULTS =================
st.markdown("---")
st.header("📊 Scan Results")

if st.session_state.scanned:
    results = st.session_state.results

    if not results:
        st.success("🎉 No vulnerabilities found!")
    else:
        grouped = defaultdict(list)
        for v in results:
            grouped[v["file_path"]].append(v)

        for file, vulns in grouped.items():
            with st.expander(f"🚨 {file} ({len(vulns)})", expanded=True):
                for v in vulns:
                    st.markdown(f"""
**{v['vuln_type']}**  
📍 **Line:** `{v['line']}`  
🔥 **Severity:** `{v['severity']}` | 🎯 **Score:** `{v['score']}`
""")
                    st.info(v.get("explanation", ""))
                    st.success(v.get("recommendation", ""))
                    st.divider()
else:
    st.info("Run a scan to view results.")

# ================= FOOTER =================
st.markdown("---")
st.markdown("*🛡️ SecureCode AI – Global Code & Package Vulnerability Scanner*")
