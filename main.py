from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import requests

from analyzer import analyze_code  # your existing SAST engine

# ================= APP SETUP =================
app = FastAPI(title="SecureCode AI – Unified Security Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= MODELS =================
class CodeRequest(BaseModel):
    code: str
    filename: str


class PackageRequest(BaseModel):
    package_name: str
    ecosystem: str = "PyPI"   # PyPI, npm, Maven, Go


# ================= CODE SECURITY (SAST) =================
@app.post("/analyze/single")
async def analyze_single(req: CodeRequest):
    try:
        return analyze_code(req.code, req.filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ================= PACKAGE SECURITY (OSV API) =================
def scan_package_osv(package_name: str, ecosystem: str):
    url = "https://api.osv.dev/v1/query"

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }

    response = requests.post(url, json=payload, timeout=15)

    if response.status_code != 200:
        return []

    data = response.json()
    vulns = data.get("vulns", [])

    results = []

    for v in vulns:
        results.append({
            "file_path": f"dependency:{package_name}",
            "line": 0,
            "vuln_type": v.get("id", "Unknown CVE"),
            "severity": "High",
            "score": 7.5,
            "reason": "",
            "explanation": v.get("summary", "Package vulnerability"),
            "recommendation": "Upgrade to a patched or newer version",
            "lang": ecosystem.lower(),
            "code_snippet": "",
            "cwe": ""
        })

    return results


@app.post("/analyze/package")
async def analyze_package(req: PackageRequest):
    package = req.package_name.strip()

    if not package:
        raise HTTPException(status_code=400, detail="Package name is required")

    try:
        return scan_package_osv(package, req.ecosystem)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ================= ROOT =================
@app.get("/")
async def root():
    return {"message": "SecureCode AI Backend is running 🚀"}
