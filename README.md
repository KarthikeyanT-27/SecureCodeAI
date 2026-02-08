# SecureCodeAI
### Unified Static Code & Dependency Security Analyzer

SecureCode AI is a **Static Application Security Testing (SAST) platform** designed to detect security vulnerabilities in application source code and third-party dependencies using **taint-based static analysis** and **rule-driven security detection**.

The project focuses on identifying vulnerabilities **early in the Software Development Life Cycle (SDLC)**, helping developers write more secure software.

---

## 🚀 Features

### 🔍 Code Security Analysis
- SQL Injection detection (taint-based, multi-line)
- Cross-Site Scripting (XSS)
- Command Injection
- Buffer Overflow & Memory Issues
- Hardcoded Secrets & Credentials
- Insecure Cryptographic Practices
- Path Traversal & File Inclusion
- Information Disclosure
- Open Redirects
- Use of dangerous functions (eval, system, exec, etc.)

### 📦 Package / Dependency Security
- Identifies insecure or risky third-party packages
- Unified reporting with code-level vulnerabilities
- No need for separate dependency scanners

### 📊 Reporting
- Severity classification (Critical / High / Medium / Low)
- CWE mapping for each vulnerability
- Line-level vulnerability location
- Remediation recommendations
- Downloadable JSON reports

---

## 🧠 How It Works (High Level)

1. User uploads source code / ZIP project or package details
2. Frontend sends data to backend API
3. Backend invokes the analysis engine
4. Taint sources are identified
5. Taint propagation is performed across variables
6. Sensitive sinks are detected
7. Security rules are applied
8. Vulnerabilities are scored and deduplicated
9. Results are displayed in the UI

---

## 🏗️ System Architecture

```

User
↓
Streamlit Frontend
↓
FastAPI Backend
↓
Analysis Engine
├── Taint Analysis
├── Rule Engine
├── Package Scanner
└── CWE Mapping
↓
Report Generator

```

---

## 🧰 Tech Stack

### Frontend
- **Streamlit** – Interactive UI for code upload and results visualization

### Backend
- **FastAPI** – High-performance REST API

### Core Language
- **Python**

### Key Libraries
- `re` – Pattern matching & rule enforcement
- `json` – Structured vulnerability reports
- `requests` – API communication
- `python-multipart` – File uploads

---

## 📁 Project Structure

```

SecureCode-AI/
│
├── app.py                 # Streamlit frontend
├── main.py                # FastAPI backend
├── analyzer.py            # Core security analysis engine
├── requirements.txt       # Dependencies
├── README.md              # Project documentation
│
└── modules/               # (Optional) additional scanners / helpers

````
## ▶️ Getting Started

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/your-username/securecode-ai.git
cd securecode-ai
````

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Start Backend (FastAPI)

```bash
uvicorn main:app --reload
```

Backend runs at:

```
http://localhost:8000
```

### 4️⃣ Start Frontend (Streamlit)

```bash
streamlit run app.py
```

Frontend runs at:

```
http://localhost:8501
```

---

## 🧪 Example Vulnerabilities Detected

```php
$firstname = $_POST["firstname"];
$sql = "SELECT lastname FROM users WHERE firstname='$firstname'";
$result = mysqli_query($conn, $sql);
```

✔ SQL Injection
✔ CWE-89
✔ Severity: Critical
✔ Line-level detection
✔ Fix recommendation provided


## 🎯 Use Cases

* Academic cybersecurity projects
* Secure coding education
* Developer security awareness
* Early vulnerability detection in small teams
* Research on static analysis & taint tracking


## 🔮 Future Enhancements

* CI/CD pipeline integration
* Authentication & user dashboards
* Advanced dependency CVE matching
* Control-flow and inter-procedural analysis
* Cloud-based SaaS deployment


## ⚠️ Ethical Use

This tool is intended **only for educational and authorized security analysis**.
Unauthorized scanning of third-party or proprietary code is strictly discouraged.



## 📜 License

This project is released for **educational and research purposes**.


## 👤 Author

**Karthikeyan**
Cybersecurity & Secure Software Engineering

