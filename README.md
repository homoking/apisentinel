🛡️ APISentinel
<div align="center">
AI-powered API Security Scanner — find, understand, and fix API vulnerabilities in minutes.

PythonFastAPISQLAlchemyHTMXTailwindCSSLicense: MITPRs Welcome

A polished, open-source developer tool to audit your APIs — install in minutes, use immediately.

Features • Quick Start • CLI • Dashboard • Architecture • Contributing

</div>
🎯 What is APISentinel?
APISentinel scans your APIs the way a security engineer would — but in seconds, not days.

It automatically discovers your endpoints from OpenAPI/Swagger docs, runs a battery of security checks (auth, JWT, rate limiting, headers, dangerous methods, IDOR indicators, public docs exposure), and produces plain-English explanations, realistic attack scenarios, and actionable fixes for every finding.

Everything is wrapped in a modern HTMX + Tailwind dashboard, a fast Typer CLI, and a clean architecture you can extend in a single afternoon.

🧠 Built for developers who want the insight of a pentester without the complexity of one.
---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Dashboard](#-dashboard)
- [CLI](#-cli)
- [API](#-api)
- [Security Checks](#-security-checks)
- [AI Security Analysis](#-ai-security-analysis)
- [Reports](#-reports)
- [Configuration](#%EF%B8%8F-configuration)
- [Project Structure](#-project-structure)
- [Testing a Target](#-testing-a-target)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**APISentinel** is a developer-first API security scanner that automatically discovers API endpoints, runs practical security checks, and provides AI-powered recommendations for every issue it finds.

It's designed to be the tool you run before pushing to production — a security review that takes minutes instead of hours.

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   Target URL ──► Discovery ──► Security Rules ──► AI Analysis   │
│                                       │                         │
│                                       ▼                         │
│                          Score · Findings · Reports             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Why APISentinel?

Pain PointAPISentinel SolutionAPI security audits take hoursAutomated scans complete in secondsSecurity findings are crypticEvery issue includes a plain-English explanationDevs don't know how to fix issuesAI provides attack scenarios + concrete fixesExisting tools require complex setup`pip install -e .` and you're runningNo unified view of API security postureDashboard with scores, history, and breakdowns

---

## ✨ Features

### 🔎 API Discovery

- Automatically detects **OpenAPI 3.x** and **Swagger 2.0** documents
- Probes common documentation paths (`/openapi.json`, `/swagger.json`, `/api-docs`, `/v3/api-docs`)
- Extracts all endpoints, HTTP methods, parameters, auth requirements, and tags
- Supports both **URL targets** and **local file** inputs (JSON/YAML)

### 🛡️ Security Scanner

Seven built-in security rules covering OWASP API Top 10 concerns:

RuleSeverityWhat It ChecksMissing AuthenticationHigh/MediumEndpoints without declared auth requirementsWeak JWT ConfigurationHigh/LowAmbiguous token formats, weak algorithm hintsMissing Rate LimitingMediumAbsence of rate-limit response headersMissing Security HeadersMediumHSTS, X-Content-Type-Options, CSPDangerous HTTP MethodsMedium/HighTRACE, DELETE exposure without controlsPublic OpenAPI ExposureLowSwagger/OpenAPI docs reachable from public internetIDOR IndicatorsHighObject IDs in paths/params without auth

### 🤖 AI Security Analysis

Every finding is enriched with:

- **Plain-English Explanation** — what the issue means in simple terms
- **Attack Scenario** — how an attacker could exploit it in practice
- **Recommended Fix** — concrete, copy-paste-friendly remediation steps

Works **offline by default** with a curated local knowledge base. Optionally integrates with OpenAI for deeper analysis.

### 📊 Security Score

- **0–100 score** calculated from finding severities
- Weighted scoring: Critical (−30), High (−20), Medium (−10), Low (−4), Info (−1)
- Severity distribution breakdown (Critical / High / Medium / Low / Info)
- Color-coded indicators: 🟢 80+ | 🟡 50–79 | 🔴 0–49

### 📄 Reports

Generate reports in three formats:

FormatUse CaseCommand**HTML**Share with stakeholders, embed in wikis`apiscan report --format html`**JSON**CI/CD integration, programmatic analysis`apiscan report --format json`**Markdown**Git repos, documentation, PR reviews`apiscan report --format markdown`

Each report includes: Executive summary · All findings with evidence · Security score · AI recommendations

### 🖥️ Web Dashboard

Modern, responsive dashboard built with HTMX + Tailwind CSS:

- **Overview** — security score, recent scans, risk breakdown at a glance
- **Scan History** — browse all past scans with scores and finding counts
- **Findings** — filter and review all detected issues across scans
- **Report Details** — deep-dive into individual scan results with AI analysis

### ⌨️ CLI

Fast, colorful command-line interface powered by Typer + Rich:

```bash
apiscan scan <target>      # Run a security scan
apiscan report             # Generate a report from the latest scan
apiscan dashboard          # Launch the web dashboard
```

---

## 🏗️ Architecture

APISentinel follows **Clean Architecture** with strict separation of concerns:

```
apisentinel/
├── api/            # FastAPI application & REST endpoints
├── cli/            # Typer CLI commands
├── core/           # Shared config, security primitives, constants
├── scanner/        # Discovery engine, security rules, scan models
├── ai/             # AI analysis service (local + OpenAI)
├── database/       # SQLAlchemy models, sessions, repository
├── dashboard/      # HTMX routes + Jinja2 templates
│   └── templates/  # HTML templates (base, overview, detail, etc.)
└── reports/        # HTML/JSON/Markdown report generation
```

**Key Design Decisions:**

- **Modular rules engine** — each security check is an independent class; add new rules by extending `BaseRule`
- **Repository pattern** — database access is abstracted behind `ScanRepository`
- **Async-first** — discovery and scanning use `httpx.AsyncClient` for non-blocking I/O
- **Settings via Pydantic** — type-safe configuration with `.env` file support
- **SQLite default, PostgreSQL ready** — zero-config locally, production-grade in deployment

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+**
- **pip** (or **uv** for faster installs)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/apisentinel.git
cd apisentinel

# Create a virtual environment
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install APISentinel in editable mode
pip install -e .
```

### Launch the Dashboard

```bash
uvicorn apisentinel.api.app:app --reload
```

Open **http://127.0.0.1:8000** in your browser.

### Run Your First Scan

**Option A: Dashboard** — paste a URL into the scan form and click "Run Scan"

**Option B: CLI**

```bash
apiscan scan https://petstore.swagger.io/v2
```

**Option C: API**

```bash
curl -X POST http://127.0.0.1:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://petstore.swagger.io/v2"}'
```

---

## 🖥️ Dashboard

The dashboard provides a real-time view of your API security posture.

### Pages

PageURLDescription**Overview**`/`Security score, scan form, recent scans, risk breakdown**Scan History**`/scans`Browse all past scans sorted by date**Findings**`/findings`All detected issues across every scan**Report Detail**`/scans/{id}`Deep-dive into a single scan with AI analysis

### Dashboard Features

- ⚡ **HTMX-powered** — scans run without page reloads
- 🎨 **Dark theme** — easy on the eyes during late-night security reviews
- 📱 **Responsive** — works on desktop, tablet, and mobile
- 🔄 **Live scan status** — visual feedback while scans are in progress
- 🎯 **Color-coded scores** — instantly see if your API is green, yellow, or red

---

## ⌨️ CLI

```bash
# Scan a live API
apiscan scan https://api.example.com

# Scan a local OpenAPI file
apiscan scan ./openapi.json

# Generate an HTML report from the latest scan
apiscan report --format html --output report.html

# Generate a Markdown report
apiscan report --format markdown --output report.md

# Generate a JSON report
apiscan report --format json --output report.json

# Launch the web dashboard
apiscan dashboard
```

---

## 🔌 API

APISentinel exposes a RESTful API alongside the dashboard.

### Endpoints

MethodPathDescription`GET/health`Health check`POST/api/scans`Create a new scan`GET/api/scans`List all scans`GET/api/scans/{id}`Get scan details`GET/api/scans/{id}/report?format=json`Download scan report

### Example: Create a Scan

```bash
curl -X POST http://127.0.0.1:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://petstore.swagger.io/v2"}'
```

### Example Response

```json
{
  "id": "a1b2c3d4e5f6...",
  "target": "https://petstore.swagger.io/v2",
  "created_at": "2026-06-23T12:00:00Z",
  "summary": {
    "score": 42,
    "findings_count": 8,
    "severity_distribution": {
      "critical": 0,
      "high": 3,
      "medium": 4,
      "low": 1,
      "info": 0
    }
  },
  "findings": [
    {
      "rule_id": "missing-authentication",
      "title": "Missing authentication",
      "severity": "high",
      "endpoint": "/pet/{petId}",
      "method": "GET",
      "description": "GET /pet/{petId} does not declare an authentication requirement.",
      "why_it_matters": "Unauthenticated API operations may expose sensitive data.",
      "ai": {
        "explanation": "The endpoint appears callable without an authenticated user.",
        "attack_scenario": "A malicious user calls the endpoint directly to read private data.",
        "recommended_fix": "Require strong authentication by default."
      }
    }
  ]
}
```

---

## 🔒 Security Checks

### 1. Missing Authentication

Flags endpoints that don't declare any security requirement in the OpenAPI spec. Sensitive paths (`/user`, `/admin`, `/payment`, etc.) are elevated to **High** severity.

### 2. Weak JWT Configuration

Analyzes `securitySchemes` in the OpenAPI spec for:

- Bearer auth without explicit `bearerFormat: JWT`
- References to weak algorithms (`none`, `HS256` without proper context)

### 3. Missing Rate Limiting

Checks response headers for rate-limiting indicators (`x-ratelimit-*`, `retry-after`, `ratelimit-*`). Missing rate limits enable brute-force, credential stuffing, and denial-of-service attacks.

### 4. Missing Security Headers

Verifies the presence of critical HTTP security headers:

- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options`
- `Content-Security-Policy`

### 5. Dangerous HTTP Methods

Flags `TRACE` (cross-site tracing risk) and `DELETE` (destructive actions) endpoints that may need additional access controls.

### 6. Public OpenAPI Exposure

Detects when API documentation is publicly accessible, which helps attackers map your attack surface.

### 7. IDOR Indicators

Identifies endpoints with object identifier parameters (`id`, `user_id`, `account_id`, etc.) that lack authentication — a precursor to Insecure Direct Object Reference attacks.

---

## 🤖 AI Security Analysis

Every detected issue is enriched with AI-generated security guidance:

```
┌─────────────────────────────────────────────────────┐
│  Issue: Missing Rate Limiting                       │
│                                                     │
│  💡 Explanation:                                    │
│  The API does not show evidence that repeated       │
│  requests are throttled.                            │
│                                                     │
│  ⚔️  Attack Scenario:                               │
│  An attacker automates login attempts, password     │
│  resets, or expensive searches until accounts or    │
│  capacity are exhausted.                            │
│                                                     │
│  ✅ Recommended Fix:                                │
│  Apply per-IP and per-account limits on sensitive   │
│  endpoints; for login, start with 5 failed          │
│  attempts per minute and progressive backoff.       │
└─────────────────────────────────────────────────────┘
```

### AI Modes

ModeConfigDescription**Local** (default)`APISENTINEL_AI_PROVIDER=local`Deterministic, offline, works without API keys**OpenAI**`APISENTINEL_AI_PROVIDER=openai`Uses GPT models for deeper, context-aware analysis

---

## 📄 Reports

### HTML Report

A standalone, styled HTML document suitable for sharing with stakeholders:

- Dark-themed design matching the dashboard
- Security score prominently displayed
- Each finding with severity badge, evidence, and AI analysis
- No external dependencies — works offline

### JSON Report

Machine-readable output for CI/CD integration:

```bash
apiscan report --format json --output report.json
```

### Markdown Report

Perfect for Git repos, pull requests, and documentation:

```bash
apiscan report --format markdown --output SECURITY_REPORT.md
```

---

## ⚙️ Configuration

APISentinel is configured via environment variables or a `.env` file in the project root.

VariableDefaultDescription`APISENTINEL_DATABASE_URLsqlite:///./.data/apisentinel.db`Database connection string`APISENTINEL_AI_PROVIDERlocal`AI provider: `local` or `openaiAPISENTINEL_OPENAI_API_KEY`—OpenAI API key (required if `ai_provider=openai`)`APISENTINEL_REQUEST_TIMEOUT_SECONDS10.0`HTTP request timeout for scanning`APISENTINEL_REDIS_URL`—Redis URL for background task queue`APISENTINEL_ENVIRONMENTdevelopment`Runtime environment`APISENTINEL_DEBUGfalse`Enable debug mode

### Example `.env`

```env
APISENTINEL_DATABASE_URL=sqlite:///./.data/apisentinel.db
APISENTINEL_AI_PROVIDER=local
APISENTINEL_REQUEST_TIMEOUT_SECONDS=15.0
```

### PostgreSQL (Production)

```env
APISENTINEL_DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/apisentinel
```

---

## 📁 Project Structure

```
apisentinel/
│
├── pyproject.toml                  # Build config, dependencies, CLI entry point
├── README.md                       # This file
├── .env                            # Local configuration (gitignored)
│
├── apisentinel/
│   ├── __init__.py
│   │
│   ├── api/                        # FastAPI application
│   │   ├── __init__.py
│   │   └── app.py                  # App factory, REST endpoints, lifespan
│   │
│   ├── cli/                        # Typer CLI
│   │   ├── __init__.py
│   │   └── main.py                 # scan, report, dashboard commands
│   │
│   ├── core/                       # Shared primitives
│   │   ├── __init__.py
│   │   ├── config.py               # Pydantic Settings
│   │   └── security.py             # Severity enum, score calculation
│   │
│   ├── scanner/                    # Scanning engine
│   │   ├── __init__.py
│   │   ├── models.py               # Pydantic models (ScanResult, Finding, etc.)
│   │   ├── discovery.py            # OpenAPI/Swagger discovery service
│   │   ├── rules.py                # Security rule classes
│   │   └── engine.py               # Orchestrator (discovery → rules → AI)
│   │
│   ├── ai/                         # AI analysis
│   │   ├── __init__.py
│   │   └── service.py              # Local knowledge + OpenAI integration
│   │
│   ├── database/                   # Persistence layer
│   │   ├── __init__.py
│   │   ├── session.py              # Engine, session factory, init_db
│   │   ├── models.py               # SQLAlchemy ScanRecord model
│   │   └── repository.py           # ScanRepository (save/list/get)
│   │
│   ├── dashboard/                  # Web UI
│   │   ├── __init__.py
│   │   ├── routes.py               # HTMX routes (overview, scans, findings)
│   │   └── templates/
│   │       ├── base.html           # Layout with nav, Tailwind, HTMX
│   │       ├── overview.html       # Dashboard home page
│   │       ├── scans.html          # Scan history page
│   │       ├── findings.html       # All findings page
│   │       ├── detail.html         # Individual scan report
│   │       ├── report.html         # Standalone HTML report template
│   │       └── partials/
│   │           ├── recent_scans.html    # HTMX partial: scan list
│   │           ├── scan_status.html     # HTMX partial: idle state
│   │           ├── scan_running.html    # HTMX partial: scanning indicator
│   │           └── scan_complete.html   # HTMX partial: done notification
│   │
│   └── reports/                    # Report generation
│       ├── __init__.py
│       └── generator.py            # HTML/JSON/Markdown generators
│
└── tests/                          # Test suite
    └── ...
```

---

## 🎯 Testing a Target

### Public Test APIs

These are safe, public APIs you can scan without permission:

```bash
# Swagger Petstore (classic test target)
apiscan scan https://petstore.swagger.io/v2

# Petstore v3
apiscan scan https://petstore3.swagger.io/api/v3

# httpbin (minimal endpoints)
apiscan scan https://httpbin.org
```

### Local OpenAPI File

```bash
# Scan a local spec file
apiscan scan ./path/to/openapi.json
apiscan scan ./path/to/swagger.yaml
```

### Your Own API

```bash
# Scan your local development server
apiscan scan http://127.0.0.1:8001

# Scan a staging API (with permission!)
apiscan scan https://api-staging.yourcompany.com
```

> ⚠️ **Important:** Only scan APIs you own or have explicit permission to test. APISentinel performs passive analysis (reads documentation and headers) — it does not exploit vulnerabilities.

---

## 🔧 Development

### Setup

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run linting
ruff check apisentinel/

# Run type checking
mypy apisentinel/

# Run tests
pytest
```

### Adding a New Security Rule

1. Create a new class in `apisentinel/scanner/rules.py`:

```python
class MyNewRule(BaseRule):
    id = "my-new-rule"
    title = "My new security check"

    def check(self, context: RuleContext) -> Iterable[Finding]:
        # Your detection logic here
        if some_condition:
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=Severity.MEDIUM,
                description="What was detected.",
                why_it_matters="Why the developer should care.",
            )
```

2. Add it to `DEFAULT_RULES` in the same file:

```python
DEFAULT_RULES: tuple[BaseRule, ...] = (
    # ... existing rules ...
    MyNewRule(),
)
```

3. Add AI guidance in `apisentinel/ai/service.py`:

```python
LOCAL_KNOWLEDGE["my-new-rule"] = AIAnalysis(
    explanation="...",
    attack_scenario="...",
    recommended_fix="...",
)
```

### Optional Dependencies

```bash
# OpenAI integration
pip install -e ".[openai]"

# Redis for background tasks
pip install -e ".[redis]"
```

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-new-check`
3. **Implement** your changes with tests
4. **Lint** your code: `ruff check apisentinel/`
5. **Submit** a Pull Request

### Ideas for Contributions

- 🆕 New security rules (CORS misconfiguration, verbose errors, etc.)
- 🌐 Internationalization (i18n) for findings and reports
- 🔗 CI/CD integrations (GitHub Actions, GitLab CI)
- 📊 Chart visualizations in the dashboard
- 🔄 WebSocket-based real-time scan progress
- 🐳 Docker / Docker Compose setup
- 📚 More comprehensive test suite

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

If APISentinel saves you from a breach, give it a ⭐ on GitHub.

Made with 🛡️ for developers who care about security.
