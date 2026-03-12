# Security Scanner — Complete Usage Guide

A comprehensive reference for all commands, flags, configuration, and usage examples including AI-powered analysis.

---

## Table of Contents

- [Installation](#installation)
- [Configuration & Settings](#configuration--settings)
  - [Config File](#config-file)
  - [Environment Variables](#environment-variables)
  - [Setting API Keys](#setting-api-keys)
  - [Viewing Configuration](#viewing-configuration)
  - [All Config Keys](#all-config-keys)
- [Commands Reference](#commands-reference)
  - [scan](#scan)
  - [config set](#config-set)
  - [config get](#config-get)
  - [version](#version)
- [Scan Examples](#scan-examples)
  - [Basic Dependency Scan (No API Keys Needed)](#1-basic-dependency-scan-no-api-keys-needed)
  - [Verbose Mode](#2-verbose-mode)
  - [JSON Output](#3-json-output)
  - [SARIF Output](#4-sarif-output-for-github-code-scanning--vs-code)
  - [Filter by Severity](#5-filter-by-severity)
  - [Write to File](#6-write-output-to-file)
  - [AI-Powered Code Analysis](#7-ai-powered-code-analysis)
  - [AI-Only (Skip Dependencies)](#8-ai-only-scan-skip-dependency-checking)
  - [Full Scan (Dependencies + AI)](#9-full-scan-dependencies--ai-code-analysis)
- [AI Use Cases](#ai-use-cases)
  - [Detecting SQL Injection](#detecting-sql-injection)
  - [Finding Hardcoded Secrets](#finding-hardcoded-secrets)
  - [Identifying Command Injection](#identifying-command-injection)
  - [Catching Insecure TLS](#catching-insecure-tls-configuration)
  - [OWASP Top 10 Coverage](#owasp-top-10-coverage)
- [AI Enrichment Layer](#ai-enrichment-layer)
  - [How It Works](#how-it-works)
  - [Enrichment Output Fields](#enrichment-output-fields)
  - [Example Enriched Output](#example-enriched-output)
- [Supported Ecosystems & Files](#supported-ecosystems--files)
- [Vulnerability Databases](#vulnerability-databases)
- [Exit Codes](#exit-codes)

---

## Installation

### From Source

```bash
git clone https://github.com/security-scanner/security-scanner.git
cd security-scanner
make build
# binary is at ./bin/security-scanner
```

### Go Install

```bash
go install github.com/security-scanner/security-scanner@latest
```

---

## Configuration & Settings

### Config File

Configuration is stored in `~/.security-scanner.json`:

```json
{
  "openai_api_key": "sk-proj-...",
  "openai_model": "gpt-4",
  "nvd_api_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "github_token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

### Environment Variables

Environment variables **always take precedence** over config file values:

| Variable | Purpose |
|----------|---------|
| `OPENAI_API_KEY` | OpenAI API key for AI code analysis |
| `OPENAI_MODEL` | OpenAI model name (default: `gpt-4`) |
| `NVD_API_KEY` | NIST NVD API key for vulnerability lookups |
| `GITHUB_TOKEN` | GitHub token for advisory database access |

**Example — using environment variables:**

```bash
# Set keys via environment (add to ~/.zshrc or ~/.bashrc for persistence)
export OPENAI_API_KEY="sk-proj-abc123..."
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Now run scans — keys are picked up automatically
security-scanner scan /path/to/project
```

### Setting API Keys

Use `config set` to persist keys to the config file:

```bash
# Required for AI-powered code analysis
security-scanner config set openai-key sk-proj-abc123def456...

# Choose a specific OpenAI model
security-scanner config set openai-model gpt-4-turbo

# Optional: NVD key gives higher rate limits (50 req/30s vs 5 req/30s)
# Get one free at: https://nvd.nist.gov/developers/request-an-api-key
security-scanner config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Optional: GitHub token for advisory database access
# Create at: https://github.com/settings/tokens
security-scanner config set github-token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Viewing Configuration

```bash
# View a specific key (secrets are masked)
security-scanner config get openai-key
# Output: ****abc1

security-scanner config get openai-model
# Output: gpt-4-turbo

security-scanner config get nvd-key
# Output: ****xxxx
```

### All Config Keys

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `openai-key` | For AI scan | — | OpenAI API key (`sk-proj-...` or `sk-...`) |
| `openai-model` | No | `gpt-4` | Model to use (`gpt-4`, `gpt-4-turbo`, `gpt-4o`, etc.) |
| `nvd-key` | No | — | NVD API key for higher rate limits |
| `github-token` | No | — | GitHub personal access token |

---

## Commands Reference

### `scan`

Scan a project directory for vulnerabilities.

```
security-scanner scan [path] [flags]
```

**Arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | No | `.` (current dir) | Path to the project directory |

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `table` | Output format: `table`, `json`, `sarif` |
| `--output` | `-o` | stdout | Write output to a file |
| `--severity` | `-s` | (all) | Minimum severity filter: `critical`, `high`, `medium`, `low` |
| `--skip-ai` | — | `false` | Skip AI code analysis (dependency scan only) |
| `--skip-deps` | — | `false` | Skip dependency scan (code analysis only) |
| `--verbose` | `-v` | `false` | Show detailed progress output |

---

### `config set`

Set a configuration value.

```
security-scanner config set <key> <value>
```

**Examples:**

```bash
security-scanner config set openai-key sk-proj-abc123...
security-scanner config set openai-model gpt-4o
security-scanner config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
security-scanner config set github-token ghp_xxxxxxxxxxxx
```

---

### `config get`

Get a configuration value (secrets are masked).

```
security-scanner config get <key>
```

**Examples:**

```bash
security-scanner config get openai-model
# Output: gpt-4o

security-scanner config get openai-key
# Output: ****23...
```

---

### `version`

Print the version.

```bash
security-scanner version
# Output: security-scanner v0.1.0 (built with go1.26.0)
```

---

## Scan Examples

### 1. Basic Dependency Scan (No API Keys Needed)

Scan a Node.js project's dependencies against the OSV database:

```bash
security-scanner scan --skip-ai /path/to/node-project
```

**Example output:**

```
🔍 Security Scan Results for /path/to/node-project
   Scanned 142 packages across 1 ecosystems in 2.3s

📦 Dependency Vulnerabilities (3 found)

╭──────────┬────────────────────┬──────────────┬─────────┬─────────┬────────────────────────────────────────╮
│ SEVERITY │ ID                 │ PACKAGE      │ VERSION │ FIXED   │ SUMMARY                                │
├──────────┼────────────────────┼──────────────┼─────────┼─────────┼────────────────────────────────────────┤
│ CRITICAL │ GHSA-xxxx-xxxx     │ lodash       │ 4.17.15 │ 4.17.21 │ Prototype Pollution in lodash           │
│ HIGH     │ CVE-2023-xxxxx     │ express      │ 4.17.1  │ 4.17.3  │ Open redirect vulnerability             │
│ MEDIUM   │ CVE-2022-xxxxx     │ minimatch    │ 3.0.4   │ 3.1.2   │ ReDoS vulnerability                     │
╰──────────┴────────────────────┴──────────────┴─────────┴─────────┴────────────────────────────────────────╯

Summary: 3 total vulnerabilities
  🔴 Critical: 1
  🟠 High:     1
  🟡 Medium:   1
```

---

### 2. Verbose Mode

See detailed progress during scanning:

```bash
security-scanner scan --skip-ai -v /path/to/go-project
```

**Example output:**

```
🔍 Scanning /path/to/go-project ...

📂 Detecting project ecosystems...
   Found 1 manifest files across 1 ecosystems
   - go.mod (Go)

📦 Parsing dependencies...
   Parsed 5 packages from go.mod
   Total: 5 packages

🔎 Querying vulnerability databases...
   Skipping NVD (no API key configured)
   Skipping GitHub Advisory (no token configured)
   Found 0 dependency vulnerabilities

✅ No vulnerabilities found in /path/to/go-project
   Scanned 5 packages across 1 ecosystems in 1s
```

---

### 3. JSON Output

Get machine-readable JSON output for scripting and pipelines:

```bash
security-scanner scan --skip-ai --format json /path/to/project
```

**Example output:**

```json
{
  "project_path": "/path/to/project",
  "ecosystems": ["npm"],
  "total_packages": 142,
  "vulnerabilities": [
    {
      "id": "GHSA-xxxx-xxxx",
      "aliases": ["CVE-2021-23337"],
      "summary": "Prototype Pollution in lodash",
      "severity": "CRITICAL",
      "score": 9.8,
      "package": {
        "name": "lodash",
        "version": "4.17.15",
        "ecosystem": "npm",
        "file_path": "/path/to/project/package-lock.json"
      },
      "fixed_in": "4.17.21",
      "source": "osv",
      "references": ["https://github.com/advisories/GHSA-xxxx-xxxx"]
    }
  ],
  "scanned_at": "2026-03-12T10:30:00Z",
  "duration": 2300000000
}
```

**Pipe to `jq` for filtering:**

```bash
# Count critical vulnerabilities
security-scanner scan --skip-ai --format json . | jq '[.vulnerabilities[] | select(.severity == "CRITICAL")] | length'

# List all affected packages
security-scanner scan --skip-ai --format json . | jq '.vulnerabilities[].package.name'

# Get only package names with fixes available
security-scanner scan --skip-ai --format json . | jq '.vulnerabilities[] | select(.fixed_in != "") | {package: .package.name, current: .package.version, fix: .fixed_in}'
```

---

### 4. SARIF Output (for GitHub Code Scanning / VS Code)

Generate SARIF v2.1.0 output for integration with GitHub Code Scanning or VS Code:

```bash
# Write SARIF to file
security-scanner scan --format sarif --output results.sarif /path/to/project
```

**Upload to GitHub Code Scanning:**

```bash
# In a GitHub Actions workflow:
- name: Run security scan
  run: security-scanner scan --format sarif --output results.sarif --skip-ai .

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Example SARIF output:**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "security-scanner",
        "version": "0.1.0",
        "rules": [{
          "id": "SEC-005",
          "shortDescription": { "text": "Hardcoded Secret or API Key" },
          "defaultConfiguration": { "level": "error" }
        }]
      }
    },
    "results": [{
      "ruleId": "SEC-005",
      "level": "error",
      "message": { "text": "Hardcoded Secret or API Key" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/config.py" },
          "region": { "startLine": 15 }
        }
      }]
    }]
  }]
}
```

---

### 5. Filter by Severity

Only show vulnerabilities at or above a given severity level:

```bash
# Only critical
security-scanner scan --severity critical /path/to/project

# High and above (high + critical)
security-scanner scan --severity high /path/to/project

# Medium and above
security-scanner scan -s medium /path/to/project
```

---

### 6. Write Output to File

```bash
# Table output to file
security-scanner scan --output report.txt /path/to/project

# JSON to file
security-scanner scan --format json --output report.json /path/to/project

# SARIF to file
security-scanner scan --format sarif --output results.sarif /path/to/project
```

---

### 7. AI-Powered Code Analysis

**Prerequisites:** Set your OpenAI API key first.

```bash
# Set key (one-time)
security-scanner config set openai-key sk-proj-abc123def456...

# Or use environment variable
export OPENAI_API_KEY="sk-proj-abc123def456..."
```

**Run a full scan (dependencies + AI):**

```bash
security-scanner scan -v /path/to/project
```

**Example output with AI findings:**

```
🔍 Security Scan Results for /path/to/project
   Scanned 28 packages across 2 ecosystems in 12.4s

📦 Dependency Vulnerabilities (1 found)

╭──────────┬────────────────────┬──────────────┬─────────┬─────────┬──────────────────────────────╮
│ SEVERITY │ ID                 │ PACKAGE      │ VERSION │ FIXED   │ SUMMARY                      │
├──────────┼────────────────────┼──────────────┼─────────┼─────────┼──────────────────────────────┤
│ HIGH     │ CVE-2023-xxxxx     │ pyyaml       │ 5.3.1   │ 6.0.1   │ Arbitrary code execution     │
╰──────────┴────────────────────┴──────────────┴─────────┴─────────┴──────────────────────────────╯

🔬 Code Analysis Findings (3 found)

╭──────────┬─────────┬────────────────────┬──────┬──────────────────────────────────────────────────╮
│ SEVERITY │ ID      │ FILE               │ LINE │ FINDING                                          │
├──────────┼─────────┼────────────────────┼──────┼──────────────────────────────────────────────────┤
│ CRITICAL │ SEC-003 │ app/views.py       │   42 │ Potential Command Injection                      │
│ HIGH     │ SEC-005 │ config/settings.py │   15 │ Hardcoded Secret or API Key                      │
│ HIGH     │ AI-001  │ app/views.py       │   67 │ SQL query built from unsanitized user input       │
╰──────────┴─────────┴────────────────────┴──────┴──────────────────────────────────────────────────╯

Summary: 4 total vulnerabilities
  🔴 Critical: 1
  🟠 High:     3
```

---

### 8. AI-Only Scan (Skip Dependency Checking)

Only run code analysis (pattern matching + AI):

```bash
security-scanner scan --skip-deps -v /path/to/project
```

---

### 9. Full Scan (Dependencies + AI Code Analysis)

Run everything — dependencies against all CVE databases and AI code analysis:

```bash
# Set up all keys for maximum coverage
security-scanner config set openai-key sk-proj-...
security-scanner config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
security-scanner config set github-token ghp_xxxxxxxxxxxx

# Full scan with all databases + AI
security-scanner scan -v /path/to/project
```

---

## AI Use Cases

The AI analyzer works in two stages:
1. **Pattern matching** (always runs, no API key needed) — fast regex-based detection of common vulnerability patterns
2. **OpenAI GPT-4 deep analysis** (requires API key) — sends flagged code snippets for semantic analysis, confirms/dismisses false positives, and finds additional issues

### Detecting SQL Injection

**Vulnerable code (`app/db.py`):**

```python
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
```

**Scanner output:**

```
│ HIGH │ SEC-002 │ app/db.py │ 2 │ Potential SQL Injection (string concat) │
```

**AI recommendation (with `--verbose`):**

> SQL query built with string concatenation from user input. Use parameterized queries:
> ```python
> cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
> ```

---

### Finding Hardcoded Secrets

**Vulnerable code (`config.js`):**

```javascript
const API_KEY = "sk-proj-abc123def456ghi789jkl012mno345";
const DB_PASSWORD = "super_secret_password_123";
```

**Scanner output:**

```
│ HIGH     │ SEC-005 │ config.js │  1 │ Hardcoded Secret or API Key │
│ HIGH     │ SEC-005 │ config.js │  2 │ Hardcoded Secret or API Key │
```

---

### Identifying Command Injection

**Vulnerable code (`handler.go`):**

```go
func runCommand(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    out, _ := exec.Command("sh", "-c", cmd).Output()
    w.Write(out)
}
```

**Scanner output:**

```
│ CRITICAL │ SEC-003 │ handler.go │ 3 │ Potential Command Injection │
```

---

### Catching Insecure TLS Configuration

**Vulnerable code (`client.go`):**

```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
```

**Scanner output:**

```
│ CRITICAL │ SEC-010 │ client.go │ 2 │ TLS Certificate Verification Disabled │
```

---

### OWASP Top 10 Coverage

The scanner detects vulnerabilities mapped to the OWASP Top 10:

| OWASP Category | Detection Rules |
|----------------|----------------|
| A01: Broken Access Control | AI analysis of auth/middleware patterns |
| A02: Cryptographic Failures | SEC-007 (weak MD5/SHA1), SEC-005 (hardcoded secrets), SEC-006 (AWS keys) |
| A03: Injection | SEC-001/SEC-002 (SQL injection), SEC-003 (command injection), SEC-008 (XSS) |
| A04: Insecure Design | AI analysis of architectural patterns |
| A05: Security Misconfiguration | SEC-010 (TLS disabled), SEC-012 (CORS wildcard), SEC-009 (HTTP) |
| A06: Vulnerable Components | Dependency scanning (OSV, NVD, GitHub Advisory) |
| A07: Auth Failures | AI analysis of authentication code |
| A08: Data Integrity | SEC-011 (insecure deserialization) |
| A09: Logging Failures | AI analysis of logging practices |
| A10: SSRF | SEC-004 (path traversal), AI analysis of URL handling |

---

## AI Enrichment Layer

When an OpenAI API key is configured, the scanner automatically enriches **all** vulnerabilities (both dependency and code findings) with structured AI analysis. This provides actionable context beyond raw CVE data.

### How It Works

1. **Evidence collection** — For each finding, the scanner builds a structured evidence block containing: package name/version, advisory text, severity, CVSS score, dependency path, file locations, code snippets, matched pattern rules, reachability hints, and known fix versions.
2. **AI analysis** — Evidence blocks are batched and sent to GPT-4 with a specialized enrichment prompt.
3. **Structured output** — The model returns structured fields (not free-form text) that are attached to each vulnerability.

### Enrichment Output Fields

| Field | Description |
|-------|-------------|
| **Summary** | 3-line summary: (1) what the vuln is, (2) how it's exploited, (3) affected component |
| **Likely Impact** | Realistic impact assessment (e.g., "Remote code execution via crafted YAML payload") |
| **Confidence** | HIGH / MEDIUM / LOW — whether this is a real, exploitable issue in context |
| **Minimal Remediation** | Smallest targeted fix (e.g., "Upgrade lodash from 4.17.15 to 4.17.21") |
| **Suppression Rationale** | Draft rationale for accepting risk (e.g., "Only used in test fixtures") |

### Example Enriched Output

**Table format** (with enrichment details printed below each table):

```
📦 Dependency Vulnerabilities (1 found)

╭──────────┬────────────────┬────────┬────────┬─────────┬──────────────────────────╮
│ Severity │ ID             │ Package│ Version│ Fixed In│ Summary                  │
├──────────┼────────────────┼────────┼────────┼─────────┼──────────────────────────┤
│ HIGH     │ GHSA-xxxx-xxxx │ lodash │ 4.17.15│ 4.17.21 │ Prototype Pollution      │
╰──────────┴────────────────┴────────┴────────┴─────────┴──────────────────────────╯

  🤖 AI Enrichment Details:

  ── GHSA-xxxx-xxxx (HIGH) [Confidence: HIGH] ──
     Prototype pollution in lodash < 4.17.21.
     Attacker can inject properties via mergeWith or zipObjectDeep.
     Affects lodash used in server-side request parsing.
     Impact: Remote DoS or privilege escalation via __proto__ injection
     Fix: Upgrade lodash from 4.17.15 to 4.17.21
     Suppress: Only used in build tooling; not reachable from user input
```

**JSON format** — enrichment fields appear directly on each vulnerability object:

```json
{
  "id": "GHSA-xxxx-xxxx",
  "severity": "HIGH",
  "ai_enrichment": {
    "summary": "Prototype pollution in lodash < 4.17.21.\nAttacker can inject...",
    "likely_impact": "Remote DoS or privilege escalation via __proto__ injection",
    "confidence": "HIGH",
    "minimal_remediation": "Upgrade lodash from 4.17.15 to 4.17.21",
    "suppression_rationale": "Only used in build tooling; not reachable from user input"
  }
}
```

**SARIF format** — enrichment is appended to the result message text for compatibility with code scanning tools.

To skip AI enrichment (e.g., for faster scans), use `--skip-ai`:

```bash
security-scanner scan ./my-project --skip-ai
```

---

## Supported Ecosystems & Files

| Ecosystem | Manifest Files Parsed |
|-----------|----------------------|
| **Go** | `go.mod` |
| **Python** | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
| **Node.js** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts` |

**Source code analysis** scans files with these extensions:
`.go`, `.py`, `.java`, `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.html`, `.yaml`, `.yml`, `.json`, `.env`, `.properties`

**Auto-skipped directories:**
`node_modules`, `.git`, `vendor`, `__pycache__`, `.idea`, `.vscode`, `target`, `build`, `dist`, `.next`, `.nuxt`

---

## Vulnerability Databases

| Database | API Key Required | Rate Limit | Notes |
|----------|-----------------|------------|-------|
| **OSV.dev** | No | Unlimited | Primary source, batch API, always enabled |
| **NVD** | Optional | 5/30s (no key), 50/30s (with key) | Set `nvd-key` for better limits |
| **GitHub Advisory** | Optional | 60/hr (no token), 5000/hr (with token) | Set `github-token` for access |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully |
| `1` | Error occurred (bad path, parse failure, etc.) |
