# security-scanner

An open-source, AI-powered vulnerability scanner CLI for **Go**, **Java**, **Python**, and **Node.js** projects.

## Features

- **Dependency Scanning** — checks your lock files against multiple CVE databases:
  - [OSV.dev](https://osv.dev) (primary, batch API, no rate limits)
  - [NVD](https://nvd.nist.gov/) (NIST National Vulnerability Database)
  - [GitHub Advisory Database](https://github.com/advisories)

- **AI-Powered Code Analysis** — uses OpenAI GPT-4 to detect OWASP Top 10 vulnerabilities:
  - SQL Injection, Command Injection, XSS
  - Hardcoded secrets & API keys
  - Insecure cryptography, TLS misconfigurations
  - Path traversal, insecure deserialization
  - CORS misconfiguration, and more

- **SAST Engine — Semgrep CE Integration** with custom rule packs:
  - 30 bundled security rules covering OWASP Top 10 + language-specific patterns
  - Custom rule packs for Go, Python, Java, and JavaScript/TypeScript
  - Bring your own rules with `--semgrep-rules`

- **Standards Compliance**:
  - **PURL** (Package URL) — standard package identifiers (`pkg:npm/@babel/core@7.0.0`)
  - **CycloneDX v1.5** — SBOM/VDR format with components, vulnerabilities, and PURLs
  - **OpenVEX v0.2.0** — Vulnerability Exploitability Exchange with status and justification

- **Multi-Ecosystem Support** (grouped output with ecosystem icons):
  - **Go** 🐹: `go.mod`
  - **Java** ☕: `pom.xml`, `build.gradle`, `build.gradle.kts`
  - **Python** 🐍: `requirements.txt`, `Pipfile.lock`, `poetry.lock`
  - **Node.js** 📗: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`

- **Multiple Output Formats**: Terminal table, JSON, SARIF v2.1.0, CycloneDX v1.5, OpenVEX v0.2.0

## Installation

### From Source

```bash
git clone https://github.com/security-scanner/security-scanner.git
cd security-scanner
make build
```

The binary will be at `./bin/security-scanner`.

### Go Install

```bash
go install github.com/security-scanner/security-scanner@latest
```

## Quick Start

```bash
# Scan current directory (dependency scan only — no API key needed)
security-scanner scan --skip-ai

# Scan a specific project
security-scanner scan /path/to/project

# Full scan with AI analysis (requires OpenAI API key)
security-scanner config set openai-key sk-...
security-scanner scan

# Output as JSON
security-scanner scan --format json

# Output as SARIF (for GitHub Code Scanning, VS Code, etc.)
security-scanner scan --format sarif --output results.sarif

# Output as CycloneDX SBOM
security-scanner scan --format cyclonedx --output sbom.json

# Output as OpenVEX
security-scanner scan --format openvex --output vex.json

# Run with custom Semgrep rules
security-scanner scan --semgrep-rules ./my-rules/

# Skip Semgrep SAST analysis
security-scanner scan --skip-semgrep

# Only show high and critical vulnerabilities
security-scanner scan --severity high

# Verbose output
security-scanner scan -v
```

## Configuration

Configuration is stored in `~/.security-scanner.json`. Environment variables take precedence.

### API Keys

```bash
# OpenAI (required for AI code analysis)
security-scanner config set openai-key sk-...
# or: export OPENAI_API_KEY=sk-...

# OpenAI model (default: gpt-4)
security-scanner config set openai-model gpt-4-turbo

# NVD API key (optional, increases rate limits)
security-scanner config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# or: export NVD_API_KEY=...

# GitHub token (optional, for GitHub Advisory Database)
security-scanner config set github-token ghp_...
# or: export GITHUB_TOKEN=...
```

### View Configuration

```bash
security-scanner config get openai-model
```

## CLI Reference

```
security-scanner [command]

Available Commands:
  scan        Scan a project for security vulnerabilities
  config      Manage scanner configuration
  version     Print the version
  help        Help about any command

Scan Flags:
  -f, --format string         Output format: table, json, sarif, cyclonedx, openvex (default "table")
  -o, --output string         Write output to file (default: stdout)
  -s, --severity string       Minimum severity: critical, high, medium, low
      --skip-ai               Skip AI-powered code analysis
      --skip-deps             Skip dependency vulnerability scanning
      --skip-semgrep          Skip Semgrep SAST analysis
      --semgrep-rules string  Path to custom Semgrep rule directory
  -v, --verbose               Enable verbose output
```

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐     ┌──────────────┐
│  Detect     │────▶│  Parse &     │────▶│  Match        │────▶│  AI Enrich   │────▶│  Report      │
│  Ecosystems │     │  PURL Gen    │     │  Against CVEs │     │  & Analyze   │     │  Results     │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────────┘     └──────────────┘
                                                │                      │
                    ┌──────────────┐             │       ┌──────────────┐
                    │  AI Code     │─────────────┘       │  Semgrep CE  │
                    │  Analysis    │                     │  SAST Engine │
                    └──────────────┘                     └──────────────┘
```

1. **Detect**: Walks the project directory to find dependency manifest files (go.mod, pom.xml, package-lock.json, etc.)
2. **Parse & PURL**: Extracts package names and versions, generates Package URLs (PURLs) per the [PURL spec](https://github.com/package-url/purl-spec)
3. **Match**: Queries OSV, NVD, and GitHub Advisory databases for known CVEs
4. **Analyze**: Runs regex pattern matching + OpenAI GPT-4 analysis on source code
5. **Semgrep SAST**: Runs Semgrep CE with bundled or custom rule packs for static analysis
6. **Enrich**: AI enrichment layer adds impact, confidence, remediation, and suppression rationale
7. **Report**: Outputs results in the requested format (table, JSON, SARIF, CycloneDX, or OpenVEX)

## Supported Vulnerability Patterns (Code Analysis)

| ID | Pattern | Severity |
|----|---------|----------|
| SEC-001 | SQL Injection (format strings) | HIGH |
| SEC-002 | SQL Injection (string concat) | HIGH |
| SEC-003 | Command Injection | CRITICAL |
| SEC-004 | Path Traversal | HIGH |
| SEC-005 | Hardcoded Secrets | HIGH |
| SEC-006 | AWS Access Keys | CRITICAL |
| SEC-007 | Weak Crypto (MD5/SHA1) | MEDIUM |
| SEC-008 | Cross-Site Scripting (XSS) | HIGH |
| SEC-009 | Insecure HTTP | LOW |
| SEC-010 | TLS Verification Disabled | CRITICAL |
| SEC-011 | Insecure Deserialization | HIGH |
| SEC-012 | Permissive CORS | MEDIUM |

## Semgrep CE Integration

The scanner integrates with [Semgrep CE](https://semgrep.dev/) for static application security testing. Install Semgrep and the scanner will automatically use it:

```bash
pip install semgrep

# Scan with bundled rule packs (OWASP Top 10 + language-specific)
security-scanner scan /path/to/project

# Scan with your own custom rules
security-scanner scan --semgrep-rules ./my-rules/ /path/to/project

# Skip Semgrep entirely
security-scanner scan --skip-semgrep /path/to/project
```

**Bundled rule packs** (in `rules/semgrep/`):
- `owasp-top10.yaml` — 18 rules: SQL injection, command injection, path traversal, hardcoded secrets, insecure TLS, weak crypto, XSS, insecure deserialization, SSRF
- `language-specific.yaml` — 12 rules: Go (unsafe pointer, HTTP no timeout, defer in loop), Python (Flask debug, bind 0.0.0.0), JS (eval, CORS wildcard, JWT no verify), Java (XXE, ECB mode)

## Standards & Output Formats

| Format | Flag | Spec | Use Case |
|--------|------|------|----------|
| Table | `--format table` | — | Human-readable terminal output (grouped by ecosystem) |
| JSON | `--format json` | — | Machine-readable, CI/CD pipelines, scripting |
| SARIF | `--format sarif` | v2.1.0 | GitHub Code Scanning, VS Code, IDE integrations |
| CycloneDX | `--format cyclonedx` | v1.5 | SBOM/VDR with components, PURLs, and vulnerabilities |
| OpenVEX | `--format openvex` | v0.2.0 | Vulnerability exploitability exchange with status/justification |

### PURL (Package URL)

All packages are identified using [PURL](https://github.com/package-url/purl-spec) standard identifiers:

| Ecosystem | Example PURL |
|-----------|-------------|
| Go | `pkg:golang/github.com/hashicorp/vault@v1.15.2` |
| npm | `pkg:npm/@babel/helpers@7.15.4` |
| PyPI | `pkg:pypi/requests@2.28.0` |
| Maven | `pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0` |

## License

Apache License 2.0 — see [LICENSE](LICENSE)
