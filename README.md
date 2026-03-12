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

- **Multi-Ecosystem Support**:
  - **Go**: `go.mod`
  - **Java**: `pom.xml`, `build.gradle`, `build.gradle.kts`
  - **Python**: `requirements.txt`, `Pipfile.lock`, `poetry.lock`
  - **Node.js**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`

- **Multiple Output Formats**: Terminal table, JSON, SARIF v2.1.0

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
  -f, --format string     Output format: table, json, sarif (default "table")
  -o, --output string     Write output to file (default: stdout)
  -s, --severity string   Minimum severity: critical, high, medium, low
      --skip-ai           Skip AI-powered code analysis
      --skip-deps         Skip dependency vulnerability scanning
  -v, --verbose           Enable verbose output
```

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│  Detect     │────▶│  Parse       │────▶│  Match        │────▶│  Report      │
│  Ecosystems │     │  Dependencies│     │  Against CVEs │     │  Results     │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────────┘
                                                │
                    ┌──────────────┐             │
                    │  AI Code     │─────────────┘
                    │  Analysis    │
                    └──────────────┘
```

1. **Detect**: Walks the project directory to find dependency manifest files (go.mod, pom.xml, package-lock.json, etc.)
2. **Parse**: Extracts package names and versions from each manifest file
3. **Match**: Queries OSV, NVD, and GitHub Advisory databases for known CVEs
4. **Analyze**: Runs regex pattern matching + OpenAI GPT-4 analysis on source code
5. **Report**: Outputs results in the requested format (table, JSON, or SARIF)

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

## License

Apache License 2.0 — see [LICENSE](LICENSE)
