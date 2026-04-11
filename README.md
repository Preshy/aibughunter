# 🎯 AI Bug Hunter

**AI-Powered Automated Bug Hunting Platform with Qwen CLI Integration**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688.svg)](https://fastapi.tiangolo.com/)
[![CLI](https://img.shields.io/badge/CLI-Typer-0078D7.svg)](https://typer.tiangolo.com/)

Automated security scanning platform that leverages AI for intelligent vulnerability discovery, exploit development, and professional bug bounty report generation. Built on top of Qwen CLI with full Kali Linux tools integration.

## ✨ Features

### 🔍 Automated Target Discovery
- **Google Dork Finder** - 60+ pre-built dorks across 8 categories, powered by Qwen web search
- **Subdomain Enumeration** - Passive DNS and brute-force techniques
- **OSINT Gathering** - Open-source intelligence collection
- **Tech Stack Analysis** - Automatic framework and technology detection

### 🛡️ Comprehensive Scanning
- **Web Application Scanner** - XSS, SQLi, security headers, cookies, info disclosure
- **API Scanner** - REST and GraphQL security testing
- **Infrastructure Scanner** - Port scanning, service detection
- **Mobile Scanner** - APK/IPA analysis (stub)

### 🐉 Kali Linux Integration
- **40+ Security Tools** - Direct access to Kali's toolkit
- **Automated Installation** - One-command tool installation with graceful fallbacks
- **Unified CLI Interface** - Run any Kali tool from the CLI
- **Quick Scan Presets** - Pre-configured multi-tool scanning profiles

### 🤖 AI-Powered Analysis
- **Qwen CLI Integration** - Uses Qwen's built-in tools (`web_search`, `run_shell_command`, etc.)
- **Smart Recon** - AI analyzes scan data to identify attack vectors
- **Automated Planning** - AI creates prioritized attack plans
- **Vulnerability Discovery** - Suggests what to test next based on findings
- **Anti-Refusal System** - Engineered prompts for authorized security research

### 📊 Web Dashboard
- **Beautiful UI** - Dark theme with interactive charts
- **Real-time Stats** - Auto-refresh every 10 seconds
- **Finding Management** - Filter, triage, and update status
- **REST API** - Full programmatic access via `/api/*` endpoints
- **Daemon Mode** - Run as background service

### 📝 Professional Reporting
- **HTML Reports** - Beautiful, client-ready reports
- **Markdown Reports** - Bug bounty platform compatible
- **Auto-Generation** - Reports created automatically after scans
- **Folder Organization** - Each scan gets its own report folder
- **SQLite Database** - Persistent storage for all findings

### 🐍 Python API
```python
from aibughunter.api import BugHunter

async with BugHunter() as hunter:
    results = await hunter.hunt("https://target.com")
    findings = await hunter.scan_web("https://target.com")
    stats = hunter.get_stats()
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Preshy/aibughunter.git
cd aibughunter

# Install
pip install -e .
```

### Prerequisites

- **Python 3.10+**
- **Qwen CLI** - Already installed (uses the `qwen` command)
- **Kali Linux** - Optional, for full tool integration

### Verify Installation

```bash
aibughunter --version
aibughunter --help
```

## 📖 Usage

### 🎯 Full Automated Hunt

End-to-end bug hunting workflow:

```bash
# Start a full hunt on a target
aibughunter hunt https://target.com

# With custom options
aibughunter hunt https://target.com --depth aggressive --auto-exploit --report
```

### 🌐 Web Dashboard

```bash
# Start dashboard as daemon (background)
aibughunter web serve --daemon

# Open in browser
open http://127.0.0.1:8000

# Stop daemon
aibughunter web stop

# Check status
aibughunter web status
```

**Dashboard Features:**
- Real-time vulnerability statistics
- Interactive severity charts
- Filter findings by severity/status/target
- Update finding status (New → Triaged → Reported → Resolved)
- Recent scan history

### 🔍 Google Dork Finder

```bash
# Find exposed admin panels
aibughunter recon dork exposed_panels

# Find config files with credentials
aibughunter recon dork config_files -m 50

# Auto-find bug bounty targets
aibughunter recon dork --find-targets

# Search for specific domain
aibughunter recon dork subdomains -t example.com

# Add custom dork
aibughunter recon dork --add-custom "inurl:login site:example.com"

# List all categories
aibughunter recon dork --list
```

**Available Categories:**
| Category | Description | Dorks |
|----------|-------------|-------|
| `exposed_panels` | Admin dashboards, login pages | 10 |
| `config_files` | Environment files, configs with secrets | 10 |
| `sensitive_files` | Leaked documents, credentials | 10 |
| `vulnerable_apps` | WordPress, Joomla, Drupal installations | 10 |
| `cloud_storage` | Exposed S3 buckets, Google Cloud storage | 5 |
| `api_endpoints` | Public APIs, GraphQL, Swagger docs | 8 |
| `error_pages` | SQL errors, stack traces | 6 |
| `subdomains` | Subdomain enumeration | 1 |

### 🐉 Kali Linux Tools

```bash
# List all available tools
aibughunter kali list

# Show installed tools
aibughunter kali list --installed

# Search for tools
aibughunter kali search sql

# Get tool info
aibughunter kali info sqlmap

# Install a tool
aibughunter kali install nmap

# Run a tool
aibughunter kali run nmap -sV -sC target.com

# Quick scan with multiple tools
aibughunter kali quick-scan https://target.com --type standard

# View statistics
aibughunter kali stats
```

**Available Tools by Category:**
- **Reconnaissance**: nmap, masscan, amass, theharvester, sublist3r
- **Web Application**: sqlmap, nikto, wfuzz, gobuster, ffuf, wpscan, joomscan
- **Vulnerability Scanning**: nuclei, openvas, nessus
- **Exploitation**: metasploit, searchsploit, beef
- **Password Attacks**: john, hashcat, hydra, crunch, cewl
- **Sniffing**: wireshark, tcpdump, mitmproxy
- **Wireless**: aircrack-ng, wifite
- **Post Exploitation**: mimikatz, mimipenguin
- **Forensics**: autopsy, volatility

### 📡 Reconnaissance

```bash
# Subdomain enumeration
aibughunter recon subdomains example.com

# Technology stack analysis
aibughunter recon techstack https://target.com --detailed

# Endpoint discovery
aibughunter recon endpoints https://target.com --crawl --js

# OSINT gathering
aibughunter recon osint example.com --emails --leaks
```

### 🔬 Vulnerability Scanning

```bash
# Web application scan
aibughunter scan web https://target.com --depth aggressive

# API scanning
aibughunter scan api https://api.target.com/v1 --type rest
aibughunter scan api https://api.target.com/graphql --type graphql

# Infrastructure scanning
aibughunter scan infra target.com --ports top-1000

# Mobile app scanning
aibughunter scan mobile app.apk --platform android
```

### 📝 Report Generation

```bash
# Generate reports (auto-creates both Markdown + HTML)
aibughunter report generate

# List all findings
aibughunter report list-findings

# Generate POC for a vulnerability
aibughunter report poc VULN-001

# Export findings
aibughunter report export --format json --output findings.json
```

### 🎯 Target Management

```bash
# Add target to scope
aibughunter targets add example.com --program hackerone

# List targets
aibughunter targets list

# Import scope from file
aibughunter targets import-scope scope.json --program bugcrowd

# Export scope
aibughunter targets export-scope --output my-scope.json
```

### 🐍 Python API

```python
import asyncio
from aibughunter.api import BugHunter, hunt, scan, query

async def main():
    # Full hunt
    async with BugHunter() as hunter:
        results = await hunter.hunt("https://target.com")
        print(f"Found {results['total_findings']} vulnerabilities")
        
        if results['report_path']:
            print(f"Report: {results['report_path']}")
    
    # Quick scan
    findings = await scan("https://target.com", scan_type="web")
    
    # Query database
    high_vulns = query(severity="high")
    
    # Find targets
    async with BugHunter() as hunter:
        targets = await hunter.find_targets(max_results=50)
    
    # Reconnaissance
    async with BugHunter() as hunter:
        recon = await hunter.recon("https://target.com")
    
    # Generate report
    async with BugHunter() as hunter:
        report_path = await hunter.generate_report(scan_id="scan_123")

asyncio.run(main())
```

### 🌐 REST API

When the dashboard is running, access the API at `http://127.0.0.1:8000`:

```bash
# Get statistics
curl http://127.0.0.1:8000/api/stats

# Query findings
curl "http://127.0.0.1:8000/api/findings?severity=high"

# List scans
curl http://127.0.0.1:8000/api/scans

# Get specific scan
curl http://127.0.0.1:8000/api/scans/scan_123

# Update finding status
curl -X PUT "http://127.0.0.1:8000/api/findings/VULN-001/status?status=triaged"

# List targets
curl http://127.0.0.1:8000/api/targets
```

## 📁 Project Structure

```
aibughunter/
├── aibughunter/
│   ├── api/                 # 🐍 Python API module
│   │   └── __init__.py      # BugHunter class
│   ├── ai/                  # 🤖 AI integration
│   │   └── qwen_client.py   # Qwen CLI wrapper
│   ├── commands/            # 💻 CLI commands
│   │   ├── scan.py          # Scanning commands
│   │   ├── recon.py         # Reconnaissance + Dorks
│   │   ├── kali.py          # Kali Linux tools
│   │   ├── web.py           # 🌐 Web dashboard
│   │   ├── report.py        # Report generation
│   │   ├── config.py        # Configuration
│   │   └── targets.py       # Target management
│   ├── core/                # ⚙️ Core functionality
│   │   ├── orchestrator.py  # Main hunt coordinator
│   │   ├── database.py      # 💾 SQLite database
│   │   ├── scope.py         # Scope management
│   │   └── dashboard.py     # Terminal dashboard
│   ├── scanners/            # 🔍 Scanning modules
│   │   ├── recon_scanner.py # Reconnaissance
│   │   ├── dork_finder.py   # Google Dork finder
│   │   ├── web_scanner.py   # Web vulnerabilities
│   │   ├── api_scanner.py   # API security
│   │   ├── infra_scanner.py # Infrastructure
│   │   └── exploit_module.py# Exploitation testing
│   ├── tools/               # 🛠️ Tool management
│   │   ├── kali_tools.py    # Kali Linux integration
│   │   ├── manager.py       # General tools
│   │   └── creator.py       # AI tool creator
│   ├── reports/             # 📝 Report generation
│   │   ├── generator.py     # Report templates
│   │   ├── html_template.py # HTML report template
│   │   ├── poc_generator.py # POC generation
│   │   └── exporter.py      # Export findings
│   └── web/                 # 🌐 Web dashboard
│       ├── api.py           # FastAPI application
│       └── dashboard.html   # Dashboard UI
├── tests/                   # 🧪 Test suite
├── examples/                # 📖 Usage examples
├── data/                    # 💾 SQLite database
└── reports/                 # 📊 Generated reports
```

## 🔧 Configuration

### Environment Variables

```bash
# .env file
AIBH_QWEN_MODEL=coder-model
AIBH_SCAN_RATE_LIMIT=0.1
AIBH_SCAN_MAX_CONCURRENT=5
```

### CLI Configuration

```bash
# Show current config
aibughunter config show

# Set configuration
aibughunter config set qwen-model coder-model
aibughunter config set scan-rate-limit 0.5

# Validate configuration
aibughunter config validate
```

### Database

All findings are stored in SQLite at `data/aibughunter.db`:

```sql
-- Tables:
-- scans      - Scan history with duration and status
-- findings   - All vulnerabilities (queryable, filterable)
-- targets    - Target scope management
-- programs   - Bug bounty programs
-- tool_usage - Tool execution history
```

## 🎓 Examples

### Example 1: Find Bug Bounty Targets

```bash
# Discover vulnerable targets automatically
aibughunter recon dork --find-targets

# Filter for high-severity results
# (Results are sorted by severity automatically)

# Add promising targets to scope
aibughunter targets add target.com --program hackerone
```

### Example 2: Automated Web App Testing

```bash
# Full workflow
aibughunter hunt https://webapp.com

# Or step-by-step
aibughunter recon subdomains webapp.com
aibughunter recon techstack https://webapp.com
aibughunter scan web https://webapp.com --depth aggressive
```

### Example 3: Python Script

```python
# examples/api_usage.py
import asyncio
from aibughunter.api import BugHunter

async def bug_hunt():
    targets = ["https://target1.com", "https://target2.com"]
    
    async with BugHunter(output_dir="./my-reports") as hunter:
        for target in targets:
            print(f"\nHunting {target}...")
            
            # Reconnaissance
            recon = await hunter.recon(target)
            print(f"  Found {len(recon['endpoints'])} endpoints")
            
            # Web scanning
            findings = await hunter.scan_web(target, depth="standard")
            print(f"  Found {len(findings)} vulnerabilities")
            
            # Generate report
            if findings:
                report = await hunter.generate_report()
                print(f"  Report: {report}")

asyncio.run(bug_hunt())
```

### Example 4: Using Kali Tools

```bash
# Quick reconnaissance
aibughunter kali run nmap -sV -sC -O example.com

# Web application testing
aibughunter kali run sqlmap -u "https://example.com/page?id=1" --batch --dbs

# Directory enumeration
aibughunter kali run ffuf -u https://example.com/FUZZ -w wordlist.txt -mc 200,301,302
```

## 🧪 Testing

```bash
# Run all tests
python run_tests.py

# Or directly
pytest tests/ -v

# Run specific test file
pytest tests/test_qwen_client.py -v
```

**Test Coverage:**
- ✅ Qwen CLI client integration
- ✅ Configuration management
- ✅ Google Dork finder
- ✅ Scope management
- ✅ Tools management
- ✅ Report generation & POC
- ✅ Finding storage & export

## 🛣️ Roadmap

- [x] Core CLI framework
- [x] Qwen CLI integration (subprocess)
- [x] Google Dork finder
- [x] Kali Linux tools integration
- [x] Web application scanner
- [x] API scanner
- [x] SQLite database
- [x] Web dashboard with FastAPI
- [x] Python API module
- [x] HTML report generation
- [ ] Mobile app scanner (full implementation)
- [ ] Automated exploit development
- [ ] CI/CD integration
- [ ] Burp Suite extension
- [ ] Team collaboration features
- [ ] Vulnerability database
- [ ] Integration with bug bounty platforms (HackerOne, Bugcrowd APIs)

## ⚠️ Safety & Ethics

**IMPORTANT**: This tool is for **authorized security testing only**.

- ✅ Only test targets you own or have explicit permission to test
- ✅ Respect scope and rules of engagement
- ✅ Follow responsible disclosure practices
- ✅ Comply with applicable laws and regulations
- ✅ Bug bounty programs require following their specific rules

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## 📞 Support

- 📖 Documentation: This README
- 🐛 Bug Reports: [GitHub Issues](https://github.com/Preshy/aibughunter/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/Preshy/aibughunter/discussions)

## ⭐ Acknowledgments

- [Qwen CLI](https://github.com/QwenLM/qwen) - AI foundation
- [Kali Linux](https://www.kali.org/) - Security tools
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
- [Typer](https://typer.tiangolo.com/) - CLI framework

---

**Built with ❤️ for the bug bounty community**

*"The best way to find bugs is to automate the hunt."*
