# Quick Start Guide

## 5-Minute Setup

### 1. Install
```bash
pip install -e .
```

### 2. Configure AI (Optional but Recommended)
```bash
# If you have Qwen API running locally:
aibughunter config set qwen-api-url http://localhost:8080

# Or use Ollama (free):
# ollama pull qwen2.5-coder:32b
# ollama serve
aibughunter config set qwen-api-url http://localhost:11434
```

### 3. Find Targets
```bash
# Discover vulnerable targets automatically
aibughunter recon dork --find-targets
```

### 4. Hunt Bugs
```bash
# Start automated hunt on a target
aibughunter hunt https://target.com
```

### 5. Generate Report
```bash
# Create professional bug bounty report
aibughunter report generate
```

---

## Common Workflows

### Web Application Testing
```bash
# Full automated scan
aibughunter scan web https://example.com --depth aggressive

# With Kali tools
aibughunter kali run nmap -sV -sC example.com
aibughunter kali run nikto -h https://example.com
```

### API Security Testing
```bash
# REST API
aibughunter scan api https://api.example.com/v1 --type rest

# GraphQL
aibughunter scan api https://api.example.com/graphql --type graphql
```

### Reconnaissance
```bash
# Find subdomains
aibughunter recon subdomains example.com

# Analyze tech stack
aibughunter recon techstack https://example.com --detailed

# Discover endpoints
aibughunter recon endpoints https://example.com --crawl
```

### Using Kali Tools
```bash
# List available tools
aibughunter kali list --installed

# Search for specific tool
aibughunter kali search sql

# Install and run
aibughunter kali install sqlmap
aibughunter kali run sqlmap -u "https://example.com/page?id=1" --batch
```

---

## Tips for Bug Bounty Hunting

1. **Start Broad**: Use `--find-targets` to discover potential targets
2. **Scope First**: Add targets to scope before hunting
3. **Depth Matters**: Use `--depth aggressive` for thorough testing
4. **Check Reports**: Review generated reports before submitting
5. **Combine Tools**: Use both AI scanning and Kali tools together
6. **Stay Legal**: Only test targets you're authorized to test

---

## Next Steps

- Read the full README.md for comprehensive documentation
- Explore all commands with `aibughunter --help`
- Check individual command help: `aibughunter hunt --help`
- Configure advanced settings: `aibughunter config --help`
