# VulnHawk 🦅

A professional, high-performance Linux CLI reconnaissance and vulnerability scanning framework written in Rust. Designed for bug bounty hunters and penetration testers who need a state-of-the-art **2026 Modern Tool Stack**.

## 🚀 2026 Modern Tool Stack
VulnHawk orchestrates the best-in-class tools for every stage of the pipeline:

- **Subdomain Enum**: `subfinder`, `amass`, `findomain`, `assetfinder`, `chaos`
- **DNS Analysis**: `dnsx`, `shuffledns`, `puredns`, `dnsrecon`
- **Live Host Detection**: `httpx`, `naabu`
- **Port Scanning**: `rustscan`, `nmap`, `masscan`
- **Vulnerability Scanning**: `nuclei`, `nikto`, `zap`, `sqlmap`, `dalfox`, `xsstrike`
- **URL & Parameter Discovery**: `katana`, `hakrawler`, `gau`, `waybackurls`, `paramspider`
- **Directory Fuzzing**: `ffuf`, `feroxbuster`, `dirsearch`, `gobuster`
- **JS Analysis**: `linkfinder`, `xnLinkFinder`, `secretfinder`
- **Cloud & Secrets**: `cloud_enum`, `s3scanner`, `trufflehog`, `gitleaks`

## 🛠️ Installation

### 1. Prerequisites
Ensure you have **Rust** and **Cargo** installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Quick Setup
Install VulnHawk and all 35+ external dependencies automatically:
```bash
git clone https://github.com/USER/vulnhawk.git
cd vulnhawk
cargo build --release
sudo cp target/release/vulnhawk /usr/local/bin/

# Install the environment (Requires Debian/Ubuntu/Kali)
vulnhawk setup
```

## 📖 Usage

### Interactive Wizard (Recommended)
Simply type `vulnhawk` to enter the guided interactive menu:
```bash
vulnhawk
```

### Check Tool Status
```bash
vulnhawk doctor
```

### Automated Full Scan
```bash
vulnhawk scan example.com --full
```

### Selective Module Scanning
```bash
vulnhawk vuln https://target.com
vulnhawk subdomain example.com
vulnhawk port 1.1.1.1
```

## 📊 Example Output
```text
┌─[ Subdomain Enumeration ]
│  [*] Running subfinder...
│  24 subdomains via subfinder
│  [*] Running amass (passive)...
│  18 subdomains via amass
│  [*] Running assetfinder...
│  12 subdomains via assetfinder
└─[ ✓ Total unique subdomains: 54 ]

... [Pipeline continues] ...

────────────────────────────────────────────────────────────────────────────────
SCAN SUMMARY FOR: example.com
Duration: 4m 12s
────────────────────────────────────────────────────────────────────────────────
+-----------------+-------+----------+
| Category        | Count | Severity |
+=================+=======+==========+
| SubdomainsFound | 72    | Low      |
| Live Hosts      | 12    | -        |
| Vulnerabilities | 3     | CRITICAL |
+-----------------+-------+----------+

TOP VULNERABILITIES
  [CRITICAL] SQL Injection (sqlmap)
  [HIGH] Missing Header (nuclei)
  [MEDIUM] XSS Found (dalfox)

[+] Reports saved to vulnhawk_example_com.json, .md, and .html
```

## 🏗️ Project Structure
- `src/main.rs`: Entry point and brand new v1.1 Hawk banner.
- `src/cli.rs`: CLI argument parsing, interactive wizard, and `setup` handler.
- `src/modules/`: Individual tool wrappers (15+ core modules).
- `src/core/`: Orchestration, deduplication, and correlation logic.
- `src/output/`: Multi-format report generation (HTML, JSON, Markdown, Terminal).

## ⚖️ License & Disclaimer
This tool is for educational and professional security testing only. Always obtain permission before scanning a target.
