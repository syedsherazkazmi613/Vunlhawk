# VulnHawk 🦅

A professional Linux CLI reconnaissance and vulnerability scanning framework written in Rust.

## Features
- **Orchestrated Scanning:** Combines 30+ industry-standard security tools.
- **Full Automated Pipeline:** Subdomains -> DNS -> Live Hosts -> Ports -> Services -> Vulns.
- **Smart Input Parsing:** Automatically handles domains, IPs, and URLs.
- **Reporting:** Generates Terminal tables, JSON, and Markdown reports.
- **Modular Design:** Easy to extend with new scanning modules.

## Installation

### 1. Prerequisites
Ensure you have **Rust** and **Cargo** installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. External Tools
VulnHawk relies on several external tools (nmap, nuclei, subfinder, etc.). Run the provided installation script:
```bash
chmod +x install_tools.sh
./install_tools.sh
```

### 3. Compile VulnHawk
```bash
cargo build --release
sudo cp target/release/vulnhawk /usr/local/bin/
```

## Usage

### Check Dependencies
```bash
vulnhawk doctor
```

### Full Automated Scan
```bash
vulnhawk scan example.com --full
```

### Individual Modules
```bash
vulnhawk subdomain example.com
vulnhawk port 1.1.1.1
vulnhawk vuln https://target.com
vulnhawk dir https://target.com
```

## Example Output
```text
┌─[ Subdomain Enumeration ]
│  [*] Running subfinder...
│  24 subdomains via subfinder
│  [*] Running findomain...
│  12 subdomains via findomain
└─[ ✓ Total unique subdomains: 32 ]

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
  [HIGH] Path Traversal (nuclei)
  [MEDIUM] XSS Found (dalfox)

[+] Report saved to vulnhawk_example_com.json and vulnhawk_example_com.md
```

## Project Structure
- `src/main.rs`: Entry point and banner.
- `src/cli.rs`: CLI argument parsing and handlers.
- `src/modules/`: Individual tool wrappers (14 modules).
- `src/core/`: Orchestration, parsing, and correlation logic.
- `src/output/`: Multi-format report generation.
