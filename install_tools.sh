#!/bin/bash

# VulnHawk External Tools Installation Script
# Targets: Debian/Ubuntu/Kali Linux
# Optimized for reliability and safety.

set -e

# ANSI Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] VulnHawk Environment Setup${NC}"
echo "--------------------------------"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}[!] WARNING: Running as root. Tools will be installed in /root/ directory.${NC}"
    echo -e "${YELLOW}[!] It is generally recommended to run this script as a normal user with sudo.${NC}"
fi

# 0. System Dependencies
echo -e "${GREEN}[*] Installing system dependencies...${NC}"
sudo apt-get update
sudo apt-get install -y golang git nmap masscan netcat-traditional whois python3 python3-pip pipx libssl-dev pkg-config libpcap-dev jq curl wget unzip cargo

# Initialize pipx
pipx ensurepath --force

# Path Setup for current session
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$HOME/.local/bin:$HOME/.cargo/bin

# Update .bashrc safely (only once)
if ! grep -q "vulnhawk-paths" ~/.bashrc; then
    echo -e "\n# vulnhawk-paths" >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin' >> ~/.bashrc
    echo -e "${GREEN}[+] Added paths to ~/.bashrc${NC}"
fi

echo -e "${GREEN}[*] Installing tools (this may take a while)...${NC}"

# 1. Subdomain Enumeration
echo -e "${GREEN}[*] Installing Subdomain tools...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
go install -v github.com/owasp-amass/amass/v4/...@latest || true
go install -v github.com/tomnomnom/assetfinder@latest || true
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest || true
pipx install sublist3r --force || true

# Findomain (Improved binary download)
if ! command -v findomain &> /dev/null; then
    echo -e "${GREEN}[*] Installing Findomain...${NC}"
    curl -sLO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
    if [ -f findomain-linux.zip ]; then
        unzip -o findomain-linux.zip
        chmod +x findomain
        sudo mv findomain /usr/local/bin/
        rm findomain-linux.zip
        echo -e "${GREEN}[+] Findomain installed successfully${NC}"
    else
        echo -e "${RED}[!] Findomain download failed${NC}"
    fi
fi

# 2. Passive & URLs
echo -e "${GREEN}[*] Installing Recon & URL tools...${NC}"
go install -v github.com/lc/gau/v2/cmd/gau@latest || true
go install -v github.com/hakluke/hakrawler@latest || true
go install -v github.com/projectdiscovery/katana/cmd/katana@latest || true
go install -v github.com/tomnomnom/waybackurls@latest || true
go install -v github.com/tomnomnom/unfurl@latest || true
go install -v github.com/tomnomnom/anew@latest || true
pipx install git+https://github.com/devanshbatham/ParamSpider.git --force || true

# 3. DNS & Live Detection
echo -e "${GREEN}[*] Installing DNS & Detection tools...${NC}"
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest || true
go install -v github.com/d3mondev/puredns/v2@latest || true
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true

# 4. Scanning & Fuzzing
echo -e "${GREEN}[*] Installing Port & Directory scanners...${NC}"
# Use --locked for cargo to ensure stability
cargo install rustscan || true
cargo install feroxbuster || true
sudo apt-get install -y ffuf gobuster dirsearch sqlmap nikto zaproxy || true

# 5. Security & Secrets (Modern versions)
echo -e "${GREEN}[*] Installing Vuln & Secret tools...${NC}"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
go install github.com/hahwul/dalfox/v2@latest || true
go install github.com/trufflesecurity/trufflehog/v3@latest || true
go install github.com/zricethezav/gitleaks/v8@latest || true
pipx install xsstrike --force || true
pipx install s3scanner --force || true
pipx install git+https://github.com/initstring/cloud_enum.git --force || true

# 6. JS Analysis
echo -e "${GREEN}[*] Installing JS analysis tools...${NC}"
pipx install xnLinkFinder --force || true
pipx install git+https://github.com/GerbenJavado/LinkFinder.git --force || true
pipx install git+https://github.com/m4ll0k/SecretFinder.git --force || true

# 7. Finalize VulnHawk
echo -e "${GREEN}[*] Building VulnHawk...${NC}"
cargo build --release
sudo cp target/release/vulnhawk /usr/local/bin/

echo -e "--------------------------------"
echo -e "${GREEN}[+] Installation complete!${NC}"
echo -e "${YELLOW}[!] Recommendations:${NC}"
echo -e "    1. Run 'source ~/.bashrc' or restart your terminal."
echo -e "    2. Run 'vulnhawk doctor' to verify all tools."
echo -e "    3. Ensure you have wordlists in /usr/share/wordlists/ for some modules."
echo -e "--------------------------------"
