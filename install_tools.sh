#!/bin/bash

# VulnHawk External Tools Installation Script
# Targets: Debian/Ubuntu/Kali Linux

echo "[*] Installing VulnHawk dependencies..."

# Update and install basic tools
sudo apt-get update
sudo apt-get install -y golang git nmap masscan netcat-traditional whois python3 python3-pip pipx libssl-dev pkg-config libpcap-dev jq curl wget unzip

# Initialize pipx paths
pipx ensurepath

# Set up Go path if not set
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$HOME/.local/bin
echo 'export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin' >> ~/.bashrc

# 1. Subdomain Enumeration
echo "[*] Installing Subdomain tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
# Findomain (binary)
curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain-linux.zip

# 2. Passive & URLs
echo "[*] Installing Passive & URL discovery tools..."
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/anew@latest
pipx install git+https://github.com/devanshbatham/ParamSpider

# 3. DNS
echo "[*] Installing DNS tools..."
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# 4. Live Detection
echo "[*] Installing Live Detection tools..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# 5. Port Scanning
# RustScan (cargo)
cargo install rustscan

# 6. Directory Discovery
echo "[*] Installing Directory Discovery tools..."
cargo install feroxbuster
sudo apt-get install -y ffuf gobuster dirsearch

# 7. Vulnerability Scanning
echo "[*] Installing Vulnerability Scanning tools..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
pipx install xsstrike
sudo apt-get install -y sqlmap nikto zaproxy

# 8. Cloud & Secrets
echo "[*] Installing Cloud & Secrets tools..."
pipx install s3scanner
pipx install trufflehog
pipx install gitleaks
pipx install git+https://github.com/initstring/cloud_enum.git

# 9. JS Analysis
echo "[*] Installing JS Analysis tools..."
pipx install xnLinkFinder
go install -v github.com/0x240x23/js-recon@latest

# 10. Install VulnHawk itself
echo "[*] Building and installing VulnHawk..."
cargo build --release
if [ $? -eq 0 ]; then
    sudo cp target/release/vulnhawk /usr/local/bin/
    echo "[+] VulnHawk binary installed to /usr/local/bin/vulnhawk"
else
    echo "[!] VulnHawk build failed. Please check the errors above."
fi

echo "[+] Installation complete. You can now run 'vulnhawk --help' from anywhere."
echo "[!] Please restart your terminal or run 'source ~/.bashrc' if you haven't already."
