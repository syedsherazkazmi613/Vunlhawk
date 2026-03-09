// ============================================================
// cli.rs — Clap CLI definitions and top-level command handlers
// ============================================================

use clap::{Parser, Subcommand};
use colored::*;
use std::time::Instant;

use crate::core::runner::ScanRunner;
use crate::core::correlation::correlate_results;
use crate::core::parser::TargetInfo;
use crate::output::terminal::print_final_report;
use crate::output::json::save_json_report;
use crate::output::markdown::save_markdown_report;
use crate::output::html::save_html_report;
use crate::modules::{
    subdomain, passive, dns, ports, directory, vuln,
};
use inquire::{Select, Text, Confirm, MultiSelect};
use std::collections::HashMap;

// ─── Clap structs ────────────────────────────────────────────

/// VulnHawk — Reconnaissance & Vulnerability Scanning Framework
#[derive(Parser, Debug)]
#[command(
    name = "vulnhawk",
    author = "VulnHawk Team",
    version = "1.0.0",
    about = "Professional recon & vuln scanning framework",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a full or selective scan against a target
    Scan {
        /// Target: domain, IP, or URL
        target: String,

        /// Run full automated pipeline
        #[arg(long, default_value_t = false)]
        full: bool,

        /// Comma-separated module list (e.g. subdomain,ports,vuln)
        #[arg(long, value_delimiter = ',')]
        modules: Option<Vec<String>>,
    },

    /// Subdomain enumeration only
    Subdomain {
        /// Domain to enumerate subdomains for
        target: String,
    },

    /// Port scanning only
    Port {
        /// IP or domain to port-scan
        target: String,
    },

    /// Directory/path discovery only
    Dir {
        /// URL to fuzz directories on
        target: String,
    },

    /// Vulnerability scanning only
    Vuln {
        /// URL or domain to scan for vulnerabilities
        target: String,
    },

    /// DNS enumeration only
    Dns {
        /// Domain to enumerate DNS records for
        target: String,
    },

    /// Check that all required external tools are installed
    Doctor,

    /// Install all required external tools (Debian/Ubuntu/Kali)
    Setup,
}

// ─── Handler functions ────────────────────────────────────────

/// Full or selective scan handler
pub async fn handle_scan(
    target: &str,
    full: bool,
    modules: Option<Vec<String>>,
) -> anyhow::Result<()> {
    // If modules were provided via CLI, convert them to the new internal filter format
    let filter = if let Some(m_list) = modules {
        let mut map = HashMap::new();
        for m in m_list {
            // Map CLI names to internal module names and their default tools
            match m.to_lowercase().as_str() {
                "subdomain" => { map.insert("Subdomain".to_string(), vec!["subfinder".to_string(), "findomain".to_string(), "amass".to_string(), "assetfinder".to_string(), "chaos".to_string()]); },
                "passive" => { map.insert("Passive".to_string(), vec!["crt.sh".to_string(), "certspotter".to_string(), "gau".to_string()]); },
                "dns" => { map.insert("DNS".to_string(), vec!["dnsrecon".to_string(), "shuffledns".to_string(), "dnsx".to_string(), "puredns".to_string()]); },
                "ports" => { map.insert("Ports".to_string(), vec!["masscan".to_string(), "rustscan".to_string(), "nmap".to_string()]); },
                "vuln" => { map.insert("Vuln".to_string(), vec!["nuclei".to_string(), "nikto".to_string(), "zap".to_string(), "sqlmap".to_string(), "dalfox".to_string(), "xsstrike".to_string()]); },
                "dir" | "directory" => { map.insert("DirectoryDiscovery".to_string(), vec!["feroxbuster".to_string(), "ffuf".to_string(), "dirsearch".to_string()]); },
                _ => {}
            }
        }
        Some(map)
    } else if full {
        None // Full scan = no filter
    } else {
        None // Should not happen based on CLI logic but for safety
    };

    execute_scan(target, filter).await
}

/// The actual execution logic for a scan
pub async fn execute_scan(target: &str, filter: Option<HashMap<String, Vec<String>>>) -> anyhow::Result<()> {
    let start = Instant::now();

    println!("{} {} {}", "[*]".cyan().bold(), "Starting scan on target:".white(), target.yellow().bold());
    
    let runner = ScanRunner::new(target).await?;
    let results = runner.run(true, filter).await?;

    let correlated = correlate_results(&results);
    let elapsed = start.elapsed();

    // Print terminal summary
    print_final_report(&correlated, target, elapsed);

    // Save JSON, Markdown, and HTML reports
    save_json_report(&correlated, target)?;
    save_markdown_report(&correlated, target)?;
    save_html_report(&correlated, target)?;

    Ok(())
}

/// Subdomain-only scan
pub async fn handle_subdomain(target: &str) -> anyhow::Result<()> {
    println!("{} {}", "[*]".cyan().bold(), format!("Subdomain enumeration → {}", target).white());
    let target_info = TargetInfo::detect(target).await?;
    let subs = subdomain::run(&target_info, None).await?;
    let passive_subs = passive::run(&target_info, None).await?;

    let mut all: Vec<String> = subs.into_iter().chain(passive_subs).collect();
    all.sort();
    all.dedup();

    println!("\n{} {}:", "[+]".green().bold(), "Discovered subdomains".white().bold());
    for s in &all {
        println!("    {}", s.bright_green());
    }
    println!("\n{} {} subdomains found", "[+]".green().bold(), all.len().to_string().yellow().bold());
    Ok(())
}

/// Port-only scan
pub async fn handle_port(target: &str) -> anyhow::Result<()> {
    println!("{} {}", "[*]".cyan().bold(), format!("Port scan → {}", target).white());
    let target_info = TargetInfo::detect(target).await?;
    let open_ports = ports::run(&target_info, None).await?;

    println!("\n{} {}:", "[+]".green().bold(), "Open ports".white().bold());
    for p in &open_ports {
        println!("    {}", p.to_string().bright_green());
    }
    Ok(())
}

/// Directory-only scan
pub async fn handle_dir(target: &str) -> anyhow::Result<()> {
    println!("{} {}", "[*]".cyan().bold(), format!("Directory discovery → {}", target).white());
    let target_info = TargetInfo::detect(target).await?;
    let dirs = directory::run(&target_info, None).await?;

    println!("\n{} {}:", "[+]".green().bold(), "Discovered paths".white().bold());
    for d in &dirs {
        println!("    {}", d.bright_green());
    }
    Ok(())
}

/// Vulnerability-only scan
pub async fn handle_vuln(target: &str) -> anyhow::Result<()> {
    println!("{} {}", "[*]".cyan().bold(), format!("Vulnerability scan → {}", target).white());
    let target_info = TargetInfo::detect(target).await?;
    let vulns = vuln::run(&target_info, None).await?;

    println!("\n{} {}:", "[+]".green().bold(), "Vulnerabilities".white().bold());
    for v in &vulns {
        println!("    {} [{}] {}",
            "•".red(),
            v.severity.to_uppercase().red().bold(),
            v.description.white()
        );
    }
    Ok(())
}

/// DNS-only enumeration
pub async fn handle_dns(target: &str) -> anyhow::Result<()> {
    println!("{} {}", "[*]".cyan().bold(), format!("DNS enumeration → {}", target).white());
    let target_info = TargetInfo::detect(target).await?;
    let records = dns::run(&target_info, None).await?;

    println!("\n{} {}:", "[+]".green().bold(), "DNS Records".white().bold());
    for r in &records {
        println!("    {} → {}", r.record_type.yellow(), r.value.bright_white());
    }
    Ok(())
}

/// Doctor — checks all required external tools
pub async fn handle_doctor() -> anyhow::Result<()> {
    use comfy_table::{Table, ContentArrangement, Color, Cell, Attribute};
    use std::process::Command;

    println!("{} {}\n", "[*]".cyan().bold(), "Checking required external tools...".white().bold());

    let tools = vec![
        // Subdomain enumeration
        ("subfinder", "Subdomain Enumeration"),
        ("findomain", "Subdomain Enumeration"),
        ("amass", "Subdomain Enumeration"),
        ("assetfinder", "Subdomain Enumeration"),
        ("chaos", "Subdomain Enumeration"),
        // Passive Recon
        ("gau", "Passive Recon"),
        ("waybackurls", "Passive Recon"),
        // DNS
        ("dnsrecon", "DNS Enumeration"),
        ("shuffledns", "DNS Brute Force"),
        ("puredns", "DNS Brute Force"),
        ("dnsx", "DNS Resolution"),
        // Live detection
        ("httpx", "Live Detection"),
        ("naabu", "Live Detection / Port Scan"),
        // Port scanning
        ("masscan", "Port Scanning"),
        ("rustscan", "Port Scanning"),
        ("nmap", "Port / Service Scan"),
        ("nc", "Banner Grabbing"),
        // Directory discovery
        ("feroxbuster", "Directory Discovery"),
        ("ffuf", "Directory/Param Fuzzing"),
        ("gobuster", "Directory/DNS Brute Force"),
        ("dirsearch", "Directory Discovery"),
        // URL discovery
        ("hakrawler", "URL Crawling"),
        ("katana", "URL Crawling"),
        ("paramspider", "Parameter Discovery"),
        // JS analysis
        ("linkfinder", "JS Analysis"),
        ("xnLinkFinder", "JS Analysis"),
        // Vuln scanning
        ("nuclei", "Vulnerability Scanning"),
        ("nikto", "Vulnerability Scanning"),
        ("zap-baseline.py", "Vulnerability Scanning (ZAP)"),
        ("dalfox", "XSS Scanner"),
        ("sqlmap", "SQL Injection"),
        ("xsstrike", "XSS Scanner"),
        // Cloud
        ("cloud_enum", "Cloud Enum"),
        ("s3scanner", "S3 Bucket Scanner"),
        ("trufflehog", "Secret Detection"),
        ("gitleaks", "Secret Detection"),
        // OSINT
        ("whois", "OSINT"),
    ];

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Tool").add_attribute(Attribute::Bold),
        Cell::new("Category").add_attribute(Attribute::Bold),
        Cell::new("Status").add_attribute(Attribute::Bold),
    ]);

    let mut installed = 0usize;
    let mut missing = 0usize;

    for (tool, category) in &tools {
        let found = Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let status_cell = if found {
            installed += 1;
            Cell::new("✓ Installed").fg(Color::Green)
        } else {
            missing += 1;
            Cell::new("✗ Missing").fg(Color::Red)
        };

        table.add_row(vec![
            Cell::new(tool),
            Cell::new(category),
            status_cell,
        ]);
    }

    println!("{}", table);
    println!();
    println!("{} {}/{} tools installed",
        "[+]".green().bold(),
        installed.to_string().green().bold(),
        tools.len().to_string().white()
    );
    if missing > 0 {
        println!("{} {} tools missing — run {} to install them",
            "[!]".yellow().bold(),
            missing.to_string().yellow().bold(),
            "install_tools.sh".cyan()
        );
    } else {
        println!("{}", "[+] All tools are installed. VulnHawk is ready!".green().bold());
    }
    Ok(())
}

/// Setup — installs all required tools by running the installation script
pub async fn handle_setup() -> anyhow::Result<()> {
    println!("{} {}\n", "[*]".cyan().bold(), "Starting VulnHawk environment setup...".white().bold());
    println!("{} This will execute {} which requires sudo privileges for some packages.", "[!]".yellow(), "install_tools.sh".cyan());
    
    let confirm = Confirm::new("Do you want to proceed with the installation?")
        .with_default(false)
        .prompt()?;
        
    if !confirm {
        println!("{}", "[-] Setup cancelled by user.".red());
        return Ok(());
    }

    println!("{}", "[*] Executing installation script...".cyan());
    
    use tokio::process::Command;
    let mut child = Command::new("bash")
        .arg("./install_tools.sh")
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to run install_tools.sh: {}. Ensure you are in a Linux/WSL environment.", e))?;
        
    let status = child.wait().await?;
    
    if status.success() {
        println!("\n{}", "[+] Environment setup completed successfully!".green().bold());
    } else {
        println!("\n{}", "[!] Installation script exited with an error status.".red().bold());
    }
    
    Ok(())
}

/// Interactive Wizard Mode
pub async fn run_interactive() -> anyhow::Result<()> {
    loop {
        // Clear screen via a simple command or ANSI escape
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        crate::print_banner();
        println!("{}\n", "Welcome to the VulnHawk Interactive Prompts Mode!".cyan().bold());

        let options = vec![
            "🚀 Full Automated Scan (All modules)",
            "🛠️  Custom Scan (Select tools & modules)",
            "🔍 Subdomain Enumeration",
            "🌐 DNS Enumeration",
            "🔓 Port Scanning",
            "📂 Directory Discovery",
            "🛡️  Vulnerability Scanning",
            "🏥 Run Doctor Check (Tool status)",
            "⚙️  Setup Environment (Install all tools)",
            "❓ Help / How to use",
            "❌ Exit"
        ];

        let selection = Select::new("Select an action to perform:", options).prompt()?;

        match selection {
            "🚀 Full Automated Scan (All modules)" => {
                let target = Text::new("Enter target (Domain/IP/URL):").prompt()?;
                handle_scan(&target, true, None).await?;
                pause_for_user()?;
            },
            "🛠️  Custom Scan (Select tools & modules)" => {
                let target = Text::new("Enter target (Domain/IP/URL):").prompt()?;
                handle_custom_scan_wizard(&target).await?;
                pause_for_user()?;
            },
            "🔍 Subdomain Enumeration" => {
                let target = Text::new("Enter domain for subdomain discovery:").prompt()?;
                handle_subdomain(&target).await?;
                pause_for_user()?;
            },
            "🌐 DNS Enumeration" => {
                let target = Text::new("Enter domain for DNS enumeration:").prompt()?;
                handle_dns(&target).await?;
                pause_for_user()?;
            },
            "🔓 Port Scanning" => {
                let target = Text::new("Enter IP or Domain for port scan:").prompt()?;
                handle_port(&target).await?;
                pause_for_user()?;
            },
            "📂 Directory Discovery" => {
                let target = Text::new("Enter URL for directory fuzzing:").prompt()?;
                handle_dir(&target).await?;
                pause_for_user()?;
            },
            "🛡️  Vulnerability Scanning" => {
                let target = Text::new("Enter URL/Domain for vulnerability scan:").prompt()?;
                handle_vuln(&target).await?;
                pause_for_user()?;
            },
            "🏥 Run Doctor Check (Tool status)" => {
                handle_doctor().await?;
                pause_for_user()?;
            },
            "⚙️  Setup Environment (Install all tools)" => {
                handle_setup().await?;
                pause_for_user()?;
            },
            "❓ Help / How to use" => {
                show_help_guide();
                pause_for_user()?;
            },
            "❌ Exit" => {
                println!("{}", "Exiting VulnHawk... Good hunting!".bright_black());
                break;
            },
            _ => break,
        }
    }

    Ok(())
}

pub async fn handle_custom_scan_wizard(target: &str) -> anyhow::Result<()> {
    let modules = vec![
        "Subdomain (Active)",
        "Subdomain (Passive)",
        "Subdomain (Brute-Force)",
        "DNS Enumeration",
        "Live Host Detection",
        "Port Scanning",
        "Service Detection",
        "Technology Detection",
        "Directory Discovery",
        "URL Discovery",
        "JavaScript Analysis",
        "Vulnerability Scanning",
        "Cloud & Misconfig",
        "OSINT Intelligence",
    ];

    let selected_modules = MultiSelect::new("Select modules to include in scan:", modules).prompt()?;
    
    let mut filter_map: HashMap<String, Vec<String>> = HashMap::new();

    for m in selected_modules {
        match m {
            "Subdomain (Active)" => {
                let tools = vec!["subfinder", "findomain"];
                let selected = MultiSelect::new("Select tools for Active Subdomain:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Subdomain".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Subdomain (Passive)" => {
                let tools = vec!["crt.sh", "certspotter", "gau"];
                let selected = MultiSelect::new("Select tools for Passive Subdomain:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Passive".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Subdomain (Brute-Force)" => {
                let tools = vec!["puredns", "shuffledns", "gobuster"];
                let selected = MultiSelect::new("Select tools for Brute-Force:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Bruteforce".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "DNS Enumeration" => {
                let tools = vec!["dnsrecon", "shuffledns", "dnsx", "puredns"];
                let selected = MultiSelect::new("Select tools for DNS:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("DNS".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Live Host Detection" => {
                let tools = vec!["httpx", "naabu"];
                let selected = MultiSelect::new("Select tools for Live Detection:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Live".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Port Scanning" => {
                let tools = vec!["masscan", "rustscan", "nmap"];
                let selected = MultiSelect::new("Select tools for Ports:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Ports".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Service Detection" => {
                let tools = vec!["nmap", "nc"];
                let selected = MultiSelect::new("Select tools for Services:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Services".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Technology Detection" => {
                let tools = vec!["httpx"];
                let selected = MultiSelect::new("Select tools for Tech Detection:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Tech".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Directory Discovery" => {
                let tools = vec!["feroxbuster", "ffuf", "dirsearch"];
                let selected = MultiSelect::new("Select tools for Directory:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("DirectoryDiscovery".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "URL Discovery" => {
                let tools = vec!["katana", "hakrawler", "gau", "waybackurls", "paramspider"];
                let selected = MultiSelect::new("Select tools for URLs:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("URLDiscovery".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "JavaScript Analysis" => {
                let tools = vec!["linkfinder", "secretfinder"];
                let selected = MultiSelect::new("Select tools for JS Analysis:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("JSAnalysis".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Vulnerability Scanning" => {
                let tools = vec!["nuclei", "nikto", "zap", "sqlmap", "dalfox", "xsstrike"];
                let selected = MultiSelect::new("Select tools for Vuln:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Vuln".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "Cloud & Misconfig" => {
                let tools = vec!["cloud_enum", "trufflehog", "s3scanner", "gitleaks"];
                let selected = MultiSelect::new("Select tools for Cloud:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("Cloud".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            "OSINT Intelligence" => {
                let tools = vec!["whois", "shodan"];
                let selected = MultiSelect::new("Select tools for OSINT:", tools).prompt()?;
                if !selected.is_empty() {
                    filter_map.insert("OSINT".to_string(), selected.into_iter().map(String::from).collect());
                }
            },
            _ => {}
        }
    }

    if filter_map.is_empty() {
        println!("{}", "[-] No tools selected. Scan cancelled.".red());
        return Ok(());
    }

    execute_scan(target, Some(filter_map)).await
}

fn pause_for_user() -> anyhow::Result<()> {
    println!();
    Confirm::new("Press Enter to return to menu...")
        .with_default(true)
        .with_help_message("Just press Enter")
        .prompt()?;
    Ok(())
}

fn show_help_guide() {
    println!("\n{}", "─── VULNHAWK COMPREHENSIVE GUIDE ───".cyan().bold());
    
    println!("\n{}", "🚀 HOW TO START A QUICK SCAN:".green().bold());
    println!("   Simply run `vulnhawk` without arguments to enter this interactive menu.");
    println!("   Choose 'Full Automated Scan' for the most comprehensive results.");

    println!("\n{}", "💻 COMMAND LINE USAGE (CLI MODE):".green().bold());
    println!("   {} scan example.com --full      {}", "vulnhawk".cyan(), "Run all modules".bright_black());
    println!("   {} subdomain example.com        {}", "vulnhawk".cyan(), "Only find subdomains".bright_black());
    println!("   {} port 192.168.1.1             {}", "vulnhawk".cyan(), "Scan for open ports".bright_black());
    println!("   {} doctor                      {}", "vulnhawk".cyan(), "Check tool dependencies".bright_black());

    println!("\n{}", "🔍 CORE MODULES EXPLAINED:".green().bold());
    println!("   - {}: Finds hidden subdomains using 10+ sources.", "Subdomain".yellow());
    println!("   - {}: Checks A, MX, TXT, and CNAME records.", "DNS".yellow());
    println!("   - {}: Scans 1000+ common ports and identifies services.", "Port".yellow());
    println!("   - {}: Fuzzes URLs for hidden files and folders.", "Dir".yellow());
    println!("   - {}: Tests for XSS, SQLi, and misconfigurations.", "Vuln".yellow());
    
    println!("\n{}", "⚠️  IMPORTANT:".red().bold());
    println!("   Ensure all external tools are installed by running 'Doctor' check.");
    println!("   Always use this tool legally and with permission.");
    println!("───────────────────────────────────────\n");
}
