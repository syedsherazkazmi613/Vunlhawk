// ============================================================
// modules/ports.rs — Port scanning
// Tools: masscan, rustscan, nmap
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

/// Run port scanning tools and return unique open ports
pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<u16>> {
    let host = target.domain_or_ip();
    let mut ports: HashSet<u16> = HashSet::new();

    println!("\n{}", "┌─[ Port Scanning ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── masscan ──────────────────────────────────────────────
    if should_run("masscan") {
        println!("{}", "│  [*] Running masscan (top 1000)...".white());
        if let Ok(out) = run_tool("masscan", &[&host, "--top-ports", "1000", "--rate", "1000"]).await {
            for line in out.lines() {
                if line.contains("Discovered open port") {
                    if let Some(port_str) = line.split_whitespace().nth(3) {
                        if let Ok(p) = port_str.split('/').next().unwrap_or("").parse::<u16>() {
                            ports.insert(p);
                        }
                    }
                }
            }
            println!("{}  {} ports via masscan", "│".bright_black(), ports.len().to_string().green());
        }
    }

    // ── rustscan ──────────────────────────────────────────────
    if should_run("rustscan") {
        println!("{}", "│  [*] Running rustscan...".white());
        if let Ok(out) = run_tool("rustscan", &["-a", &host, "--ulimit", "5000", "--", "-sS", "-Pn"]).await {
            for line in out.lines() {
                if line.contains("Open") && line.contains(':') {
                    if let Some(port_part) = line.split(':').last() {
                        if let Ok(p) = port_part.trim().parse::<u16>() {
                            ports.insert(p);
                        }
                    }
                }
            }
            println!("{}  {} unique ports total", "│".bright_black(), ports.len().to_string().green());
        }
    }

    // ── nmap (verification) ───────────────────────────────────
    if should_run("nmap") && !ports.is_empty() {
        println!("{}", "│  [*] Running nmap verification...".white());
        let port_list = ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",");
        if let Ok(out) = run_tool("nmap", &["-p", &port_list, &host, "-Pn", "-sS", "-oG", "-"]).await {
            for line in out.lines() {
                if line.contains("/open/") {
                    for part in line.split("/open/") {
                        if let Some(port_str) = part.split_whitespace().last() {
                            if let Ok(p) = port_str.parse::<u16>() {
                                ports.insert(p);
                            }
                        }
                    }
                }
            }
        }
    }

    let mut result: Vec<u16> = ports.into_iter().collect();
    result.sort();

    println!("{}", format!("└─[ ✓ Total open ports: {} ]", result.len()).bright_green().bold());
    Ok(result)
}
