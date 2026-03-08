// ============================================================
// modules/services.rs — Service and version detection
// Tools: nmap -sV, banner grabbing, nc
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service: String,
    pub version: String,
    pub banner: Option<String>,
}

/// Detect services and versions running on open ports
pub async fn run(target: &TargetInfo, open_ports: &[u16], tools: Option<Vec<String>>) -> anyhow::Result<Vec<ServiceInfo>> {
    let host = target.domain_or_ip();
    let mut services = Vec::new();

    if open_ports.is_empty() {
        return Ok(services);
    }

    println!("\n{}", "┌─[ Service & Version Detection ]".bright_cyan().bold());
    
    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    let port_list = open_ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",");
    
    // ── nmap -sV ──────────────────────────────────────────────
    if should_run("nmap") {
        println!("{}", "│  [*] Running nmap service detection...".white());
        if let Ok(out) = run_tool("nmap", &["-p", &port_list, "-sV", "--version-intensity", "5", &host, "-Pn"]).await {
            services = parse_nmap_services(&out);
        }
    }

    // ── Banner Grabbing ───────────────────────────────────────
    if should_run("nc") {
        for service in &mut services {
            if service.banner.is_none() {
                println!("{}  [*] Grabbing banner for port {}...", "│".bright_black(), service.port);
                if let Ok(banner) = run_tool("nc", &["-zv", "-w", "2", &host, &service.port.to_string()]).await {
                    service.banner = Some(banner.trim().to_string());
                }
            }
        }
    }

    println!("{}", format!("└─[ ✓ Services detected: {} ]", services.len()).bright_green().bold());
    Ok(services)
}

fn parse_nmap_services(raw: &str) -> Vec<ServiceInfo> {
    let mut results = Vec::new();
    let mut in_table = false;
    for line in raw.lines() {
        if line.contains("PORT") && line.contains("STATE") && line.contains("SERVICE") {
            in_table = true;
            continue;
        }
        if in_table && line.is_empty() {
            in_table = false;
            continue;
        }
        if in_table {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "open" {
                let port: u16 = parts[0].split('/').next().unwrap_or("0").parse().unwrap_or(0);
                let service = parts[2].to_string();
                let version = parts[3..].join(" ");
                results.push(ServiceInfo {
                    port,
                    service,
                    version,
                    banner: None,
                });
            }
        }
    }
    results
}
