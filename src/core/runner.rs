// ============================================================
// core/runner.rs — Tool orchestration and execution engine
// ============================================================

use anyhow::Context;
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::AsyncWriteExt;
use crate::modules::{
    subdomain, passive, dns, bruteforce, live, ports, services,
    tech, directory, urls, js, vuln, cloud, osint,
};
use crate::core::parser::TargetInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullScanResults {
    pub subdomains: Vec<String>,
    pub dns_records: Vec<dns::DnsRecord>,
    pub live_hosts: Vec<live::LiveHost>,
    pub open_ports: Vec<u16>,
    pub services: Vec<services::ServiceInfo>,
    pub tech: Vec<tech::TechInfo>,
    pub directories: Vec<String>,
    pub urls: Vec<String>,
    pub js_findings: Vec<js::JsFinding>,
    pub vulnerabilities: Vec<vuln::Vulnerability>,
    pub cloud_findings: Vec<cloud::CloudFinding>,
    pub osint_info: Vec<osint::OsintInfo>,
}

pub struct ScanRunner {
    pub target: TargetInfo,
}

impl ScanRunner {
    pub async fn new(target_str: &str) -> anyhow::Result<Self> {
        let target = TargetInfo::detect(target_str).await?;
        Ok(Self { target })
    }

    pub async fn run(
        &self, 
        _full: bool, 
        modules_filter: Option<HashMap<String, Vec<String>>>
    ) -> anyhow::Result<FullScanResults> {
        // 1. Subdomain Enumeration (Passive + Active)
        let mut all_subs = Vec::new();
        
        let passive_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Passive"))
            .cloned()
            .unwrap_or_default();
        
        if !modules_filter.is_some() || !passive_tools.is_empty() {
             let passive_subs = passive::run(&self.target, if modules_filter.is_some() { Some(passive_tools) } else { None }).await.unwrap_or_default();
             all_subs.extend(passive_subs);
        }

        let subdomain_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Subdomain"))
            .cloned()
            .unwrap_or_default();
        
        if !modules_filter.is_some() || !subdomain_tools.is_empty() {
            let active_subs = subdomain::run(&self.target, if modules_filter.is_some() { Some(subdomain_tools) } else { None }).await.unwrap_or_default();
            all_subs.extend(active_subs);
        }

        all_subs.sort();
        all_subs.dedup();

        // 2. DNS Enumeration
        let mut dns_recs = Vec::new();
        let dns_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("DNS"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !dns_tools.is_empty() {
            dns_recs = dns::run(&self.target, if modules_filter.is_some() { Some(dns_tools) } else { None }).await.unwrap_or_default();
        }

        // 3. Subdomain Brute Force
        let brute_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Bruteforce"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !brute_tools.is_empty() {
             let brute_subs = bruteforce::run(&self.target, if modules_filter.is_some() { Some(brute_tools) } else { None }).await.unwrap_or_default();
             all_subs.extend(brute_subs);
             all_subs.sort();
             all_subs.dedup();
        }

        // 4. Live Host Detection
        let mut live_hosts = Vec::new();
        let live_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Live"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !live_tools.is_empty() {
            live_hosts = live::run(&self.target, &all_subs, if modules_filter.is_some() { Some(live_tools) } else { None }).await.unwrap_or_default();
        }
        let live_urls: Vec<String> = live_hosts.iter().map(|h| h.url.clone()).collect();

        // 5. Port Scanning
        let mut open_ports = Vec::new();
        let port_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Ports"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !port_tools.is_empty() {
             open_ports = ports::run(&self.target, if modules_filter.is_some() { Some(port_tools) } else { None }).await.unwrap_or_default();
        }

        // 6. Service & Version Detection
        let mut svcs = Vec::new();
        let svc_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Services"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !svc_tools.is_empty() {
            svcs = services::run(&self.target, &open_ports, if modules_filter.is_some() { Some(svc_tools) } else { None }).await.unwrap_or_default();
        }

        // 7. Technology Detection
        let mut technology = Vec::new();
        let tech_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Tech"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !tech_tools.is_empty() {
            technology = tech::run(&self.target, &live_urls, if modules_filter.is_some() { Some(tech_tools) } else { None }).await.unwrap_or_default();
        }

        // 8. Directory Discovery
        let mut dirs = Vec::new();
        let dir_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("DirectoryDiscovery"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !dir_tools.is_empty() {
            dirs = directory::run(&self.target, if modules_filter.is_some() { Some(dir_tools) } else { None }).await.unwrap_or_default();
        }

        // 9. URL Discovery
        let mut discovered_urls = Vec::new();
        let url_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("URLDiscovery"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !url_tools.is_empty() {
            discovered_urls = urls::run(&self.target, if modules_filter.is_some() { Some(url_tools) } else { None }).await.unwrap_or_default();
        }

        // 10. JS Analysis
        let mut js_finds = Vec::new();
        let js_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("JSAnalysis"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !js_tools.is_empty() {
            let js_files: Vec<String> = discovered_urls.iter().filter(|u| u.ends_with(".js")).cloned().collect();
            js_finds = js::run(&self.target, &js_files, if modules_filter.is_some() { Some(js_tools) } else { None }).await.unwrap_or_default();
        }

        // 11. Vulnerability Scanning
        let mut vulnerabilities = Vec::new();
        let vuln_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Vuln"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !vuln_tools.is_empty() {
             vulnerabilities = vuln::run(&self.target, if modules_filter.is_some() { Some(vuln_tools) } else { None }).await.unwrap_or_default();
        }

        // 12. Cloud & Misconfig
        let mut cloud_finds = Vec::new();
        let cloud_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("Cloud"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !cloud_tools.is_empty() {
             cloud_finds = cloud::run(&self.target, if modules_filter.is_some() { Some(cloud_tools) } else { None }).await.unwrap_or_default();
        }

        // 13. OSINT
        let mut osint_data = Vec::new();
        let osint_tools: Vec<String> = modules_filter.as_ref()
            .and_then(|m| m.get("OSINT"))
            .cloned()
            .unwrap_or_default();
        if !modules_filter.is_some() || !osint_tools.is_empty() {
            osint_data = osint::run(&self.target, if modules_filter.is_some() { Some(osint_tools) } else { None }).await.unwrap_or_default();
        }

        Ok(FullScanResults {
            subdomains: all_subs,
            dns_records: dns_recs,
            live_hosts,
            open_ports,
            services: svcs,
            tech: technology,
            directories: dirs,
            urls: discovered_urls,
            js_findings: js_finds,
            vulnerabilities,
            cloud_findings: cloud_finds,
            osint_info: osint_data,
        })
    }
}

/// Helper to run an external tool and capture stdout
pub async fn run_tool(cmd: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .with_context(|| format!("Failed to execute tool: {}", cmd))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Helper to run an external tool with stdin data
pub async fn run_tool_with_stdin(cmd: &str, args: &[&str], input: &str) -> anyhow::Result<String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("Failed to spawn tool with stdin: {}", cmd))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
