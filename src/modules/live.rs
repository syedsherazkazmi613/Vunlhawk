// ============================================================
// modules/live.rs — Live host detection
// Tools: httpx, httprobe, naabu
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::{run_tool, run_tool_with_stdin};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Information about a confirmed live host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveHost {
    pub url: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub tech: Vec<String>,
    pub source: String,
}

/// Detect which subdomains/hosts are actually responding to HTTP(S)
pub async fn run(
    target: &TargetInfo,
    candidates: &[String],
    tools: Option<Vec<String>>,
) -> anyhow::Result<Vec<LiveHost>> {
    let input = candidates.join("\n");
    let mut live: HashSet<String> = HashSet::new();
    let mut hosts: Vec<LiveHost> = Vec::new();

    println!("\n{}", "┌─[ Live Host Detection ]".bright_cyan().bold());
    println!("{}  Probing {} candidates...", "│".bright_black(), candidates.len().to_string().yellow());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── httpx ─────────────────────────────────────────────────
    if should_run("httpx") {
        println!("{}", "│  [*] Running httpx...".white());
        if let Ok(out) = run_tool_with_stdin(
            "httpx",
            &["-silent", "-status-code", "-title", "-tech-detect", "-no-color"],
            &input,
        )
        .await
        {
            for line in out.lines().filter(|l| !l.trim().is_empty()) {
                let host = parse_httpx_line(line);
                if !live.contains(&host.url) {
                    live.insert(host.url.clone());
                    hosts.push(host);
                }
            }
            println!("{}  {} live hosts via httpx", "│".bright_black(), hosts.len().to_string().green());
        }
    }

    // ── naabu (port pre-check) ────────────────────────────────
    if should_run("naabu") {
        println!("{}", "│  [*] Running naabu (port 80/443 check)...".white());
        let domain = target.domain_or_ip();
        if let Ok(out) = run_tool(
            "naabu",
            &["-host", &domain, "-p", "80,443,8080,8443", "-silent"],
        )
        .await
        {
            for line in out.lines().filter(|l| !l.trim().is_empty()) {
                let parts: Vec<&str> = line.trim().splitn(2, ':').collect();
                if parts.len() == 2 {
                    let host_str = parts[0];
                    let port: u16 = parts[1].parse().unwrap_or(80);
                    let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
                    let url = format!("{}://{}:{}", scheme, host_str, port);
                    if !live.contains(&url) {
                        live.insert(url.clone());
                        hosts.push(LiveHost {
                            url,
                            status_code: None,
                            title: None,
                            tech: vec![],
                            source: "naabu".to_string(),
                        });
                    }
                }
            }
        }
    }

    println!("{}", format!("└─[ ✓ Live hosts confirmed: {} ]", hosts.len()).bright_green().bold());
    Ok(hosts)
}

/// Parse a single httpx output line into a LiveHost struct
fn parse_httpx_line(line: &str) -> LiveHost {
    // Pattern: "https://sub.example.com [200] [tech1,tech2] [Page Title]"
    let url;
    let mut status: Option<u16> = None;
    let mut tech = Vec::new();
    let mut title: Option<String> = None;

    // Extract bracket-enclosed tokens
    let mut rest = line.to_string();
    if let Some(end) = rest.find(' ') {
        url = rest[..end].trim().to_string();
        rest = rest[end..].trim().to_string();
    } else {
        url = rest.clone();
        rest = String::new();
    }

    // Parse [code] [tech] [title] tokens lazily
    let mut depth = 0usize;
    let mut token = String::new();
    let mut tokens: Vec<String> = Vec::new();
    for ch in rest.chars() {
        match ch {
            '[' => { depth += 1; }
            ']' => {
                depth -= 1;
                if depth == 0 {
                    tokens.push(token.trim().to_string());
                    token.clear();
                }
            }
            c if depth > 0 => { token.push(c); }
            _ => {}
        }
    }

    for (i, tok) in tokens.iter().enumerate() {
        if i == 0 {
            status = tok.parse::<u16>().ok();
        } else if i == 1 {
            tech = tok.split(',').map(|s| s.trim().to_string()).collect();
        } else if i == 2 {
            title = Some(tok.clone());
        }
    }

    LiveHost { url, status_code: status, title, tech, source: "httpx".to_string() }
}
