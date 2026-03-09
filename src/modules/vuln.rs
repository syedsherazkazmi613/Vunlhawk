// ============================================================
// modules/vuln.rs — Vulnerability Scanning
// Tools: nuclei, nikto, zap, dalfox, sqlmap
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub tool: String,
}

pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<Vulnerability>> {
    let url = target.url().unwrap_or(&target.domain_or_ip().to_string()).to_string();
    let mut vulns = Vec::new();

    println!("\n{}", "┌─[ Vulnerability Scanning ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── nuclei ────────────────────────────────────────────────
    if should_run("nuclei") {
        println!("{}", "│  [*] Running nuclei...".white());
        if let Ok(out) = run_tool("nuclei", &["-u", &url, "-silent", "-nc"]).await {
            for line in out.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    vulns.push(Vulnerability {
                        name: parts[0].trim_matches(|c| c == '[' || c == ']').to_string(),
                        severity: parts[1].trim_matches(|c| c == '[' || c == ']').to_string(),
                        description: line.to_string(),
                        tool: "nuclei".to_string(),
                    });
                }
            }
        }
    }

    // ── nikto ──────────────────────────────────────────────────
    if should_run("nikto") {
        println!("{}", "│  [*] Running nikto...".white());
        // Run nikto with tuning for common web vulns
        if let Ok(out) = run_tool("nikto", &["-h", &url, "-nointeractive", "-Format", "txt"]).await {
            for line in out.lines() {
                if line.starts_with("+ ") {
                    vulns.push(Vulnerability {
                        name: "Nikto Finding".to_string(),
                        severity: "info".to_string(),
                        description: line[2..].to_string(),
                        tool: "nikto".to_string(),
                    });
                }
            }
        }
    }

    // ── zap ────────────────────────────────────────────────────
    if should_run("zap") {
        println!("{}", "│  [*] Running OWASP ZAP (baseline)...".white());
        // Using zap-baseline.py which is common in CI/CD and CLI environments
        if let Ok(out) = run_tool("zap-baseline.py", &["-t", &url, "-m", "1"]).await {
            for line in out.lines() {
                if line.contains("PASS:") || line.contains("WARN:") || line.contains("FAIL:") {
                    let severity = if line.contains("FAIL:") {
                        "high"
                    } else if line.contains("WARN:") {
                        "medium"
                    } else {
                        "info"
                    };

                    vulns.push(Vulnerability {
                        name: "ZAP Finding".to_string(),
                        severity: severity.to_string(),
                        description: line.to_string(),
                        tool: "zap".to_string(),
                    });
                }
            }
        }
    }

    // ── sqlmap ─────────────────────────────────────────────────
    if should_run("sqlmap") {
        println!("{}", "│  [*] Running sqlmap (basic check)...".white());
        if let Ok(out) = run_tool("sqlmap", &["-u", &url, "--batch", "--random-agent", "--level=1"]).await {
            if out.contains("is vulnerable") || out.contains("confirming") {
                 vulns.push(Vulnerability {
                    name: "SQL Injection".to_string(),
                    severity: "high".to_string(),
                    description: "Possible SQL injection detected by sqlmap".to_string(),
                    tool: "sqlmap".to_string(),
                });
            }
        }
    }

    // ── dalfox ─────────────────────────────────────────────────
    if should_run("dalfox") {
        println!("{}", "│  [*] Running dalfox (XSS)...".white());
        if let Ok(out) = run_tool("dalfox", &["url", &url, "--silent"]).await {
            for line in out.lines() {
                if line.contains("POC") {
                     vulns.push(Vulnerability {
                        name: "Cross-Site Scripting (XSS)".to_string(),
                        severity: "medium".to_string(),
                        description: line.to_string(),
                        tool: "dalfox".to_string(),
                    });
                }
            }
        }
    }

    // ── xsstrike ───────────────────────────────────────────────
    if should_run("xsstrike") {
        println!("{}", "│  [*] Running xsstrike...".white());
        if let Ok(out) = run_tool("xsstrike", &["-u", &url, "--crawl"]).await {
            if out.contains("Vulnerable") {
                 vulns.push(Vulnerability {
                    name: "XSS (XSStrike)".to_string(),
                    severity: "medium".to_string(),
                    description: "Possible XSS detected by XSStrike".to_string(),
                    tool: "xsstrike".to_string(),
                });
            }
        }
    }

    println!("{}", format!("└─[ ✓ Vulnerabilities found: {} ]", vulns.len()).bright_green().bold());
    Ok(vulns)
}
