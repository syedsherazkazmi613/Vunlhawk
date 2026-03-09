// ============================================================
// modules/js.rs — JavaScript Analysis
// Tools: linkfinder, secretfinder, jsfinder
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFinding {
    pub url: String,
    pub findings: Vec<String>,
}

pub async fn run(_target: &TargetInfo, js_urls: &[String], tools: Option<Vec<String>>) -> anyhow::Result<Vec<JsFinding>> {
    let mut results = Vec::new();
    
    println!("\n{}", "┌─[ JavaScript Analysis ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    for url in js_urls.iter().take(10) {
        println!("{}  [*] Analyzing {}...", "│".bright_black(), url);
        let mut findings = Vec::new();

        // ── linkfinder ──────────────────────────────────────────
        if should_run("linkfinder") {
            if let Ok(out) = run_tool("linkfinder", &["-i", url, "-o", "cli"]).await {
                for line in out.lines() {
                    if line.starts_with("http") || line.starts_with("/") {
                        findings.push(line.trim().to_string());
                    }
                }
            }
        }

        // ── secretfinder ───────────────────────────────────────
        if should_run("secretfinder") {
            if let Ok(out) = run_tool("secretfinder", &["-i", url, "-o", "cli"]).await {
                for line in out.lines() {
                    if line.contains("Found") {
                        findings.push(line.trim().to_string());
                    }
                }
            }
        }

        // ── xnLinkFinder ───────────────────────────────────────
        if should_run("xnlinkfinder") {
             if let Ok(out) = run_tool("xnLinkFinder", &["-i", url, "-o", "cli"]).await {
                for line in out.lines() {
                    if line.starts_with("http") || line.starts_with("/") {
                        findings.push(line.trim().to_string());
                    }
                }
            }
        }

        results.push(JsFinding {
            url: url.clone(),
            findings,
        });
    }

    println!("{}", format!("└─[ ✓ JavaScript analysis complete ]").bright_green().bold());
    Ok(results)
}
