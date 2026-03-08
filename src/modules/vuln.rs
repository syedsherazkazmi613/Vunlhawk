// ============================================================
// modules/vuln.rs — Vulnerability Scanning
// Tools: nuclei, nikto, dalfox, sqlmap
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

    println!("{}", format!("└─[ ✓ Vulnerabilities found: {} ]", vulns.len()).bright_green().bold());
    Ok(vulns)
}
