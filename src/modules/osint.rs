// ============================================================
// modules/osint.rs — OSINT Intelligence
// Tools: shodan, whois, censys
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintInfo {
    pub category: String,
    pub data: String,
}

pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<OsintInfo>> {
    let host = target.domain_or_ip();
    let mut infos = Vec::new();

    println!("\n{}", "┌─[ OSINT Intelligence ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── whois ────────────────────────────────────────────────
    if should_run("whois") {
        println!("{}", "│  [*] Running whois...".white());
        if let Ok(out) = run_tool("whois", &[&host]).await {
            for line in out.lines() {
                if line.to_lowercase().contains("registrar:") || line.to_lowercase().contains("creation date:") {
                    infos.push(OsintInfo {
                        category: "Whois".to_string(),
                        data: line.trim().to_string(),
                    });
                }
            }
        }
    }

    // ── shodan ────────────────────────────────────────────────
    if should_run("shodan") {
        println!("{}", "│  [*] Querying shodan...".white());
        if let Ok(out) = run_tool("shodan", &["host", &host]).await {
            infos.push(OsintInfo {
                category: "Shodan".to_string(),
                data: out.lines().take(5).collect::<Vec<_>>().join(" | "),
            });
        }
    }

    println!("{}", format!("└─[ ✓ OSINT collection complete ]").bright_green().bold());
    Ok(infos)
}
