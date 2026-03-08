// ============================================================
// modules/directory.rs — Directory Discovery
// Tools: feroxbuster, dirsearch, ffuf, gobuster
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use std::collections::HashSet;

/// Discover hidden directories and files
pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<String>> {
    let url = target.url().unwrap_or(&target.domain_or_ip().to_string()).to_string();
    let mut found = HashSet::new();

    println!("\n{}", "┌─[ Directory Discovery ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── feroxbuster ──────────────────────────────────────────
    if should_run("feroxbuster") {
        println!("{}", "│  [*] Running feroxbuster...".white());
        if let Ok(out) = run_tool("feroxbuster", &["-u", &url, "--silent", "-n", "-e"]).await {
            for line in out.lines() {
                if line.contains("http") {
                    if let Some(link) = line.split_whitespace().find(|s| s.starts_with("http")) {
                        found.insert(link.to_string());
                    }
                }
            }
        }
    }

    println!("{}", format!("└─[ ✓ Paths discovered: {} ]", found.len()).bright_green().bold());
    Ok(found.into_iter().collect())
}
