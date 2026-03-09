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

    // ── ffuf ──────────────────────────────────────────────────
    if should_run("ffuf") {
        println!("{}", "│  [*] Running ffuf...".white());
        // Simple ffuf run with common wordlist if it exists
        if let Ok(out) = run_tool("ffuf", &["-u", &format!("{}/FUZZ", url), "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,301,302", "-s"]).await {
            for line in out.lines() {
                found.insert(format!("{}/{}", url, line.trim()));
            }
        }
    }

    // ── dirsearch ─────────────────────────────────────────────
    if should_run("dirsearch") {
        println!("{}", "│  [*] Running dirsearch...".white());
        if let Ok(out) = run_tool("dirsearch", &["-u", &url, "--format=plain", "-q"]).await {
            for line in out.lines() {
                if line.starts_with("http") {
                    found.insert(line.trim().to_string());
                }
            }
        }
    }

    println!("{}", format!("└─[ ✓ Paths discovered: {} ]", found.len()).bright_green().bold());
    Ok(found.into_iter().collect())
}
