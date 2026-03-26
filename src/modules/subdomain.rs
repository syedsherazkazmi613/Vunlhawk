// ============================================================
// modules/subdomain.rs — Active subdomain enumeration
// Tools: subfinder, amass, findomain, assetfinder, sublist3r, chaos
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use std::collections::HashSet;

/// Run all subdomain enumeration tools against the target domain.
/// Returns a deduplicated list of discovered subdomains.
pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<String>> {
    let domain = target.domain_or_ip();
    let mut found: HashSet<String> = HashSet::new();

    println!("\n{}", "┌─[ Subdomain Enumeration ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── subfinder ─────────────────────────────────────────────
    if should_run("subfinder") {
        println!("{}", "│  [*] Running subfinder...".white());
        if let Ok(out) = run_tool("subfinder", &["-d", &domain, "-silent"]).await {
            let subs = parse_line_output(&out);
            println!("{}  {} subdomains via subfinder", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    // ── amass ─────────────────────────────────────────────────
    if should_run("amass") {
        println!("{}", "│  [*] Running amass (passive)...".white());
        if let Ok(out) = run_tool("amass", &["enum", "-passive", "-d", &domain]).await {
            let subs = parse_line_output(&out);
            println!("{}  {} subdomains via amass", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    // ── assetfinder ───────────────────────────────────────────
    if should_run("assetfinder") {
        println!("{}", "│  [*] Running assetfinder...".white());
        if let Ok(out) = run_tool("assetfinder", &["--subs-only", &domain]).await {
            let subs = parse_line_output(&out);
            println!("{}  {} subdomains via assetfinder", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    // ── chaos ─────────────────────────────────────────────────
    if should_run("chaos") {
        println!("{}", "│  [*] Running chaos...".white());
        if let Ok(out) = run_tool("chaos", &["-d", &domain, "-silent"]).await {
            let subs = parse_line_output(&out);
            println!("{}  {} subdomains via chaos", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    // ── findomain ─────────────────────────────────────────────
    if should_run("findomain") {
        println!("{}", "│  [*] Running findomain...".white());
        if let Ok(out) = run_tool("findomain", &["-t", &domain, "--quiet"]).await {
            let subs = parse_line_output(&out);
            println!("{}  {} subdomains via findomain", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    // ── sublist3r ─────────────────────────────────────────────
    if should_run("sublist3r") {
        println!("{}", "│  [*] Running sublist3r...".white());
        // Using -n to skip DNS resolution for speed as we do it later
        if let Ok(out) = run_tool("sublist3r", &["-d", &domain, "-n"]).await {
            let subs = parse_line_output(&out);
            println!("{}  {} subdomains via sublist3r", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    let mut results: Vec<String> = found
        .into_iter()
        .filter(|s| s.contains(&domain) && !s.is_empty())
        .collect();
    results.sort();

    println!("{}", format!("└─[ ✓ Total unique subdomains: {} ]", results.len()).bright_green().bold());
    Ok(results)
}

/// Parse newline-separated tool output into a Vec<String>
fn parse_line_output(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && l.contains('.'))
        .map(String::from)
        .collect()
}
