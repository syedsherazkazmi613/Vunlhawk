// ============================================================
// modules/bruteforce.rs — Subdomain brute-force
// Tools: puredns, shuffledns, gobuster dns
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use std::collections::HashSet;

const DEFAULT_WORDLIST: &str = "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt";
const RESOLVERS: &str = "/usr/share/wordlists/resolvers.txt";

/// Run subdomain brute-force tools and return discovered subdomains
pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<String>> {
    let domain = target.domain_or_ip();
    let wlist = DEFAULT_WORDLIST; // Simplify for now
    let mut found: HashSet<String> = HashSet::new();

    println!("\n{}", "┌─[ Subdomain Brute-Force ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── puredns ───────────────────────────────────────────────
    if should_run("puredns") {
        println!("{}", "│  [*] Running puredns bruteforce...".white());
        if let Ok(out) = run_tool(
            "puredns",
            &["bruteforce", wlist, &domain, "-r", RESOLVERS, "--quiet"],
        )
        .await
        {
            let subs = parse_lines(&out);
            println!("{}  {} subdomains via puredns", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    // ── shuffledns ────────────────────────────────────────────
    if should_run("shuffledns") {
        println!("{}", "│  [*] Running shuffledns bruteforce...".white());
        if let Ok(out) = run_tool(
            "shuffledns",
            &["-d", &domain, "-w", wlist, "-r", RESOLVERS, "-silent"],
        )
        .await
        {
            let subs = parse_lines(&out);
            println!("{}  {} subdomains via shuffledns", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    // ── gobuster dns ──────────────────────────────────────────
    if should_run("gobuster") {
        println!("{}", "│  [*] Running gobuster dns...".white());
        if let Ok(out) = run_tool(
            "gobuster",
            &["dns", "-d", &domain, "-w", wlist, "-q", "--no-error"],
        )
        .await
        {
            let subs: Vec<String> = out
                .lines()
                .filter(|l| l.contains("Found:"))
                .map(|l| l.replace("Found:", "").trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            println!("{}  {} subdomains via gobuster dns", "│".bright_black(), subs.len().to_string().green());
            found.extend(subs);
        }
    }

    let mut results: Vec<String> = found
        .into_iter()
        .filter(|s| s.ends_with(&domain))
        .collect();
    results.sort();

    println!("{}", format!("└─[ ✓ Brute-forced subdomains: {} ]", results.len()).bright_green().bold());
    Ok(results)
}

fn parse_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && l.contains('.'))
        .map(String::from)
        .collect()
}
