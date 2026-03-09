// ============================================================
// modules/urls.rs — URL and Parameter Discovery
// Tools: gau, waybackurls, hakrawler, katana
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use std::collections::HashSet;

pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<String>> {
    let domain = target.domain_or_ip();
    let mut urls = HashSet::new();

    println!("\n{}", "┌─[ URL & Parameter Discovery ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── katana ────────────────────────────────────────────────
    if should_run("katana") {
        println!("{}", "│  [*] Running katana (crawler)...".white());
        if let Ok(out) = run_tool("katana", &["-u", &domain, "-silent", "-em", "js,php,html"]).await {
            for line in out.lines() {
                urls.insert(line.trim().to_string());
            }
        }
    }

    // ── gau ───────────────────────────────────────────────────
    if should_run("gau") {
        println!("{}", "│  [*] Running gau (Get All URLs)...".white());
        if let Ok(out) = run_tool("gau", &[&domain, "--subs"]).await {
            for line in out.lines() {
                urls.insert(line.trim().to_string());
            }
        }
    }

    // ── waybackurls ───────────────────────────────────────────
    if should_run("waybackurls") {
        println!("{}", "│  [*] Running waybackurls...".white());
        if let Ok(out) = run_tool("waybackurls", &[&domain]).await {
            for line in out.lines() {
                urls.insert(line.trim().to_string());
            }
        }
    }

    // ── hakrawler ─────────────────────────────────────────────
    if should_run("hakrawler") {
        println!("{}", "│  [*] Running hakrawler...".white());
        if let Ok(out) = run_tool("hakrawler", &["-url", &domain, "-plain"]).await {
            for line in out.lines() {
                urls.insert(line.trim().to_string());
            }
        }
    }

    // ── paramspider ───────────────────────────────────────────
    if should_run("paramspider") {
        println!("{}", "│  [*] Running paramspider...".white());
        // paramspider typically saves to a file, but some versions allow stdout or we can read the file
        // For CLI integration, we'll try to run it and capture what we can
        if let Ok(out) = run_tool("paramspider", &["-d", &domain, "--stream"]).await {
            for line in out.lines() {
                 if line.starts_with("http") {
                    urls.insert(line.trim().to_string());
                 }
            }
        }
    }

    println!("{}", format!("└─[ ✓ Total URLs discovered: {} ]", urls.len()).bright_green().bold());
    Ok(urls.into_iter().collect())
}
