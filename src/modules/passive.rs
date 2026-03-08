// ============================================================
// modules/passive.rs — Passive certificate & URL sources
// Sources: crt.sh API, certspotter, gau, waybackurls
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

// crt.sh JSON response shape
#[derive(Deserialize)]
struct CrtEntry {
    name_value: String,
}

/// Enumerate subdomains/URLs from passive certificate transparency logs and archives.
pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<String>> {
    let domain = target.domain_or_ip();
    let mut found: HashSet<String> = HashSet::new();

    println!("\n{}", "┌─[ Passive Certificate Sources ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── crt.sh ────────────────────────────────────────────────
    if should_run("crt.sh") {
        println!("{}", "│  [*] Querying crt.sh...".white());
        match query_crtsh(&domain).await {
            Ok(subs) => {
                println!("{}  {} names from crt.sh", "│".bright_black(), subs.len().to_string().green());
                found.extend(subs);
            }
            Err(e) => {
                println!("{}  {} crt.sh error: {}", "│".bright_black(), "[-]".yellow(), e);
            }
        }
    }

    // ── certspotter ───────────────────────────────────────────
    if should_run("certspotter") {
        println!("{}", "│  [*] Querying certspotter...".white());
        match query_certspotter(&domain).await {
            Ok(subs) => {
                println!("{}  {} names from certspotter", "│".bright_black(), subs.len().to_string().green());
                found.extend(subs);
            }
            Err(e) => {
                println!("{}  {} certspotter error: {}", "│".bright_black(), "[-]".yellow(), e);
            }
        }
    }

    // ── gau ───────────────────────────────────────────────────
    if should_run("gau") {
        println!("{}", "│  [*] Running gau (GetAllURLs)...".white());
        if let Ok(out) = run_tool("gau", &["--subs", &domain]).await {
            let urls: Vec<String> = out
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            println!("{}  {} URLs via gau", "│".bright_black(), urls.len().to_string().green());
            for u in &urls {
                if let Ok(parsed) = url::Url::parse(u) {
                    if let Some(host) = parsed.host_str() {
                        if host.ends_with(&domain) {
                            found.insert(host.to_lowercase());
                        }
                    }
                }
            }
        }
    }

    let mut results: Vec<String> = found
        .into_iter()
        .filter(|s| s.contains(&domain) && !s.is_empty())
        .collect();
    results.sort();

    println!("{}", format!("└─[ ✓ Total unique passive hits: {} ]", results.len()).bright_green().bold());
    Ok(results)
}

/// Query the crt.sh JSON API for a given domain
async fn query_crtsh(domain: &str) -> anyhow::Result<Vec<String>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let entries: Vec<CrtEntry> = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?
        .json()
        .await?;

    let mut subs = HashSet::new();
    for entry in entries {
        for name in entry.name_value.lines() {
            let clean = name.trim().trim_start_matches('*').trim_start_matches('.').to_lowercase();
            if clean.ends_with(domain) {
                subs.insert(clean);
            }
        }
    }
    let mut v: Vec<String> = subs.into_iter().collect();
    v.sort();
    Ok(v)
}

/// Query certspotter API (unauthenticated tier)
async fn query_certspotter(domain: &str) -> anyhow::Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Entry {
        dns_names: Vec<String>,
    }

    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        domain
    );
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let entries: Vec<Entry> = client
        .get(&url)
        .send()
        .await?
        .json()
        .await?;

    let mut subs = HashSet::new();
    for entry in entries {
        for name in entry.dns_names {
            let clean = name.trim().to_lowercase();
            if clean.ends_with(domain) {
                subs.insert(clean);
            }
        }
    }
    let mut v: Vec<String> = subs.into_iter().collect();
    v.sort();
    Ok(v)
}
