// ============================================================
// modules/dns.rs — DNS enumeration
// Tools: dnsrecon, fierce, dnsenum, shuffledns
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use serde::{Deserialize, Serialize};

/// A single DNS record returned from any tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub source: String,
}

/// Run all DNS enumeration tools and return merged unique records
pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<DnsRecord>> {
    let domain = target.domain_or_ip();
    let mut records: Vec<DnsRecord> = Vec::new();

    println!("\n{}", "┌─[ DNS Enumeration ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── dnsrecon ──────────────────────────────────────────────
    if should_run("dnsrecon") {
        println!("{}", "│  [*] Running dnsrecon...".white());
        if let Ok(out) = run_tool("dnsrecon", &["-d", &domain, "-t", "std"]).await {
            let parsed = parse_dnsrecon(&out, &domain);
            println!("{}  {} DNS records via dnsrecon", "│".bright_black(), parsed.len().to_string().green());
            records.extend(parsed);
        }
    }

    // ── dnsx ──────────────────────────────────────────────────
    if should_run("dnsx") {
        println!("{}", "│  [*] Running dnsx (resolving)...".white());
        if let Ok(out) = run_tool("dnsx", &["-d", &domain, "-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp-all"]).await {
             for line in out.lines() {
                 let parts: Vec<&str> = line.split_whitespace().collect();
                 if parts.len() >= 2 {
                     records.push(DnsRecord {
                         record_type: "DNSX".to_string(), // dnsx output is complex, keeping raw for now
                         name: domain.clone(),
                         value: line.to_string(),
                         source: "dnsx".to_string(),
                     });
                 }
             }
        }
    }

    // ── puredns ────────────────────────────────────────────────
    if should_run("puredns") {
        println!("{}", "│  [*] Running puredns (resolve)...".white());
        if let Ok(out) = run_tool("puredns", &["resolve", &domain, "--quiet"]).await {
            for line in out.lines() {
                records.push(DnsRecord {
                    record_type: "A".to_string(),
                    name: domain.clone(),
                    value: line.trim().to_string(),
                    source: "puredns".to_string(),
                });
            }
        }
    }

    // ── shuffledns (resolve) ───────────────────────────────────
    if should_run("shuffledns") {
        println!("{}", "│  [*] Running shuffledns (resolve mode)...".white());
        if let Ok(out) = run_tool(
            "shuffledns",
            &["-d", &domain, "-r", "/usr/share/wordlists/resolvers.txt", "-silent"],
        )
        .await
        {
            let parsed = out
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| DnsRecord {
                    record_type: "A".to_string(),
                    name: l.trim().to_string(),
                    value: String::new(),
                    source: "shuffledns".to_string(),
                })
                .collect::<Vec<_>>();
            println!("{}  {} resolved via shuffledns", "│".bright_black(), parsed.len().to_string().green());
            records.extend(parsed);
        }
    }

    // Deduplicate on (type, name, value)
    records.sort_by(|a, b| a.name.cmp(&b.name));
    records.dedup_by(|a, b| a.record_type == b.record_type && a.name == b.name && a.value == b.value);

    println!("{}", format!("└─[ ✓ Total DNS records: {} ]", records.len()).bright_green().bold());
    Ok(records)
}

// ─── Output parsers ───────────────────────────────────────────

/// Parse dnsrecon stdout into DnsRecord entries
fn parse_dnsrecon(raw: &str, _domain: &str) -> Vec<DnsRecord> {
    let mut out = Vec::new();
    for line in raw.lines() {
        // Typical line: "[*] A example.com 93.184.216.34"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let rtype = parts[1].to_uppercase();
            if matches!(rtype.as_str(), "A" | "AAAA" | "MX" | "NS" | "TXT" | "CNAME" | "SOA" | "SRV") {
                out.push(DnsRecord {
                    record_type: rtype,
                    name: parts[2].to_string(),
                    value: parts[3].to_string(),
                    source: "dnsrecon".to_string(),
                });
            }
        }
    }
    out
}
