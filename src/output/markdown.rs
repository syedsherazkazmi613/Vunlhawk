// ============================================================
// output/markdown.rs — Markdown reporting
// ============================================================

use crate::core::correlation::CorrelatedResults;
use std::fs::File;
use std::io::Write;
use chrono::Local;
use colored::*;

pub fn save_markdown_report(results: &CorrelatedResults, target: &str) -> anyhow::Result<()> {
    let filename = format!("vulnhawk_{}.md", target.replace(".", "_"));
    
    // Create reports directory
    std::fs::create_dir_all("reports")?;
    let report_path = std::path::Path::new("reports").join(&filename);

    let mut f = File::create(&report_path)?;
    writeln!(f, "# VulnHawk Scan Report: {}", target)?;
    writeln!(f, "Generated on: {}\n", Local::now().format("%Y-%m-%d %H:%M:%S"))?;

    writeln!(f, "## Summary")?;
    writeln!(f, "- **Subdomains:** {}", results.subdomains_count)?;
    writeln!(f, "- **Live Hosts:** {}", results.live_hosts_count)?;
    writeln!(f, "- **Vulnerabilities:** {}", results.vulnerabilities_count)?;
    writeln!(f, "- **Critical Issues:** {}\n", results.critical_issues)?;

    writeln!(f, "## Vulnerabilities")?;
    if results.findings.vulnerabilities.is_empty() {
        writeln!(f, "No vulnerabilities found.")?;
    } else {
        writeln!(f, "| Severity | Name | Tool | Description |")?;
        writeln!(f, "|----------|------|------|-------------|")?;
        for v in &results.findings.vulnerabilities {
            writeln!(f, "| {} | {} | {} | {} |", v.severity, v.name, v.tool, v.description)?;
        }
    }

    writeln!(f, "\n## Open Ports")?;
    writeln!(f, "{:?}\n", results.findings.open_ports)?;

    writeln!(f, "## Subdomains")?;
    for s in &results.findings.subdomains {
        writeln!(f, "- {}", s)?;
    }

    let full_path = std::env::current_dir()?.join(&report_path);
    println!("{} Markdown Report saved to: {}", "[+]".green().bold(), full_path.display().to_string().cyan());
    Ok(())
}
