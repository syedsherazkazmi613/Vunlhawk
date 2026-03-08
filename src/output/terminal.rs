// ============================================================
// output/terminal.rs — Pretty-printed terminal output
// ============================================================

use crate::core::correlation::CorrelatedResults;
use colored::*;
use comfy_table::{Table, ContentArrangement, Cell, Color, Attribute};
use std::time::Duration;

pub fn print_final_report(results: &CorrelatedResults, target: &str, duration: Duration) {
    println!("\n\n{}", "─".repeat(80).bright_black());
    println!("{} {}", "SCAN SUMMARY FOR:".bold(), target.yellow().bold());
    println!("{} {:.2?}", "Duration:".bold(), duration);
    println!("{}\n", "─".repeat(80).bright_black());

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Category").add_attribute(Attribute::Bold),
        Cell::new("Count").add_attribute(Attribute::Bold),
        Cell::new("Severity").add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec![
        Cell::new("SubdomainsFound").fg(Color::Cyan),
        Cell::new(results.subdomains_count.to_string()),
        Cell::new("Low"),
    ]);
    table.add_row(vec![
        Cell::new("Live Hosts").fg(Color::Green),
        Cell::new(results.live_hosts_count.to_string()),
        Cell::new("-"),
    ]);
    table.add_row(vec![
        Cell::new("Vulnerabilities").fg(Color::Red),
        Cell::new(results.vulnerabilities_count.to_string()),
        Cell::new(if results.critical_issues > 0 { "CRITICAL" } else { "INFO" }).fg(if results.critical_issues > 0 { Color::Red } else { Color::White }),
    ]);

    println!("{}", table);

    if !results.findings.vulnerabilities.is_empty() {
        println!("\n{}", "TOP VULNERABILITIES".red().bold());
        for v in results.findings.vulnerabilities.iter().take(10) {
            println!("  [{}] {} ({})", v.severity.to_uppercase().red(), v.name.white(), v.tool.bright_black());
        }
    }

    println!("\n{} Report saved to {} and {}", 
        "[+]".green().bold(),
        format!("vulnhawk_{}.json", target.replace(".", "_")).cyan(),
        format!("vulnhawk_{}.md", target.replace(".", "_")).cyan(),
    );
}
