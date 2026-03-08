// ============================================================
// output/json.rs — JSON reporting
// ============================================================

use crate::core::correlation::CorrelatedResults;
use std::fs::File;
use std::io::Write;
use colored::*;

pub fn save_json_report(results: &CorrelatedResults, target: &str) -> anyhow::Result<()> {
    let filename = format!("vulnhawk_{}.json", target.replace(".", "_"));
    
    // Create reports directory
    std::fs::create_dir_all("reports")?;
    let report_path = std::path::Path::new("reports").join(&filename);

    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(&report_path)?;
    file.write_all(json.as_bytes())?;

    let full_path = std::env::current_dir()?.join(&report_path);
    println!("{} JSON Report saved to: {}", "[+]".green().bold(), full_path.display().to_string().cyan());
    Ok(())
}
