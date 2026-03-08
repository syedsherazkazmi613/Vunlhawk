// ============================================================
// modules/tech.rs — Technology Detection
// Tools: whatweb, wappalyzer (via httpx)
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechInfo {
    pub url: String,
    pub technologies: Vec<String>,
}

/// Detect technologies for a list of URLs
pub async fn run(_target: &TargetInfo, urls: &[String], tools: Option<Vec<String>>) -> anyhow::Result<Vec<TechInfo>> {
    let mut results = Vec::new();
    
    println!("\n{}", "┌─[ Technology Detection ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    for url in urls.iter().take(5) {
        println!("{}  [*] Checking {}...", "│".bright_black(), url);
        
        let mut tech_list = Vec::new();

        // ── httpx (tech detect) ───────────────────────────────────
        if should_run("httpx") {
            if let Ok(out) = run_tool("httpx", &[url, "-silent", "-tech-detect", "-no-color"]).await {
                if let Some(start) = out.find('[') {
                    if let Some(end) = out.rfind(']') {
                        let techs = &out[start + 1..end];
                        tech_list = techs.split(',').map(|s| s.trim().to_string()).collect();
                    }
                }
            }
        }
        
        tech_list.sort();
        tech_list.dedup();
        
        results.push(TechInfo {
            url: url.clone(),
            technologies: tech_list,
        });
    }

    println!("{}", format!("└─[ ✓ Technology scans mapping complete ]").bright_green().bold());
    Ok(results)
}
