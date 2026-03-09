// ============================================================
// modules/cloud.rs — Cloud & Misconfiguration Checks
// Tools: cloud_enum, s3scanner, trufflehog
// ============================================================

use crate::core::parser::TargetInfo;
use crate::core::runner::run_tool;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudFinding {
    pub provider: String,
    pub resource: String,
    pub status: String,
}

pub async fn run(target: &TargetInfo, tools: Option<Vec<String>>) -> anyhow::Result<Vec<CloudFinding>> {
    let domain = target.domain_or_ip();
    let mut findings = Vec::new();

    println!("\n{}", "┌─[ Cloud & Misconfiguration ]".bright_cyan().bold());

    let should_run = |tool: &str| -> bool {
        tools.as_ref().map_or(true, |t| t.contains(&tool.to_string()))
    };

    // ── cloud_enum ────────────────────────────────────────────
    if should_run("cloud_enum") {
        println!("{}", "│  [*] Running cloud_enum...".white());
        if let Ok(out) = run_tool("cloud_enum", &["-k", &domain]).await {
            for line in out.lines() {
                if line.contains("FOUND") {
                    findings.push(CloudFinding {
                        provider: "Cloud".to_string(),
                        resource: line.trim().to_string(),
                        status: "detected".to_string(),
                    });
                }
            }
        }
    }

    // ── s3scanner ─────────────────────────────────────────────
    if should_run("s3scanner") {
        println!("{}", "│  [*] Running s3scanner...".white());
        if let Ok(out) = run_tool("s3scanner", &["scan", "--bucket", &domain]).await {
            if out.contains("found") || out.contains("exists") {
                findings.push(CloudFinding {
                    provider: "AWS S3".to_string(),
                    resource: domain.clone(),
                    status: "discovered".to_string(),
                });
            }
        }
    }

    // ── trufflehog ─────────────────────────────────────────────
    if should_run("trufflehog") {
        println!("{}", "│  [*] Running trufflehog (secrets)...".white());
        if let Ok(out) = run_tool("trufflehog", &["github", "--repo", &format!("https://github.com/{}", domain), "--only-verified"]).await {
            if !out.is_empty() {
                 findings.push(CloudFinding {
                    provider: "Secrets".to_string(),
                    resource: "Git Secrets (trufflehog)".to_string(),
                    status: "CRITICAL".to_string(),
                });
            }
        }
    }

    // ── gitleaks ───────────────────────────────────────────────
    if should_run("gitleaks") {
         println!("{}", "│  [*] Running gitleaks...".white());
         if let Ok(out) = run_tool("gitleaks", &["detect", "--source", &format!("https://github.com/{}", domain)]).await {
              if out.contains("leaks found") {
                  findings.push(CloudFinding {
                    provider: "Secrets".to_string(),
                    resource: "Git Leaks (gitleaks)".to_string(),
                    status: "HIGH".to_string(),
                });
              }
         }
    }

    println!("{}", format!("└─[ ✓ Cloud findings: {} ]", findings.len()).bright_green().bold());
    Ok(findings)
}
