// ============================================================
// core/correlation.rs — Merging and scoring engine
// ============================================================

use crate::core::runner::FullScanResults;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedResults {
    pub target: String,
    pub subdomains_count: usize,
    pub live_hosts_count: usize,
    pub vulnerabilities_count: usize,
    pub critical_issues: usize,
    pub findings: FullScanResults,
    pub confidence_score: u8,
}

pub fn correlate_results(raw: &FullScanResults) -> CorrelatedResults {
    let mut critical = 0;
    
    for v in &raw.vulnerabilities {
        if v.severity.to_lowercase() == "high" || v.severity.to_lowercase() == "critical" {
            critical += 1;
        }
    }

    CorrelatedResults {
        target: String::new(), // Set by handler
        subdomains_count: raw.subdomains.len(),
        live_hosts_count: raw.live_hosts.len(),
        vulnerabilities_count: raw.vulnerabilities.len(),
        critical_issues: critical,
        findings: raw.clone(),
        confidence_score: 85, // Static for now, can be calculated based on tool overlap
    }
}
