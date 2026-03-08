// ============================================================
// core/parser.rs — Target detection and resolution
// ============================================================

use trust_dns_resolver::TokioAsyncResolver;
use url::Url;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum TargetType {
    Domain(String),
    IP(IpAddr),
    URL(Url),
}

#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub raw: String,
    pub detected_type: TargetType,
    #[allow(dead_code)]
    pub resolved_ips: Vec<IpAddr>,
}

impl TargetInfo {
    pub async fn detect(input: &str) -> anyhow::Result<Self> {
        let input = input.trim();
        
        let detected_type = if let Ok(url) = Url::parse(input) {
            TargetType::URL(url)
        } else if let Ok(ip) = input.parse::<IpAddr>() {
            TargetType::IP(ip)
        } else {
            TargetType::Domain(input.to_string())
        };

        let mut resolved_ips = Vec::new();
        match &detected_type {
            TargetType::Domain(d) => {
                let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
                if let Ok(lookup) = resolver.lookup_ip(d).await {
                    resolved_ips = lookup.iter().collect();
                }
            }
            TargetType::IP(ip) => {
                resolved_ips.push(*ip);
            }
            TargetType::URL(u) => {
                if let Some(host) = u.host_str() {
                    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
                    if let Ok(lookup) = resolver.lookup_ip(host).await {
                        resolved_ips = lookup.iter().collect();
                    }
                }
            }
        }

        Ok(Self {
            raw: input.to_string(),
            detected_type,
            resolved_ips,
        })
    }

    pub fn domain_or_ip(&self) -> String {
        match &self.detected_type {
            TargetType::Domain(d) => d.clone(),
            TargetType::IP(ip) => ip.to_string(),
            TargetType::URL(u) => u.host_str().unwrap_or(&self.raw).to_string(),
        }
    }

    pub fn url(&self) -> Option<&str> {
        match &self.detected_type {
            TargetType::URL(_) => Some(&self.raw),
            _ => None,
        }
    }
}
