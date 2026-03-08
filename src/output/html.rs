use crate::core::correlation::CorrelatedResults;
use std::fs::File;
use std::io::Write;
use colored::*;
use tinytemplate::TinyTemplate;
use serde::Serialize;
use chrono::Local;

static HTML_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnHawk Report - {target}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        {css_style}
    </style>
</head>
<body class="min-h-screen p-8">
    <div class="max-w-7xl mx-auto glass-panel rounded-2xl p-8 shadow-2xl">
        
        <!-- Header -->
        <div class="flex items-center justify-between border-b border-slate-700 pb-6 mb-8">
            <div class="flex items-center gap-4">
                <i class="fa-solid fa-shield-halved text-5xl text-cyan-400"></i>
                <div>
                    <h1 class="text-4xl font-bold text-white tracking-wider">VULNHAWK</h1>
                    <p class="text-slate-400 mt-1">Professional Security Assessment Report</p>
                </div>
            </div>
            <div class="text-right">
                <p class="text-xl font-semibold text-cyan-300">Target: {target}</p>
                <p class="text-slate-400 text-sm mt-1">Generated: {date}</p>
            </div>
        </div>

        <!-- Summary Widgets -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">
            <div class="glass-panel p-6 rounded-xl border-l-4 border-l-blue-500 hover:scale-105 transition-transform">
                <div class="flex justify-between items-center">
                    <div>
                        <p class="text-slate-400 font-medium">Subdomains</p>
                        <p class="text-3xl font-bold text-white mt-2">{subdomains}</p>
                    </div>
                    <i class="fa-solid fa-sitemap text-3xl text-blue-500 opacity-80"></i>
                </div>
            </div>
            <div class="glass-panel p-6 rounded-xl border-l-4 border-l-green-500 hover:scale-105 transition-transform">
                <div class="flex justify-between items-center">
                    <div>
                        <p class="text-slate-400 font-medium">Live Hosts</p>
                        <p class="text-3xl font-bold text-white mt-2">{live_hosts}</p>
                    </div>
                    <i class="fa-solid fa-server text-3xl text-green-500 opacity-80"></i>
                </div>
            </div>
            <div class="glass-panel p-6 rounded-xl border-l-4 border-l-red-500 hover:scale-105 transition-transform">
                <div class="flex justify-between items-center">
                    <div>
                        <p class="text-slate-400 font-medium">Critical Issues</p>
                        <p class="text-3xl font-bold text-white mt-2">{critical}</p>
                    </div>
                    <i class="fa-solid fa-skull-crossbones text-3xl text-red-500 opacity-80"></i>
                </div>
            </div>
            <div class="glass-panel p-6 rounded-xl border-l-4 border-l-purple-500 hover:scale-105 transition-transform">
                <div class="flex justify-between items-center">
                    <div>
                        <p class="text-slate-400 font-medium">Total Vulns</p>
                        <p class="text-3xl font-bold text-white mt-2">{vulns}</p>
                    </div>
                    <i class="fa-solid fa-bug text-3xl text-purple-500 opacity-80"></i>
                </div>
            </div>
        </div>

        <!-- Details Section -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            
            <!-- Vulnerabilities Section -->
            <div class="glass-panel rounded-xl overflow-hidden">
                <div class="bg-slate-800 px-6 py-4 border-b border-slate-700">
                    <h2 class="text-xl font-bold flex items-center gap-2">
                        <i class="fa-solid fa-fire text-orange-500"></i> Top Vulnerabilities
                    </h2>
                </div>
                <div class="p-6">
                    {{ if has_vulns }}
                    <ul class="space-y-4">
                        {{ for vuln in vuln_list }}
                        <li class="bg-slate-800/50 p-4 rounded-lg flex items-start gap-4 border border-slate-700/50 hover:bg-slate-800 transition-colors">
                            <span class="px-2 py-1 text-xs font-bold rounded bg-red-500/20 text-red-400 border border-red-500/30 mt-1">{vuln.severity}</span>
                            <div>
                                <p class="font-semibold text-white">{vuln.title}</p>
                                <p class="text-sm text-slate-400 mt-1">{vuln.desc}</p>
                            </div>
                        </li>
                        {{ endfor }}
                    </ul>
                    {{ else }}
                    <p class="text-slate-400 italic text-center py-8">No vulnerabilities discovered during this scan.</p>
                    {{ endif }}
                </div>
            </div>

            <!-- Recon Data Section -->
            <div class="glass-panel rounded-xl overflow-hidden">
                <div class="bg-slate-800 px-6 py-4 border-b border-slate-700">
                    <h2 class="text-xl font-bold flex items-center gap-2">
                        <i class="fa-solid fa-network-wired text-cyan-400"></i> Discovered Architecture
                    </h2>
                </div>
                <div class="p-6">
                    <div class="space-y-6">
                        <div>
                            <h3 class="text-sm font-bold text-slate-400 uppercase tracking-wider mb-3">Open Ports ({port_count})</h3>
                            <div class="flex flex-wrap gap-2">
                                {{ for port in port_list }}
                                <span class="bg-blue-500/20 text-blue-300 border border-blue-500/30 px-3 py-1 rounded-full text-sm font-mono">{port}</span>
                                {{ endfor }}
                            </div>
                        </div>

                        <div>
                            <h3 class="text-sm font-bold text-slate-400 uppercase tracking-wider mb-3">Sample Targets ({sample_host_count})</h3>
                            <ul class="space-y-2 font-mono text-sm">
                                {{ for host in sample_hosts }}
                                <li class="text-green-400 flex items-center gap-2">
                                    <i class="fa-solid fa-caret-right text-slate-500"></i> {host}
                                </li>
                                {{ endfor }}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

        </div>

        <div class="mt-12 text-center border-t border-slate-700 pt-6">
            <p class="text-slate-500 text-sm">VulnHawk Security Framework :: Generated Automatically :: Use Responsibly</p>
        </div>

    </div>
</body>
</html>
"#;

#[derive(Serialize)]
struct ReportContext {
    target: String,
    date: String,
    subdomains: usize,
    live_hosts: usize,
    vulns: usize,
    critical: usize,
    has_vulns: bool,
    vuln_list: Vec<VulnItem>,
    port_count: usize,
    port_list: Vec<String>,
    sample_host_count: usize,
    sample_hosts: Vec<String>,
    css_style: String,
}

#[derive(Serialize)]
struct VulnItem {
    severity: String,
    title: String,
    desc: String,
}

pub fn save_html_report(results: &CorrelatedResults, target: &str) -> anyhow::Result<()> {
    let safe_target = target.replace("://", "_").replace('.', "_").replace('/', "_");
    let filename = format!("vulnhawk_{}.html", safe_target);
    
    // Create reports directory if it doesn't exist
    std::fs::create_dir_all("reports")?;
    let report_path = std::path::Path::new("reports").join(&filename);

    let mut tt = TinyTemplate::new();
    tt.add_template("report", HTML_TEMPLATE)?;

    // Map vulnerabilities
    let mut mapped_vulns = Vec::new();
    for v in results.findings.vulnerabilities.iter().take(10) {
        mapped_vulns.push(VulnItem {
            severity: v.severity.clone().to_uppercase(),
            title: v.name.clone(),
            desc: v.description.clone(),
        });
    }

    // Map ports
    let mapped_ports: Vec<String> = results.findings.open_ports.iter().map(|p| p.to_string()).collect();

    // Map samples hosts (first 5)
    let sample_hosts: Vec<String> = results.findings.subdomains.iter().take(5).cloned().collect();

    let context = ReportContext {
        target: target.to_string(),
        date: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        subdomains: results.subdomains_count,
        live_hosts: results.live_hosts_count,
        vulns: results.vulnerabilities_count,
        critical: results.critical_issues,
        has_vulns: !mapped_vulns.is_empty(),
        vuln_list: mapped_vulns,
        port_count: mapped_ports.len(),
        port_list: mapped_ports,
        sample_host_count: sample_hosts.len(),
        sample_hosts,
        css_style: "body { background-color: #0f172a; color: #e2e8f0; } .glass-panel { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); }".to_string(),
    };

    let rendered = tt.render("report", &context)?;

    let mut file = File::create(&report_path)?;
    file.write_all(rendered.as_bytes())?;

    let full_path = std::env::current_dir()?.join(&report_path);
    println!("{} HTML Report saved to: {}", "[+]".green().bold(), full_path.display().to_string().cyan());
    Ok(())
}
