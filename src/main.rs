// ============================================================
// VulnHawk - Professional Reconnaissance & Vulnerability Scanner
// main.rs — Entry point: banner, CLI dispatch, async runtime
// ============================================================

mod cli;
mod modules;
mod core;
mod output;

use cli::{Cli, Commands};
use clap::Parser;
use colored::*;

#[tokio::main]
async fn main() {
    // Initialize logger (controlled via RUST_LOG env var)
    env_logger::init();

    // Print the ASCII banner on every invocation
    print_banner();

    let cli = Cli::parse();

    // Dispatch to the correct subcommand handler
    let result = match &cli.command {
        Some(Commands::Scan { target, full, modules }) => {
            cli::handle_scan(target, *full, modules.clone()).await
        }
        Some(Commands::Subdomain { target }) => {
            cli::handle_subdomain(target).await
        }
        Some(Commands::Port { target }) => {
            cli::handle_port(target).await
        }
        Some(Commands::Dir { target }) => {
            cli::handle_dir(target).await
        }
        Some(Commands::Vuln { target }) => {
            cli::handle_vuln(target).await
        }
        Some(Commands::Dns { target }) => {
            cli::handle_dns(target).await
        }
        Some(Commands::Doctor) => {
            cli::handle_doctor().await
        }
        None => {
            cli::run_interactive().await
        }
    };

    if let Err(e) = result {
        eprintln!("{} {}", "[-] Fatal error:".red().bold(), e);
        std::process::exit(1);
    }
}

/// Print the VulnHawk ASCII art banner with version info
pub fn print_banner() {
    let hawk = r#"
           ___
      .---'   `---.
     /   VULNHAWK  \
    |    _______    |
    |   /       \   |
    |  |  (O) (O) |  |  
    |   \    ^    /   |
     \   '-----'   /
      '---.     .---'
           |   |
    "#;

    let text_art = r#"
      __     __      _         _   _                _    
      \ \   / /   _ | | _ __  | | | |  __ _ __      _| | __
       \ \ / / | | || || '_ \ | |_| | / _` |\ \ /\ / /| |/ /
        \ V /| |_| || || | | ||  _  || (_| | \ V  V / |   < 
         \_/  \__,_||_||_| |_||_| |_| \__,_|  \_/\_/  |_|\_\
    "#;

    println!("{}", hawk.cyan().bold());
    println!("{}", text_art.yellow().bold());
    println!("{}", "       v1.0.0 — Professional Recon & Vuln Framework".bright_white());
    println!("{}", "       by VulnHawk Team | Use responsibly & legally\n".bright_black());
    println!("{}", "─".repeat(80).bright_black());
    println!();
}
