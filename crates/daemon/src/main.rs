use clap::{Parser, Subcommand};
use database::{CacheDatabase, ThreatDatabase};
use notifier::MacOSNotifier;
use scanner::ScannerEngine;
use shared::Config;
use std::fs;
use std::path::PathBuf;
use std::process;
use tokio::sync::broadcast;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod daemon;
mod signals;
mod watcher;

use daemon::Daemon;
use watcher::FileWatcher;

#[derive(Parser)]
#[command(name = "supplyguard")]
#[command(about = "SupplyGuard: Real-time supply chain attack detection daemon")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon
    Start,
    /// Stop the daemon
    Stop,
    /// Show daemon status
    Status,
    /// Manually scan a directory
    Scan {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// List all detected threats
    Threats {
        #[arg(short, long, default_value = "10")]
        limit: i32,
    },
    /// Manage quarantined files
    Quarantine {
        #[command(subcommand)]
        cmd: QuarantineCommands,
    },
    /// Manage whitelist
    Whitelist {
        #[command(subcommand)]
        cmd: WhitelistCommands,
    },
    /// Show configuration
    Config {
        #[command(subcommand)]
        cmd: ConfigCommands,
    },
    /// Install as launchd daemon
    Install,
    /// Uninstall launchd daemon
    Uninstall,
}

#[derive(Subcommand)]
enum QuarantineCommands {
    /// List quarantined files
    List,
    /// Restore file from quarantine
    Restore {
        #[arg(value_name = "ID")]
        id: i64,
    },
}

#[derive(Subcommand)]
enum WhitelistCommands {
    /// Add path pattern to whitelist
    Add {
        #[arg(value_name = "PATTERN")]
        pattern: String,
        #[arg(short, long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Initialize default configuration
    Init,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    match cli.command {
        Commands::Start => {
            if let Err(e) = start_daemon().await {
                error!("Failed to start daemon: {}", e);
                process::exit(1);
            }
        }
        Commands::Stop => {
            if let Err(e) = stop_daemon().await {
                error!("Failed to stop daemon: {}", e);
                process::exit(1);
            }
        }
        Commands::Status => {
            if let Err(e) = show_status().await {
                error!("Failed to get status: {}", e);
                process::exit(1);
            }
        }
        Commands::Scan { path } => {
            if let Err(e) = scan_directory(path).await {
                error!("Failed to scan: {}", e);
                process::exit(1);
            }
        }
        Commands::Threats { limit } => {
            if let Err(e) = list_threats(limit).await {
                error!("Failed to list threats: {}", e);
                process::exit(1);
            }
        }
        Commands::Quarantine { cmd } => {
            match cmd {
                QuarantineCommands::List => {
                    if let Err(e) = list_quarantined().await {
                        error!("Failed to list quarantined files: {}", e);
                        process::exit(1);
                    }
                }
                QuarantineCommands::Restore { id } => {
                    if let Err(e) = restore_quarantined(id).await {
                        error!("Failed to restore file: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        Commands::Whitelist { cmd } => {
            match cmd {
                WhitelistCommands::Add { pattern, reason } => {
                    if let Err(e) = add_whitelist(pattern, reason).await {
                        error!("Failed to add whitelist entry: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        Commands::Config { cmd } => {
            match cmd {
                ConfigCommands::Show => {
                    if let Err(e) = show_config().await {
                        error!("Failed to show config: {}", e);
                        process::exit(1);
                    }
                }
                ConfigCommands::Init => {
                    if let Err(e) = init_config().await {
                        error!("Failed to init config: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        Commands::Install => {
            if let Err(e) = install_daemon().await {
                error!("Failed to install: {}", e);
                process::exit(1);
            }
        }
        Commands::Uninstall => {
            if let Err(e) = uninstall_daemon().await {
                error!("Failed to uninstall: {}", e);
                process::exit(1);
            }
        }
    }
}

async fn start_daemon() -> anyhow::Result<()> {
    // Check if already running
    if let Ok(pid) = read_pid_file() {
        if is_process_running(pid) {
            info!("Daemon already running with PID {}", pid);
            return Ok(());
        }
    }

    // Load config
    let config = Config::load()?;

    // Initialize database
    let db_path = config.database_path();
    let threat_db = std::sync::Arc::new(ThreatDatabase::new(&db_path)?);
    let cache_db = std::sync::Arc::new(CacheDatabase::new(&db_path)?);

    // Initialize scanner
    let scanner = std::sync::Arc::new(ScannerEngine::new(config.scanning.max_file_size_mb));

    // Initialize notifier
    let notifier = std::sync::Arc::new(MacOSNotifier::new(
        config.notifications.enabled,
        config.min_notification_severity(),
    ));

    // Create event channel
    let (event_tx, event_rx) = async_channel::unbounded();

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    // Setup signal handlers
    signals::setup_shutdown_handler(shutdown_tx.clone())?;

    // Create watcher
    let watcher = FileWatcher::new(event_tx.clone(), config.monitoring.ignored_paths.clone());
    let watch_paths = config.expand_paths();
    watcher.watch_paths(watch_paths).await?;

    // Write PID file
    write_pid_file()?;

    // Create and run daemon
    let mut daemon = Daemon::new(
        config,
        scanner,
        threat_db,
        cache_db,
        notifier,
        event_rx,
        shutdown_rx,
    );

    // Run daemon (blocks until shutdown)
    daemon.run().await?;

    // Cleanup
    remove_pid_file()?;
    watcher.stop().await;

    Ok(())
}

async fn stop_daemon() -> anyhow::Result<()> {
    let pid = read_pid_file()?;
    
    if !is_process_running(pid) {
        info!("Daemon is not running");
        remove_pid_file()?;
        return Ok(());
    }

    // Send SIGTERM
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }

    // Wait for process to exit
    for _ in 0..10 {
        if !is_process_running(pid) {
            remove_pid_file()?;
            info!("Daemon stopped");
            return Ok(());
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    // Force kill if still running
    if is_process_running(pid) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        remove_pid_file()?;
        info!("Daemon force killed");
    }

    Ok(())
}

async fn show_status() -> anyhow::Result<()> {
    let pid = read_pid_file().ok();
    let is_running = pid.map(|p| is_process_running(p)).unwrap_or(false);

    println!("Status: {}", if is_running { "Running" } else { "Stopped" });
    
    if let Some(pid) = pid {
        println!("PID: {}", pid);
    }

    // Show statistics
    let config = Config::load()?;
    let db_path = config.database_path();
    let threat_db = ThreatDatabase::new(&db_path)?;
    let (total, unresolved, quarantined) = threat_db.get_statistics()?;

    println!("\nStatistics:");
    println!("  Total threats detected: {}", total);
    println!("  Unresolved threats: {}", unresolved);
    println!("  Quarantined files: {}", quarantined);

    Ok(())
}

async fn scan_directory(path: PathBuf) -> anyhow::Result<()> {
    let config = Config::load()?;
    let scanner = ScannerEngine::new(config.scanning.max_file_size_mb);
    
    println!("Scanning {}...", path.display());
    let results = scanner.scan_directory(&path).await?;

    let mut threat_count = 0;
    for result in results {
        if !result.is_clean {
            threat_count += result.threats.len();
            println!("\n⚠️  Threats found in {}:", result.path.display());
            for threat in result.threats {
                println!("  [{}] {}: {}", threat.severity.as_str(), threat.threat_type.as_str(), threat.context);
            }
        }
    }

    if threat_count == 0 {
        println!("✓ No threats found");
    } else {
        println!("\nTotal threats: {}", threat_count);
    }

    Ok(())
}

async fn list_threats(limit: i32) -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let threat_db = ThreatDatabase::new(&db_path)?;
    let threats = threat_db.get_recent_threats(limit)?;

    if threats.is_empty() {
        println!("No threats found");
        return Ok(());
    }

    println!("Recent threats:");
    for threat in threats {
        println!("\n[{}] {}", threat.severity.as_str(), threat.threat_type.as_str());
        println!("  File: {}", threat.file_path.display());
        println!("  Pattern: {}", threat.pattern_name);
        println!("  Context: {}", threat.context);
        println!("  Time: {}", threat.timestamp.format("%Y-%m-%d %H:%M:%S"));
    }

    Ok(())
}

async fn list_quarantined() -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let threat_db = ThreatDatabase::new(&db_path)?;
    let quarantined = threat_db.get_quarantined()?;

    if quarantined.is_empty() {
        println!("No quarantined files");
        return Ok(());
    }

    println!("Quarantined files:");
    for (id, original, quarantine, threat_id) in quarantined {
        println!("\nID: {}", id);
        println!("  Original: {}", original.display());
        println!("  Quarantine: {}", quarantine.display());
        if let Some(tid) = threat_id {
            println!("  Threat ID: {}", tid);
        }
    }

    Ok(())
}

async fn restore_quarantined(id: i64) -> anyhow::Result<()> {
    println!("Restore functionality not yet implemented");
    Ok(())
}

async fn add_whitelist(pattern: String, reason: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let threat_db = ThreatDatabase::new(&db_path)?;
    threat_db.add_whitelist(&pattern, reason.as_deref())?;
    println!("Added whitelist pattern: {}", pattern);
    Ok(())
}

async fn show_config() -> anyhow::Result<()> {
    let config = Config::load()?;
    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

async fn init_config() -> anyhow::Result<()> {
    let config = Config::default();
    config.save()?;
    println!("Configuration initialized at {}", Config::config_path()?.display());
    Ok(())
}

async fn install_daemon() -> anyhow::Result<()> {
    println!("Install functionality - use install.sh script");
    Ok(())
}

async fn uninstall_daemon() -> anyhow::Result<()> {
    println!("Uninstall functionality - use uninstall.sh script");
    Ok(())
}

fn pid_file_path() -> PathBuf {
    PathBuf::from("/tmp/supplyguard.pid")
}

fn read_pid_file() -> anyhow::Result<i32> {
    let pid_str = fs::read_to_string(pid_file_path())?;
    Ok(pid_str.trim().parse()?)
}

fn write_pid_file() -> anyhow::Result<()> {
    let pid = process::id() as i32;
    fs::write(pid_file_path(), pid.to_string())?;
    Ok(())
}

fn remove_pid_file() -> anyhow::Result<()> {
    let _ = fs::remove_file(pid_file_path());
    Ok(())
}

fn is_process_running(pid: i32) -> bool {
    unsafe {
        libc::kill(pid, 0) == 0
    }
}
