use clap::{Parser, Subcommand};
use database::{CacheDatabase, ThreatDatabase};
use notifier::MacOSNotifier;
use scanner::ScannerEngine;
use shared::Config;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
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
    /// Scan a package before installation
    ScanPackage {
        #[arg(value_name = "MANAGER")]
        manager: String,
        #[arg(value_name = "PACKAGE")]
        package: String,
        #[arg(value_name = "VERSION")]
        version: Option<String>,
    },
    /// Manage package manager interception
    Intercept {
        #[command(subcommand)]
        cmd: InterceptCommands,
    },
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

#[derive(Subcommand)]
enum InterceptCommands {
    /// Enable package manager interception
    Enable,
    /// Disable package manager interception
    Disable,
    /// Show interception status
    Status,
}

fn print_logo() {
    println!("\x1b[36m");
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║                                                           ║");
    println!("  ║   \x1b[1m\x1b[33m███████╗██╗   ██╗██████╗ ██╗     ██╗    ██╗\x1b[0m\x1b[36m   ║");
    println!("  ║   \x1b[1m\x1b[33m██╔════╝██║   ██║██╔══██╗██║     ██║    ██║\x1b[0m\x1b[36m   ║");
    println!("  ║   \x1b[1m\x1b[33m███████╗██║   ██║██████╔╝██║     ██║ █╗ ██║\x1b[0m\x1b[36m   ║");
    println!("  ║   \x1b[1m\x1b[33m╚════██║██║   ██║██╔═══╝ ██║     ██║███╗██║\x1b[0m\x1b[36m   ║");
    println!("  ║   \x1b[1m\x1b[33m███████║╚██████╔╝██║     ███████╗╚███╔███╔╝\x1b[0m\x1b[36m   ║");
    println!("  ║   \x1b[1m\x1b[33m╚══════╝ ╚═════╝ ╚═╝     ╚══════╝ ╚══╝╚══╝ \x1b[0m\x1b[36m   ║");
    println!("  ║                                                           ║");
    println!("  ║   \x1b[32m🛡️  Supply Chain Attack Detection & Protection\x1b[0m\x1b[36m   ║");
    println!("  ║   \x1b[90m              Real-time Threat Monitoring\x1b[0m\x1b[36m              ║");
    println!("  ║                                                           ║");
    println!("  ╚═══════════════════════════════════════════════════════════╝");
    println!("\x1b[0m");
}

#[tokio::main]
async fn main() {
    // Set up panic handler to log panics
    std::panic::set_hook(Box::new(|panic_info| {
        error!("PANIC: {}", panic_info);
        eprintln!("PANIC: {:?}", panic_info);
    }));

    let cli = Cli::parse();

    // Initialize logging with colors - ensure it writes to stderr (which launchd captures)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(true) // Enable ANSI colors
        .with_target(true)
        .with_level(true)
        .with_file(true)
        .with_line_number(true)
        .init();
    
    // Force flush stderr to ensure logs are written immediately
    use std::io::Write;
    let _ = std::io::stderr().flush();
    
    // Print logo for interactive commands (not when running as daemon)
    match &cli.command {
        Commands::Start => {
            // Don't print logo when starting daemon (runs in background)
        }
        _ => {
            print_logo();
        }
    }
    
    // Log immediately to verify logging works
    eprintln!("=== SupplyGuard starting ===");
    eprintln!("PID: {}", std::process::id());
    eprintln!("About to call info! macro...");
    info!("SupplyGuard daemon process starting (PID: {})", std::process::id());
    eprintln!("info! macro called, entering match statement...");

    match cli.command {
        Commands::Start => {
            eprintln!("Command: Start - about to call start_daemon()");
            info!("Starting SupplyGuard daemon...");
            eprintln!("Calling start_daemon().await...");
            match start_daemon().await {
                Ok(()) => {
                    info!("Daemon exited normally");
                    process::exit(0);
                }
                Err(e) => {
                    error!("Failed to start daemon: {}", e);
                    process::exit(1);
                }
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
        Commands::ScanPackage { manager, package, version } => {
            if let Err(e) = scan_package(manager, package, version).await {
                error!("Failed to scan package: {}", e);
                process::exit(1);
            }
        }
        Commands::Intercept { cmd } => {
            match cmd {
                InterceptCommands::Enable => {
                    if let Err(e) = enable_interception().await {
                        error!("Failed to enable interception: {}", e);
                        process::exit(1);
                    }
                }
                InterceptCommands::Disable => {
                    if let Err(e) = disable_interception().await {
                        error!("Failed to disable interception: {}", e);
                        process::exit(1);
                    }
                }
                InterceptCommands::Status => {
                    if let Err(e) = show_intercept_status().await {
                        error!("Failed to show interception status: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
    }
}

async fn start_daemon() -> anyhow::Result<()> {
    eprintln!("start_daemon() called");
    info!("=== SupplyGuard daemon startup beginning ===");
    eprintln!("About to check PID file...");
    
    // Check if already running
    eprintln!("Calling read_pid_file()...");
    match read_pid_file() {
        Ok(pid) => {
            eprintln!("PID file found, PID: {}", pid);
            eprintln!("Checking if process is running...");
            if is_process_running(pid) {
                eprintln!("Process {} is already running", pid);
                info!("Daemon already running with PID {}", pid);
                return Ok(());
            }
            // Stale PID file from a previous crash/exit
            eprintln!("Process {} is not running, removing stale PID file", pid);
            info!("Removing stale PID file");
            remove_pid_file()?;
        }
        Err(e) => {
            eprintln!("No PID file found (or error reading): {}", e);
            // This is fine - no existing daemon
        }
    }
    eprintln!("PID file check complete, continuing startup...");

    info!("Loading configuration...");
    eprintln!("About to call Config::load()...");
    // Load config
    let config = Config::load()?;
    eprintln!("Config loaded successfully");
    info!("Configuration loaded successfully");

    // Initialize database
    info!("Initializing databases at: {}", config.database_path().display());
    eprintln!("About to initialize threat database...");
    let db_path = config.database_path();
    let threat_db = std::sync::Arc::new(ThreatDatabase::new(&db_path)?);
    eprintln!("Threat database initialized");
    info!("Threat database initialized");
    eprintln!("About to initialize cache database...");
    let cache_db = std::sync::Arc::new(CacheDatabase::new(&db_path)?);
    eprintln!("Cache database initialized");
    info!("Cache database initialized");

    // Initialize scanner
    eprintln!("About to initialize scanner...");
    let scanner = std::sync::Arc::new(ScannerEngine::new(config.scanning.max_file_size_mb));
    eprintln!("Scanner initialized");

    // Initialize notifier
    eprintln!("About to initialize notifier...");
    let notifier = std::sync::Arc::new(MacOSNotifier::new(
        config.notifications.enabled,
        config.min_notification_severity(),
    ));
    eprintln!("Notifier initialized");

    // Create event channel
    let (event_tx, event_rx) = async_channel::unbounded();

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    // Setup signal handlers
    info!("Setting up signal handlers...");
    eprintln!("About to set up signal handlers...");
    signals::setup_shutdown_handler(shutdown_tx.clone())?;
    eprintln!("Signal handlers set up successfully");
    info!("Signal handlers set up successfully");

    // Create watcher
    eprintln!("About to create file watcher...");
    let watcher = FileWatcher::new(event_tx.clone(), config.monitoring.ignored_paths.clone());
    eprintln!("File watcher created, about to watch paths...");
    let watch_paths = config.expand_paths();
    eprintln!("Got {} paths to watch", watch_paths.len());
    if let Err(e) = watcher.watch_paths(watch_paths).await {
        // Don't fail startup if watching fails - daemon can still do manual scans
        eprintln!("Failed to set up file watching: {}", e);
        warn!("Failed to set up file watching: {}. Daemon will continue without automatic monitoring.", e);
    } else {
        eprintln!("File watching set up successfully");
    }
    
    // Force flush to ensure logs are written
    use std::io::Write;
    let _ = std::io::stderr().flush();
    eprintln!("Flushed stderr, continuing to PID file writing...");

    // Write PID file
    info!("Writing PID file...");
    eprintln!("About to write PID file...");
    write_pid_file()?;
    eprintln!("PID file written successfully");
    info!("PID file written: {} (PID: {})", pid_file_path().display(), std::process::id());

    // Create and run daemon
    eprintln!("About to create Daemon struct...");
    let mut daemon = Daemon::new(
        config,
        scanner,
        threat_db,
        cache_db,
        notifier,
        event_rx,
        shutdown_rx,
    );
    eprintln!("Daemon struct created successfully");

    info!("=== About to enter daemon.run() - this should block forever ===");
    eprintln!("About to call daemon.run().await - this should block forever...");
    // Run daemon (blocks until shutdown)
    // This should block forever until shutdown signal is received
    match daemon.run().await {
        Ok(()) => {
            info!("Daemon main loop exited normally");
        }
        Err(e) => {
            error!("Daemon run() returned error: {}. Attempting to keep daemon alive...", e);
            // Don't exit immediately - wait a bit to see if it recovers
            // In production, you might want to restart instead
            warn!("Daemon will attempt to continue running despite error");
            tokio::time::sleep(Duration::from_secs(5)).await;
            // Return error but don't crash - let launchd restart if needed
            return Err(e);
        }
    }
    info!("Daemon main loop exited - this should only happen on shutdown");

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
    
    // Check if process is running - try multiple methods for reliability
    let is_running = if let Some(pid) = pid {
        // Method 1: Direct PID check
        let pid_running = is_process_running(pid);
        
        // Method 2: Check via launchctl (for system LaunchDaemons)
        let launchctl_running = std::process::Command::new("launchctl")
            .args(&["print", "system/com.supplyguard.daemon"])
            .output()
            .map(|output| {
                if output.status.success() {
                    // Parse output to check if PID matches
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    output_str.contains(&format!("pid = {}", pid))
                } else {
                    false
                }
            })
            .unwrap_or(false);
        
        // Method 3: Check if any supplyguard process is running
        let ps_running = std::process::Command::new("pgrep")
            .args(&["-f", "supplyguard start"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        
        pid_running || launchctl_running || ps_running
    } else {
        // No PID file - check if process exists anyway
        std::process::Command::new("pgrep")
            .args(&["-f", "supplyguard start"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    };

    // Colored status output
    let status_color = if is_running { "\x1b[32m" } else { "\x1b[31m" }; // Green for Running, Red for Stopped
    let reset_color = "\x1b[0m";
    let status_text = if is_running { "Running" } else { "Stopped" };
    println!("Status: {}{}{}", status_color, status_text, reset_color);
    
    if let Some(pid) = pid {
        println!("PID: \x1b[36m{}\x1b[0m", pid); // Cyan for PID
    }

    // Show statistics with colors
    let config = Config::load()?;
    let db_path = config.database_path();
    let threat_db = ThreatDatabase::new(&db_path)?;
    let (total, unresolved, quarantined) = threat_db.get_statistics()?;

    println!("\n\x1b[1mStatistics:\x1b[0m"); // Bold for "Statistics"
    println!("  Total threats detected: \x1b[33m{}\x1b[0m", total); // Yellow
    println!("  Unresolved threats: \x1b[31m{}\x1b[0m", unresolved); // Red
    println!("  Quarantined files: \x1b[35m{}\x1b[0m", quarantined); // Magenta

    Ok(())
}

async fn scan_directory(path: PathBuf) -> anyhow::Result<()> {
    let config = Config::load()?;
    let scanner = ScannerEngine::new(config.scanning.max_file_size_mb);
    
    println!("\x1b[36mScanning {}...\x1b[0m", path.display()); // Cyan
    let results = scanner.scan_directory(&path).await?;

    let mut threat_count = 0;
    for result in results {
        if !result.is_clean {
            threat_count += result.threats.len();
            println!("\n\x1b[31m⚠️  Threats found in {}:\x1b[0m", result.path.display()); // Red
            for threat in result.threats {
                let severity_color = match threat.severity {
                    shared::Severity::Critical => "\x1b[31m", // Red
                    shared::Severity::High => "\x1b[33m",     // Yellow
                    shared::Severity::Medium => "\x1b[35m",  // Magenta
                    shared::Severity::Low => "\x1b[36m",      // Cyan
                };
                println!("  [{}] {}: {}", 
                    format!("{}{}\x1b[0m", severity_color, threat.severity.as_str()),
                    threat.threat_type.as_str(), 
                    threat.context);
            }
        }
    }

    if threat_count == 0 {
        println!("\x1b[32m✓ No threats found\x1b[0m"); // Green
    } else {
        println!("\n\x1b[1mTotal threats: \x1b[31m{}\x1b[0m", threat_count); // Bold + Red
    }

    Ok(())
}

async fn list_threats(limit: i32) -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let threat_db = ThreatDatabase::new(&db_path)?;
    let threats = threat_db.get_recent_threats(limit)?;

    if threats.is_empty() {
        println!("\x1b[32mNo threats found\x1b[0m"); // Green
        return Ok(());
    }

    println!("\x1b[1mRecent threats:\x1b[0m"); // Bold
    for threat in threats {
        let severity_color = match threat.severity {
            shared::Severity::Critical => "\x1b[31m", // Red
            shared::Severity::High => "\x1b[33m",     // Yellow
            shared::Severity::Medium => "\x1b[35m",  // Magenta
            shared::Severity::Low => "\x1b[36m",      // Cyan
        };
        println!("\n[{}] \x1b[1m{}\x1b[0m", 
            format!("{}{}\x1b[0m", severity_color, threat.severity.as_str()),
            threat.threat_type.as_str());
        println!("  \x1b[36mFile:\x1b[0m {}", threat.file_path.display()); // Cyan label
        println!("  \x1b[36mPattern:\x1b[0m {}", threat.pattern_name);
        println!("  \x1b[36mContext:\x1b[0m {}", threat.context);
        println!("  \x1b[36mTime:\x1b[0m {}", threat.timestamp.format("%Y-%m-%d %H:%M:%S"));
    }

    Ok(())
}

async fn list_quarantined() -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let threat_db = ThreatDatabase::new(&db_path)?;
    let quarantined = threat_db.get_quarantined()?;

    if quarantined.is_empty() {
        println!("\x1b[32mNo quarantined files\x1b[0m"); // Green
        return Ok(());
    }

    println!("\x1b[1mQuarantined files:\x1b[0m"); // Bold
    for (id, original, quarantine, threat_id) in quarantined {
        println!("\n\x1b[33mID:\x1b[0m {}", id); // Yellow label
        println!("  \x1b[36mOriginal:\x1b[0m {}", original.display()); // Cyan label
        println!("  \x1b[35mQuarantine:\x1b[0m {}", quarantine.display()); // Magenta label
        if let Some(tid) = threat_id {
            println!("  \x1b[31mThreat ID:\x1b[0m {}", tid); // Red label
        }
    }

    Ok(())
}

async fn restore_quarantined(_id: i64) -> anyhow::Result<()> {
    println!("Restore functionality not yet implemented");
    Ok(())
}

async fn add_whitelist(pattern: String, reason: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let threat_db = ThreatDatabase::new(&db_path)?;
    threat_db.add_whitelist(&pattern, reason.as_deref())?;
    println!("\x1b[32m✓ Added whitelist pattern:\x1b[0m \x1b[36m{}\x1b[0m", pattern); // Green checkmark, cyan pattern
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
    println!("\x1b[32m✓ Configuration initialized at\x1b[0m \x1b[36m{}\x1b[0m", Config::config_path()?.display()); // Green checkmark, cyan path
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

async fn scan_package(manager: String, package: String, version: Option<String>) -> anyhow::Result<()> {
    use scanner::{PackageScanner, PackageManager as PM};
    
    let pm = PM::from_str(&manager)
        .ok_or_else(|| anyhow::anyhow!("Unknown package manager: {}. Supported: npm, pip, cargo", manager))?;
    
    let scanner = PackageScanner::new();
    let threats = scanner.scan_package(pm, &package, version.as_deref()).await
        .map_err(|e| anyhow::anyhow!("Package scan failed: {}", e))?;
    
    if threats.is_empty() {
        println!("\x1b[32m✓ Package is clean - no threats detected\x1b[0m");
        Ok(())
    } else {
        println!("\x1b[31m✗ Found {} threat(s) in package:\x1b[0m", threats.len());
        for threat in &threats {
            println!("  \x1b[33m[{}]\x1b[0m {}: {}", 
                match threat.severity {
                    shared::Severity::Critical => "\x1b[31mCRITICAL\x1b[0m",
                    shared::Severity::High => "\x1b[33mHIGH\x1b[0m",
                    shared::Severity::Medium => "\x1b[35mMEDIUM\x1b[0m",
                    shared::Severity::Low => "\x1b[36mLOW\x1b[0m",
                },
                threat.pattern_name,
                threat.context
            );
            if let Some(line) = threat.line_number {
                println!("    Line {}: {}", line, threat.matched_pattern);
            }
            println!("    Remediation: {}", threat.remediation);
        }
        Err(anyhow::anyhow!("Package contains threats"))
    }
}

async fn enable_interception() -> anyhow::Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    
    let wrapper_dir = PathBuf::from("/usr/local/bin");
    fs::create_dir_all(&wrapper_dir)?;
    
    // Create wrapper scripts
    let npm_wrapper = wrapper_dir.join("npm");
    let pip_wrapper = wrapper_dir.join("pip");
    let cargo_wrapper = wrapper_dir.join("cargo");
    
    // Create npm wrapper
    let npm_script = include_str!("wrappers/npm.sh");
    fs::write(&npm_wrapper, npm_script)?;
    fs::set_permissions(&npm_wrapper, fs::Permissions::from_mode(0o755))?;
    
    // Create pip wrapper
    let pip_script = include_str!("wrappers/pip.sh");
    fs::write(&pip_wrapper, pip_script)?;
    fs::set_permissions(&pip_wrapper, fs::Permissions::from_mode(0o755))?;
    
    // Create cargo wrapper
    let cargo_script = include_str!("wrappers/cargo.sh");
    fs::write(&cargo_wrapper, cargo_script)?;
    fs::set_permissions(&cargo_wrapper, fs::Permissions::from_mode(0o755))?;
    
    // Update shell configs to prepend /usr/local/bin to PATH
    update_shell_path(true)?;
    
    println!("\x1b[32m✓ Package manager interception enabled\x1b[0m");
    println!("  Wrappers installed to /usr/local/bin");
    println!("  Please restart your shell or run: source ~/.zshrc (or ~/.bashrc)");
    
    Ok(())
}

async fn disable_interception() -> anyhow::Result<()> {
    use std::fs;
    
    let wrapper_dir = PathBuf::from("/usr/local/bin");
    
    // Remove wrapper scripts
    let npm_wrapper = wrapper_dir.join("npm");
    let pip_wrapper = wrapper_dir.join("pip");
    let cargo_wrapper = wrapper_dir.join("cargo");
    
    if npm_wrapper.exists() {
        fs::remove_file(&npm_wrapper)?;
    }
    if pip_wrapper.exists() {
        fs::remove_file(&pip_wrapper)?;
    }
    if cargo_wrapper.exists() {
        fs::remove_file(&cargo_wrapper)?;
    }
    
    // Remove PATH modifications
    update_shell_path(false)?;
    
    println!("\x1b[32m✓ Package manager interception disabled\x1b[0m");
    println!("  Wrappers removed from /usr/local/bin");
    println!("  Please restart your shell or run: source ~/.zshrc (or ~/.bashrc)");
    
    Ok(())
}

async fn show_intercept_status() -> anyhow::Result<()> {
    use std::fs;
    
    let wrapper_dir = PathBuf::from("/usr/local/bin");
    let npm_wrapper = wrapper_dir.join("npm");
    let pip_wrapper = wrapper_dir.join("pip");
    let cargo_wrapper = wrapper_dir.join("cargo");
    
    let npm_enabled = npm_wrapper.exists() && 
        fs::read_to_string(&npm_wrapper).unwrap_or_default().contains("supplyguard");
    let pip_enabled = pip_wrapper.exists() && 
        fs::read_to_string(&pip_wrapper).unwrap_or_default().contains("supplyguard");
    let cargo_enabled = cargo_wrapper.exists() && 
        fs::read_to_string(&cargo_wrapper).unwrap_or_default().contains("supplyguard");
    
    println!("Package Manager Interception Status:");
    println!("  npm:   {}", if npm_enabled { "\x1b[32m✓ Enabled\x1b[0m" } else { "\x1b[31m✗ Disabled\x1b[0m" });
    println!("  pip:   {}", if pip_enabled { "\x1b[32m✓ Enabled\x1b[0m" } else { "\x1b[31m✗ Disabled\x1b[0m" });
    println!("  cargo: {}", if cargo_enabled { "\x1b[32m✓ Enabled\x1b[0m" } else { "\x1b[31m✗ Disabled\x1b[0m" });
    
    Ok(())
}

fn update_shell_path(enable: bool) -> anyhow::Result<()> {
    use std::fs;
    
    let home = std::env::var("HOME")
        .map_err(|_| anyhow::anyhow!("HOME environment variable not set"))?;
    
    let shell_configs = vec![
        PathBuf::from(&home).join(".zshrc"),
        PathBuf::from(&home).join(".bashrc"),
        PathBuf::from(&home).join(".bash_profile"),
        PathBuf::from(&home).join(".profile"),
    ];
    
    let path_line = "export PATH=\"/usr/local/bin:$PATH\"  # SupplyGuard interception\n";
    
    for config_path in shell_configs {
        if !config_path.exists() {
            continue;
        }
        
        let content = fs::read_to_string(&config_path)?;
        
        if enable {
            if !content.contains("SupplyGuard interception") {
                let mut new_content = content.clone();
                new_content.push_str(path_line);
                fs::write(&config_path, new_content)?;
            }
        } else {
            let new_content: String = content
                .lines()
                .filter(|line| !line.contains("SupplyGuard interception"))
                .collect::<Vec<_>>()
                .join("\n");
            if new_content != content {
                fs::write(&config_path, new_content)?;
            }
        }
    }
    
    Ok(())
}

fn pid_file_path() -> PathBuf {
    PathBuf::from("/tmp/supplyguard.pid")
}

fn read_pid_file() -> anyhow::Result<i32> {
    let path = pid_file_path();
    let pid_str = fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read PID file {}: {}", path.display(), e))?;
    let pid = pid_str.trim().parse::<i32>()
        .map_err(|e| anyhow::anyhow!("Failed to parse PID from '{}': {}", pid_str.trim(), e))?;
    Ok(pid)
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
    if pid <= 0 {
        return false;
    }
    unsafe {
        // kill(pid, 0) checks if process exists
        // Returns 0 if process exists, -1 with errno if it doesn't
        let result = libc::kill(pid, 0);
        result == 0
    }
}
