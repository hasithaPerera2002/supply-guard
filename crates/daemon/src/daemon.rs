use async_channel::Receiver;
use chrono::Utc;
use database::{CacheDatabase, ThreatDatabase};
use notifier::MacOSNotifier;
use scanner::{cache::ScanCache, ScannerEngine};
use shared::{Config, FileEvent};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::time::sleep;
use tracing::{error, info, warn};

pub struct Daemon {
    config: Config,
    scanner: Arc<ScannerEngine>,
    threat_db: Arc<ThreatDatabase>,
    cache_db: Arc<CacheDatabase>,
    notifier: Arc<MacOSNotifier>,
    event_rx: Receiver<FileEvent>,
    shutdown_rx: broadcast::Receiver<()>,
}

impl Daemon {
    pub fn new(
        config: Config,
        scanner: Arc<ScannerEngine>,
        threat_db: Arc<ThreatDatabase>,
        cache_db: Arc<CacheDatabase>,
        notifier: Arc<MacOSNotifier>,
        event_rx: Receiver<FileEvent>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            config,
            scanner,
            threat_db,
            cache_db,
            notifier,
            event_rx,
            shutdown_rx,
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        eprintln!("daemon.run() called - entering main loop");
        info!("SupplyGuard daemon starting...");
        info!("Config: {} workers, scan_interval: {}ms", 
              self.config.scanning.parallel_workers, 
              self.config.monitoring.scan_interval_ms);
        eprintln!("About to create worker tasks...");

        // Create worker pool
        let num_workers = self.config.scanning.parallel_workers;
        let mut handles = Vec::new();
        
        info!("Creating {} worker tasks...", num_workers);
        eprintln!("Creating {} worker tasks...", num_workers);

        for worker_id in 0..num_workers {
            eprintln!("Creating worker {}...", worker_id);
            let scanner = Arc::clone(&self.scanner);
            let threat_db = Arc::clone(&self.threat_db);
            let cache_db = Arc::clone(&self.cache_db);
            let notifier = Arc::clone(&self.notifier);
            eprintln!("Worker {} - cloned Arc references", worker_id);
            // Note: async_channel::Receiver doesn't implement Clone
            // Each worker needs its own receiver, so we need to share the sender instead
            // For now, we'll create a new receiver from the same channel
            // Actually, we can't clone receivers - we need to rethink this architecture
            // Let's use the same receiver for all workers (they'll compete for messages)
            let event_rx = self.event_rx.clone();
            let shutdown_rx = self.shutdown_rx.resubscribe();
            eprintln!("Worker {} - got channels", worker_id);
            let config = self.config.clone();
            eprintln!("Worker {} - cloned config", worker_id);

            eprintln!("Worker {} - about to spawn tokio task", worker_id);
            let handle = tokio::spawn(async move {
                eprintln!("Worker {} task started", worker_id);
                Self::worker_loop(
                    worker_id,
                    scanner,
                    threat_db,
                    cache_db,
                    notifier,
                    event_rx,
                    shutdown_rx,
                    config,
                ).await;
                eprintln!("Worker {} task exited", worker_id);
            });
            eprintln!("Worker {} task spawned", worker_id);

            handles.push(handle);
        }
        eprintln!("All {} workers created", num_workers);

        info!("Started {} scanner workers", num_workers);
        eprintln!("Started {} scanner workers", num_workers);
        info!("Daemon is now running and monitoring for file changes...");
        eprintln!("Daemon is now running and monitoring for file changes...");

        // Spawn a heartbeat task to verify daemon is alive
        eprintln!("About to spawn heartbeat task...");
        let heartbeat_handle = tokio::spawn({
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            async move {
                eprintln!("Heartbeat task started");
                loop {
                    interval.tick().await;
                    eprintln!("Daemon heartbeat - still running");
                    info!("Daemon heartbeat - still running");
                }
            }
        });
        eprintln!("Heartbeat task spawned");

        // Wait for shutdown signal
        eprintln!("About to wait for shutdown signal (this should block forever)...");
        loop {
            eprintln!("Waiting for shutdown signal...");
            match self.shutdown_rx.recv().await {
                Ok(_) => {
                    info!("Shutdown signal received, waiting for workers to finish...");
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    error!("Shutdown channel closed unexpectedly. This should not happen.");
                    warn!("Daemon will continue running - heartbeat will keep it alive");
                    // Keep running - don't exit. The heartbeat task will keep the process alive.
                    // Wait a bit and log - this keeps the loop alive
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    info!("Daemon still running (channel was closed but process continues)");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Lagged means we missed messages but channel is still open
                    // Continue waiting
                    continue;
                }
            }
        }
        
        // Cancel heartbeat when shutting down
        heartbeat_handle.abort();

        // Give workers time to finish (10 second timeout)
        tokio::select! {
            _ = async {
                for handle in handles {
                    let _ = handle.await;
                }
            } => {
                info!("All workers finished");
            }
            _ = sleep(Duration::from_secs(10)) => {
                warn!("Timeout waiting for workers, forcing shutdown");
            }
        }

        info!("Daemon stopped");
        Ok(())
    }

    async fn worker_loop(
        worker_id: usize,
        scanner: Arc<ScannerEngine>,
        threat_db: Arc<ThreatDatabase>,
        cache_db: Arc<CacheDatabase>,
        notifier: Arc<MacOSNotifier>,
        event_rx: Receiver<FileEvent>,
        mut shutdown_rx: broadcast::Receiver<()>,
        config: Config,
    ) {
        info!("Worker {} started", worker_id);

        let mut pending_events: Vec<(FileEvent, Instant)> = Vec::new();
        let debounce_window = Duration::from_millis(config.monitoring.scan_interval_ms);

        loop {
            tokio::select! {
                // Check for shutdown
                _ = shutdown_rx.recv() => {
                    info!("Worker {} received shutdown signal", worker_id);
                    break;
                }
                // Receive file event
                Ok(event) = event_rx.recv() => {
                    if event.event_type == shared::FileEventType::Removed {
                        continue;
                    }

                    // Debounce: add to pending events
                    pending_events.push((event, Instant::now()));
                }
                // Process pending events after debounce window
                _ = sleep(Duration::from_millis(50)) => {
                    let now = Instant::now();
                    pending_events.retain(|(_, timestamp)| {
                        now.duration_since(*timestamp) < debounce_window
                    });

                    // Sort by priority and process
                    pending_events.sort_by_key(|(event, _)| event.priority);
                    
                    for (event, _) in pending_events.drain(..) {
                        if event.path.exists() && event.path.is_file() {
                            if let Err(e) = Self::process_file(
                                &scanner,
                                &threat_db,
                                &cache_db,
                                &notifier,
                                &config,
                                &event.path,
                            ).await {
                                error!("Worker {} error processing {}: {}", worker_id, event.path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        info!("Worker {} stopped", worker_id);
    }

    async fn process_file(
        scanner: &Arc<ScannerEngine>,
        threat_db: &Arc<ThreatDatabase>,
        cache_db: &Arc<CacheDatabase>,
        notifier: &Arc<MacOSNotifier>,
        config: &Config,
        path: &PathBuf,
    ) -> anyhow::Result<()> {
        // Check whitelist
        if threat_db.is_whitelisted(path)? {
            return Ok(());
        }

        // Scan file
        let scan_result = scanner.scan_file(path).await?;

        // Update cache
        if scan_result.is_clean {
            if let Ok(content) = std::fs::read(path) {
                let hash = ScanCache::compute_hash(&content);
                let _ = cache_db.update_hash(path, &hash, true);
            }
        }

        // Process threats
        for threat in &scan_result.threats {
            // Record in database
            let threat_id = threat_db.record_threat(threat)?;

            // Send notification
            if let Err(e) = notifier.notify_threat(threat).await {
                warn!("Failed to send notification: {}", e);
            }

            // Auto-quarantine if enabled and severity matches
            if config.quarantine.enabled && threat.severity >= config.auto_quarantine_severity() {
                if let Err(e) = Self::quarantine_file(config, path, Some(threat_id)).await {
                    error!("Failed to quarantine {}: {}", path.display(), e);
                }
            }
        }

        Ok(())
    }

    async fn quarantine_file(
        config: &Config,
        path: &PathBuf,
        _threat_id: Option<i64>,
    ) -> anyhow::Result<()> {
        let quarantine_dir = config.quarantine_path();
        std::fs::create_dir_all(&quarantine_dir)?;

        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        let timestamp = Utc::now().timestamp();
        let quarantine_path = quarantine_dir.join(format!("{}_{}", timestamp, filename));

        // Move file
        std::fs::rename(path, &quarantine_path)?;

        info!("Quarantined {} to {}", path.display(), quarantine_path.display());
        Ok(())
    }
}
