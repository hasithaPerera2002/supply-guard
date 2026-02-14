use async_channel::Receiver;
use chrono::Utc;
use database::{CacheDatabase, ThreatDatabase};
use notifier::MacOSNotifier;
use scanner::{cache::ScanCache, ScannerEngine};
use shared::{Config, FileEvent, Severity};
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
        info!("SupplyGuard daemon starting...");

        // Create worker pool
        let num_workers = self.config.scanning.parallel_workers;
        let mut handles = Vec::new();

        for worker_id in 0..num_workers {
            let scanner = Arc::clone(&self.scanner);
            let threat_db = Arc::clone(&self.threat_db);
            let cache_db = Arc::clone(&self.cache_db);
            let notifier = Arc::clone(&self.notifier);
            let mut event_rx = self.event_rx.clone();
            let mut shutdown_rx = self.shutdown_rx.resubscribe();
            let config = self.config.clone();

            let handle = tokio::spawn(async move {
                Self::worker_loop(
                    worker_id,
                    scanner,
                    threat_db,
                    cache_db,
                    notifier,
                    &mut event_rx,
                    &mut shutdown_rx,
                    config,
                ).await;
            });

            handles.push(handle);
        }

        info!("Started {} scanner workers", num_workers);

        // Wait for shutdown signal
        let _ = self.shutdown_rx.recv().await;
        info!("Shutdown signal received, waiting for workers to finish...");

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
        event_rx: &mut Receiver<FileEvent>,
        shutdown_rx: &mut broadcast::Receiver<()>,
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
        threat_id: Option<i64>,
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
