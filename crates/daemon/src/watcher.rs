use async_channel::Sender;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use shared::{FileEvent, FileEventType};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

pub struct FileWatcher {
    watcher: Arc<Mutex<Option<RecommendedWatcher>>>,
    event_tx: Sender<FileEvent>,
    ignored_paths: Vec<String>,
}

impl FileWatcher {
    pub fn new(event_tx: Sender<FileEvent>, ignored_paths: Vec<String>) -> Self {
        Self {
            watcher: Arc::new(Mutex::new(None)),
            event_tx,
            ignored_paths,
        }
    }

    pub async fn watch_paths(&self, paths: Vec<PathBuf>) -> anyhow::Result<()> {
        let mut watcher_guard = self.watcher.lock().await;
        
        let event_tx = self.event_tx.clone();
        let ignored_paths = self.ignored_paths.clone();

        let watcher = match notify::recommended_watcher(move |res: notify::Result<Event>| {
            match res {
                Ok(event) => {
                    for path in &event.paths {
                        let path_str = path.to_string_lossy().to_lowercase();
                        
                        // Check if path should be ignored
                        let should_ignore = ignored_paths.iter().any(|ignored| {
                            path_str.contains(ignored.to_lowercase().as_str())
                        });

                        if should_ignore {
                            debug!("Ignoring path: {}", path.display());
                            continue;
                        }

                        // Determine event type and priority
                        let (event_type, priority) = match event.kind {
                            EventKind::Create(_) => (FileEventType::Created, Self::get_priority(path)),
                            EventKind::Modify(_) => (FileEventType::Modified, Self::get_priority(path)),
                            EventKind::Remove(_) => (FileEventType::Removed, 3),
                            _ => continue,
                        };

                        let file_event = FileEvent {
                            path: path.clone(),
                            priority,
                            event_type,
                        };

                        // Try to send, but don't block
                        if let Err(e) = event_tx.try_send(file_event) {
                            warn!("Failed to send file event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Watcher error: {}", e);
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to create file watcher: {}", e);
                warn!("Daemon will continue without file watching - manual scans will still work");
                return Ok(()); // Don't fail startup if watcher can't be created
            }
        };

        *watcher_guard = Some(watcher);

        // Watch all paths
        let watcher_ref = watcher_guard.as_mut().unwrap();
        for path in paths {
            if path.exists() {
                info!("Watching path: {}", path.display());
                if let Err(e) = watcher_ref.watch(&path, RecursiveMode::Recursive) {
                    // On macOS this can fail due to TCC/privacy permissions (even as root under launchd).
                    // Don't crash the whole daemon; just skip paths we can't watch.
                    warn!("Failed to watch {}: {}", path.display(), e);
                }
            } else {
                warn!("Path does not exist, skipping: {}", path.display());
            }
        }

        Ok(())
    }

    fn get_priority(path: &PathBuf) -> u8 {
        let path_str = path.to_string_lossy().to_lowercase();
        
        // Priority 1: Critical files
        if path_str.contains(".vscode/tasks.json") ||
           path_str.contains(".git/hooks/") ||
           path.file_name() == Some(std::ffi::OsStr::new("package.json")) ||
           path.extension().and_then(|e| e.to_str()) == Some("sh") {
            return 1;
        }

        // Priority 2: Important config files
        if path.file_name() == Some(std::ffi::OsStr::new("Cargo.toml")) ||
           path.file_name() == Some(std::ffi::OsStr::new("setup.py")) ||
           path.file_name() == Some(std::ffi::OsStr::new("build.rs")) ||
           path_str.contains(".github/workflows") ||
           path_str.contains(".gitlab-ci.yml") ||
           path.extension().and_then(|e| e.to_str()).map(|e| matches!(e, "yml" | "yaml")) == Some(true) {
            return 2;
        }

        // Priority 3: Other files
        3
    }

    pub async fn stop(&self) {
        let mut watcher_guard = self.watcher.lock().await;
        *watcher_guard = None;
    }
}
