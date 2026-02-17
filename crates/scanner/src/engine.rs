use crate::cache::ScanCache;
use crate::detectors::{all_detectors, Detector};
use shared::{ScanResult, ScannerError};
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info, warn};

pub struct ScannerEngine {
    detectors: Vec<Box<dyn Detector>>,
    cache: ScanCache,
    max_file_size: usize,
}

impl ScannerEngine {
    pub fn new(max_file_size_mb: usize) -> Self {
        Self {
            detectors: all_detectors(),
            cache: ScanCache::new(),
            max_file_size: max_file_size_mb * 1024 * 1024,
        }
    }

    pub async fn scan_file(&self, path: &Path) -> Result<ScanResult, ScannerError> {
        let start = Instant::now();

        // Check file size
        let metadata = std::fs::metadata(path)
            .map_err(|e| ScannerError::IoError(format!("Failed to read metadata: {}", e)))?;
        
        if metadata.len() > self.max_file_size as u64 {
            return Ok(ScanResult {
                path: path.to_path_buf(),
                threats: vec![],
                scan_duration_ms: start.elapsed().as_millis() as u64,
                is_clean: true,
            });
        }

        // Read file content
        let content = std::fs::read_to_string(path)
            .map_err(|e| ScannerError::IoError(format!("Failed to read file: {}", e)))?;

        // Check cache
        if self.cache.is_unchanged(path, content.as_bytes()) {
            return Ok(ScanResult {
                path: path.to_path_buf(),
                threats: vec![],
                scan_duration_ms: start.elapsed().as_millis() as u64,
                is_clean: true,
            });
        }

        // Determine which detectors to use
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        
        let path_str = path.to_string_lossy().to_lowercase();
        
        let applicable_detectors: Vec<&Box<dyn Detector>> = self.detectors
            .iter()
            .filter(|detector| {
                detector.supported_extensions().contains(&ext) ||
                path_str.contains(".vscode/tasks.json") ||
                path_str.contains(".git/hooks/") ||
                path.file_name() == Some(std::ffi::OsStr::new("package.json")) ||
                path.file_name() == Some(std::ffi::OsStr::new("Cargo.toml")) ||
                path.file_name() == Some(std::ffi::OsStr::new("build.rs")) ||
                path.file_name() == Some(std::ffi::OsStr::new("setup.py")) ||
                path_str.contains(".github/workflows") ||
                path_str.contains(".gitlab-ci.yml")
            })
            .collect();

        // Run detectors
        let mut all_threats = Vec::new();
        
        for detector in applicable_detectors {
            match detector.detect(path, &content).await {
                Ok(mut threats) => {
                    all_threats.append(&mut threats);
                }
                Err(e) => {
                    warn!("Detector error for {}: {}", path.display(), e);
                }
            }
        }

        // Update cache
        if all_threats.is_empty() {
            self.cache.update(path, content.as_bytes());
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let is_clean = all_threats.is_empty();
        
        if !is_clean {
            info!("Found {} threats in {} ({}ms)", all_threats.len(), path.display(), duration_ms);
        } else {
            debug!("Scanned {} - clean ({}ms)", path.display(), duration_ms);
        }

        Ok(ScanResult {
            path: path.to_path_buf(),
            threats: all_threats,
            scan_duration_ms: duration_ms,
            is_clean,
        })
    }

    pub async fn scan_directory(&self, dir: &Path) -> Result<Vec<ScanResult>, ScannerError> {
        let mut results = Vec::new();
        
        let entries = std::fs::read_dir(dir)
            .map_err(|e| ScannerError::IoError(format!("Failed to read directory: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| ScannerError::IoError(format!("Failed to read entry: {}", e)))?;
            let path = entry.path();
            
            if path.is_file() {
                match self.scan_file(&path).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        warn!("Failed to scan {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(results)
    }
}
