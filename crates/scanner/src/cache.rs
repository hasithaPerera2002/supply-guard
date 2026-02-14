use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use tracing::debug;

pub struct ScanCache {
    cache: Mutex<HashMap<String, String>>,
}

impl ScanCache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn compute_hash(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    pub fn is_unchanged(&self, path: &Path, content: &[u8]) -> bool {
        let hash = Self::compute_hash(content);
        let path_str = path.to_string_lossy().to_string();
        
        let mut cache = self.cache.lock().unwrap();
        
        if let Some(cached_hash) = cache.get(&path_str) {
            if cached_hash == &hash {
                debug!("File unchanged, skipping: {}", path.display());
                return true;
            }
        }
        
        cache.insert(path_str, hash);
        false
    }

    pub fn update(&self, path: &Path, content: &[u8]) {
        let hash = Self::compute_hash(content);
        let path_str = path.to_string_lossy().to_string();
        let mut cache = self.cache.lock().unwrap();
        cache.insert(path_str, hash);
    }

    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }
}

impl Default for ScanCache {
    fn default() -> Self {
        Self::new()
    }
}
