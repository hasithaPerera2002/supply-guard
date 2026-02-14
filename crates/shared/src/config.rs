use crate::error::ConfigError;
use crate::Severity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub monitoring: MonitoringConfig,
    pub scanning: ScanningConfig,
    pub notifications: NotificationConfig,
    pub quarantine: QuarantineConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub watch_paths: Vec<String>,
    pub ignored_paths: Vec<String>,
    pub scan_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningConfig {
    pub parallel_workers: usize,
    pub max_file_size_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub min_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub enabled: bool,
    pub auto_quarantine_severity: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

impl Config {
    pub fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        
        Self {
            monitoring: MonitoringConfig {
                watch_paths: vec![
                    format!("{}/Projects", home),
                    format!("{}/Downloads", home),
                    format!("{}/Developer", home),
                ],
                ignored_paths: vec![
                    "node_modules".to_string(),
                    ".git/objects".to_string(),
                    "target".to_string(),
                    "dist".to_string(),
                    "build".to_string(),
                    "__pycache__".to_string(),
                ],
                scan_interval_ms: 100,
            },
            scanning: ScanningConfig {
                parallel_workers: 4,
                max_file_size_mb: 10,
            },
            notifications: NotificationConfig {
                enabled: true,
                min_severity: "High".to_string(),
            },
            quarantine: QuarantineConfig {
                enabled: true,
                auto_quarantine_severity: "Critical".to_string(),
                path: format!("{}/.supplyguard/quarantine", home),
            },
            database: DatabaseConfig {
                path: format!("{}/.supplyguard/threats.db", home),
            },
        }
    }

    pub fn load() -> Result<Self, ConfigError> {
        let config_path = Self::config_path()?;
        
        if !config_path.exists() {
            let config = Self::default();
            config.save()?;
            return Ok(config);
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| ConfigError::IoError(format!("Failed to read config: {}", e)))?;
        
        let config: Config = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(format!("Failed to parse config: {}", e)))?;
        
        Ok(config)
    }

    pub fn save(&self) -> Result<(), ConfigError> {
        let config_path = Self::config_path()?;
        
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ConfigError::IoError(format!("Failed to create config directory: {}", e)))?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::ParseError(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(&config_path, content)
            .map_err(|e| ConfigError::IoError(format!("Failed to write config: {}", e)))?;
        
        Ok(())
    }

    pub fn config_path() -> Result<PathBuf, ConfigError> {
        let home = std::env::var("HOME")
            .map_err(|_| ConfigError::IoError("HOME environment variable not set".to_string()))?;
        Ok(PathBuf::from(home).join(".supplyguard").join("config.toml"))
    }

    pub fn min_notification_severity(&self) -> Severity {
        Severity::from_str(&self.notifications.min_severity)
            .unwrap_or(Severity::High)
    }

    pub fn auto_quarantine_severity(&self) -> Severity {
        Severity::from_str(&self.quarantine.auto_quarantine_severity)
            .unwrap_or(Severity::Critical)
    }

    pub fn expand_paths(&self) -> Vec<PathBuf> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        self.monitoring.watch_paths
            .iter()
            .map(|p| {
                let expanded = p.replace("~", &home);
                PathBuf::from(expanded)
            })
            .collect()
    }

    pub fn quarantine_path(&self) -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        let expanded = self.quarantine.path.replace("~", &home);
        PathBuf::from(expanded)
    }

    pub fn database_path(&self) -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        let expanded = self.database.path.replace("~", &home);
        PathBuf::from(expanded)
    }
}
