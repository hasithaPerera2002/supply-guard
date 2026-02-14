use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
}

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("Watcher error: {0}")]
    WatcherError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Config error: {0}")]
    ConfigError(#[from] ConfigError),
    
    #[error("IO error: {0}")]
    IoError(String),
}

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Detector error: {0}")]
    DetectorError(String),
    
    #[error("IO error: {0}")]
    IoError(String),
}

#[derive(Error, Debug)]
pub enum NotificationError {
    #[error("Failed to send notification: {0}")]
    SendError(String),
}
