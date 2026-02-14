pub mod vscode;
pub mod git_hooks;
pub mod package_json;
pub mod shell;
pub mod cargo;
pub mod python;
pub mod ci;

use async_trait::async_trait;
use shared::{ThreatResult, ScannerError};
use std::path::Path;

#[async_trait]
pub trait Detector: Send + Sync {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError>;
    fn supported_extensions(&self) -> Vec<&'static str>;
    fn priority(&self) -> u8 {
        2
    }
}

pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(vscode::VscodeDetector),
        Box::new(git_hooks::GitHooksDetector),
        Box::new(package_json::PackageJsonDetector),
        Box::new(shell::ShellDetector),
        Box::new(cargo::CargoDetector),
        Box::new(python::PythonDetector),
        Box::new(ci::CiDetector),
    ]
}
