use crate::detectors::Detector;
use crate::patterns::get_patterns;
use async_trait::async_trait;
use chrono::Utc;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::Path;
use tracing::debug;

pub struct GitHooksDetector;

#[async_trait]
impl Detector for GitHooksDetector {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError> {
        if !path.to_string_lossy().contains(".git/hooks/") {
            return Ok(vec![]);
        }

        let mut threats = Vec::new();

        // Check if file is executable (Unix-like systems)
        #[cfg(unix)]
        let is_executable = {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path)
                .map_err(|e| ScannerError::IoError(format!("Failed to read metadata: {}", e)))?;
            metadata.permissions().mode() & 0o111 != 0
        };
        
        #[cfg(not(unix))]
        let is_executable = false;
        
        if is_executable {
            threats.push(ThreatResult {
                file_path: path.to_path_buf(),
                threat_type: ThreatType::GitHookMalware,
                severity: Severity::High,
                line_number: None,
                matched_pattern: "executable git hook".to_string(),
                pattern_name: "EXECUTABLE_HOOK".to_string(),
                context: "Git hook file is executable".to_string(),
                remediation: "Review git hooks for malicious code. Only trusted hooks should be executable.".to_string(),
                timestamp: Utc::now(),
            });
        }

        // Check against all patterns
        for pattern in get_patterns() {
            for (line_num, line) in content.lines().enumerate() {
                if pattern.regex.is_match(line) {
                    threats.push(ThreatResult {
                        file_path: path.to_path_buf(),
                        threat_type: pattern.threat_type.clone(),
                        severity: pattern.severity,
                        line_number: Some(line_num + 1),
                        matched_pattern: pattern.regex.find(line).map(|m| m.as_str().to_string()).unwrap_or_default(),
                        pattern_name: pattern.id.to_string(),
                        context: format!("Line {}: {}", line_num + 1, line.trim()),
                        remediation: pattern.remediation.to_string(),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        debug!("GitHooksDetector found {} threats in {}", threats.len(), path.display());
        Ok(threats)
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["sh", "bash", "zsh"]
    }

    fn priority(&self) -> u8 {
        1
    }
}
