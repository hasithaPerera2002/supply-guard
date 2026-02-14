use crate::detectors::Detector;
use crate::patterns::get_patterns;
use async_trait::async_trait;
use chrono::Utc;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::Path;
use tracing::debug;

pub struct ShellDetector;

#[async_trait]
impl Detector for ShellDetector {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError> {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        
        if !matches!(ext, "sh" | "bash" | "zsh") {
            return Ok(vec![]);
        }

        let mut threats = Vec::new();

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

        // Check for persistence mechanisms
        if content.contains("crontab") || content.contains("launchd") || content.contains("launchctl") {
            threats.push(ThreatResult {
                file_path: path.to_path_buf(),
                threat_type: ThreatType::GitHookMalware,
                severity: Severity::Medium,
                line_number: None,
                matched_pattern: "persistence mechanism".to_string(),
                pattern_name: "PERSISTENCE".to_string(),
                context: "Script attempts to establish persistence via crontab or launchd".to_string(),
                remediation: "Review script for legitimate persistence needs. Malware often uses these mechanisms.".to_string(),
                timestamp: Utc::now(),
            });
        }

        debug!("ShellDetector found {} threats in {}", threats.len(), path.display());
        Ok(threats)
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["sh", "bash", "zsh"]
    }

    fn priority(&self) -> u8 {
        1
    }
}
