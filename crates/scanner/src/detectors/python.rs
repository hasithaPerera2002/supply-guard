use crate::detectors::Detector;
use crate::patterns::get_patterns;
use async_trait::async_trait;
use chrono::Utc;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::Path;
use tracing::debug;

pub struct PythonDetector;

#[async_trait]
impl Detector for PythonDetector {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError> {
        if path.file_name() != Some(std::ffi::OsStr::new("setup.py")) {
            return Ok(vec![]);
        }

        let mut threats = Vec::new();

        // Check for os.system or subprocess at module level
        let lines: Vec<&str> = content.lines().collect();
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            // Skip comments and docstrings
            if trimmed.starts_with('#') || trimmed.starts_with("\"\"\"") || trimmed.starts_with("'''") {
                continue;
            }

            // Check for os.system or subprocess calls at module level
            if trimmed.contains("os.system") || trimmed.contains("subprocess.") {
                // Check if it's inside a function (indented)
                if !trimmed.starts_with(" ") && !trimmed.starts_with("\t") {
                    threats.push(ThreatResult {
                        file_path: path.to_path_buf(),
                        threat_type: ThreatType::BuildScriptAttack,
                        severity: Severity::High,
                        line_number: Some(line_num + 1),
                        matched_pattern: trimmed.to_string(),
                        pattern_name: "MODULE_LEVEL_EXEC".to_string(),
                        context: format!("Line {}: Module-level command execution", line_num + 1),
                        remediation: "Command execution at module level runs during import. Review carefully.".to_string(),
                        timestamp: Utc::now(),
                    });
                }
            }

            // Check for urllib/requests during import
            if (trimmed.contains("urllib") || trimmed.contains("requests")) && trimmed.contains("import") {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::SuspiciousNetwork,
                    severity: Severity::Medium,
                    line_number: Some(line_num + 1),
                    matched_pattern: trimmed.to_string(),
                    pattern_name: "NETWORK_IMPORT".to_string(),
                    context: format!("Line {}: Network library imported", line_num + 1),
                    remediation: "Review why setup.py imports network libraries. May be exfiltration attempt.".to_string(),
                    timestamp: Utc::now(),
                });
            }

            // Check for __import__ with encoded strings
            if trimmed.contains("__import__") && (trimmed.contains("base64") || trimmed.contains("fromCharCode")) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::ObfuscatedCode,
                    severity: Severity::High,
                    line_number: Some(line_num + 1),
                    matched_pattern: trimmed.to_string(),
                    pattern_name: "OBFUSCATED_IMPORT".to_string(),
                    context: format!("Line {}: Obfuscated import detected", line_num + 1),
                    remediation: "Obfuscated imports are suspicious. Deobfuscate and review.".to_string(),
                    timestamp: Utc::now(),
                });
            }
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

        debug!("PythonDetector found {} threats in {}", threats.len(), path.display());
        Ok(threats)
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["py"]
    }

    fn priority(&self) -> u8 {
        2
    }
}
