use crate::detectors::Detector;
use crate::patterns::get_patterns;
use async_trait::async_trait;
use chrono::Utc;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::Path;
use tracing::debug;

pub struct CargoDetector;

#[async_trait]
impl Detector for CargoDetector {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError> {
        let mut threats = Vec::new();

        if path.file_name() == Some(std::ffi::OsStr::new("Cargo.toml")) {
            // Check for build.rs
            if content.contains(r#"build = "build.rs""#) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::BuildScriptAttack,
                    severity: Severity::Medium,
                    line_number: None,
                    matched_pattern: r#"build = "build.rs""#.to_string(),
                    pattern_name: "BUILD_SCRIPT".to_string(),
                    context: "Cargo.toml specifies build.rs script".to_string(),
                    remediation: "Review build.rs for malicious code execution. Build scripts run during compilation.".to_string(),
                    timestamp: Utc::now(),
                });
            }

            // Check for suspicious git dependencies
            for line in content.lines() {
                if line.contains("git =") && (line.contains("bit.ly") || line.contains("short.gy") || line.contains("tinyurl")) {
                    threats.push(ThreatResult {
                        file_path: path.to_path_buf(),
                        threat_type: ThreatType::DependencyConfusion,
                        severity: Severity::High,
                        line_number: None,
                        matched_pattern: "git dependency with URL shortener".to_string(),
                        pattern_name: "SUSPICIOUS_GIT_DEP".to_string(),
                        context: format!("Line: {}", line.trim()),
                        remediation: "Git dependencies should use full URLs. URL shorteners are suspicious.".to_string(),
                        timestamp: Utc::now(),
                    });
                }
            }
        } else if path.file_name() == Some(std::ffi::OsStr::new("build.rs")) {
            // Check build.rs for malicious patterns
            for pattern in get_patterns() {
                for (line_num, line) in content.lines().enumerate() {
                    if pattern.regex.is_match(line) {
                        threats.push(ThreatResult {
                            file_path: path.to_path_buf(),
                            threat_type: ThreatType::BuildScriptAttack,
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

            // Check for Command::new("sh")
            if content.contains(r#"Command::new("sh")"#) || content.contains("Command::new(\"sh\")") {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::BuildScriptAttack,
                    severity: Severity::High,
                    line_number: None,
                    matched_pattern: "Command::new(\"sh\")".to_string(),
                    pattern_name: "SHELL_COMMAND".to_string(),
                    context: "build.rs executes shell commands".to_string(),
                    remediation: "Review build.rs for legitimate shell command usage. Malicious build scripts often execute arbitrary shell commands.".to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        debug!("CargoDetector found {} threats in {}", threats.len(), path.display());
        Ok(threats)
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["toml", "rs"]
    }

    fn priority(&self) -> u8 {
        2
    }
}
