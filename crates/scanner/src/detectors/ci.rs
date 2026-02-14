use crate::detectors::Detector;
use crate::patterns::get_patterns;
use async_trait::async_trait;
use chrono::Utc;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::Path;
use tracing::debug;

pub struct CiDetector;

#[async_trait]
impl Detector for CiDetector {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError> {
        let path_str = path.to_string_lossy();
        if !path_str.contains(".github/workflows") && 
           !path_str.contains(".gitlab-ci.yml") && 
           path.file_name() != Some(std::ffi::OsStr::new(".gitlab-ci.yml")) {
            return Ok(vec![]);
        }

        let mut threats = Vec::new();

        // Try parsing as YAML
        let yaml: serde_yaml::Value = serde_yaml::from_str(content)
            .map_err(|e| ScannerError::ParseError(format!("Failed to parse YAML: {}", e)))?;

        // Check for GitHub Actions workflows
        if let Some(steps) = yaml.get("jobs")
            .and_then(|j| j.as_mapping())
            .and_then(|jobs| {
                jobs.values().next()
                    .and_then(|job| job.get("steps"))
                    .and_then(|s| s.as_sequence())
            }) {
            for (step_idx, step) in steps.iter().enumerate() {
                if let Some(run) = step.get("run").and_then(|r| r.as_str()) {
                    // Check against all patterns
                    for pattern in get_patterns() {
                        if pattern.regex.is_match(run) {
                            threats.push(ThreatResult {
                                file_path: path.to_path_buf(),
                                threat_type: ThreatType::CiCdBackdoor,
                                severity: pattern.severity,
                                line_number: None,
                                matched_pattern: pattern.regex.find(run).map(|m| m.as_str().to_string()).unwrap_or_default(),
                                pattern_name: pattern.id.to_string(),
                                context: format!("Step #{}: {}", step_idx + 1, run),
                                remediation: pattern.remediation.to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }

                // Check for secrets being echoed
                if let Some(run) = step.get("run").and_then(|r| r.as_str()) {
                    if run.contains("echo") && (run.contains("${{ secrets.") || run.contains("$GITHUB_TOKEN")) {
                        threats.push(ThreatResult {
                            file_path: path.to_path_buf(),
                            threat_type: ThreatType::CredentialTheft,
                            severity: Severity::High,
                            line_number: None,
                            matched_pattern: "echo with secrets".to_string(),
                            pattern_name: "SECRET_EXPOSURE".to_string(),
                            context: format!("Step #{}: Secrets may be exposed in logs", step_idx + 1),
                            remediation: "Never echo secrets to logs. Use ::add-mask:: or set output to /dev/null.".to_string(),
                            timestamp: Utc::now(),
                        });
                    }
                }
            }
        }

        // Check for GitLab CI
        if let Some(script) = yaml.get("script").and_then(|s| s.as_sequence()) {
            for (idx, cmd) in script.iter().enumerate() {
                if let Some(cmd_str) = cmd.as_str() {
                    for pattern in get_patterns() {
                        if pattern.regex.is_match(cmd_str) {
                            threats.push(ThreatResult {
                                file_path: path.to_path_buf(),
                                threat_type: ThreatType::CiCdBackdoor,
                                severity: pattern.severity,
                                line_number: None,
                                matched_pattern: pattern.regex.find(cmd_str).map(|m| m.as_str().to_string()).unwrap_or_default(),
                                pattern_name: pattern.id.to_string(),
                                context: format!("Script command #{}: {}", idx + 1, cmd_str),
                                remediation: pattern.remediation.to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }
            }
        }

        // Also check raw content for patterns
        for pattern in get_patterns() {
            for (line_num, line) in content.lines().enumerate() {
                if pattern.regex.is_match(line) {
                    threats.push(ThreatResult {
                        file_path: path.to_path_buf(),
                        threat_type: ThreatType::CiCdBackdoor,
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

        debug!("CiDetector found {} threats in {}", threats.len(), path.display());
        Ok(threats)
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["yml", "yaml"]
    }

    fn priority(&self) -> u8 {
        2
    }
}
