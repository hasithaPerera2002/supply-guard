use crate::detectors::Detector;
use crate::patterns::get_patterns;
use async_trait::async_trait;
use chrono::Utc;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::Path;
use tracing::debug;

pub struct VscodeDetector;

#[async_trait]
impl Detector for VscodeDetector {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError> {
        if !path.to_string_lossy().contains(".vscode/tasks.json") {
            return Ok(vec![]);
        }

        let mut threats = Vec::new();

        // Parse JSON
        let json: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| ScannerError::ParseError(format!("Failed to parse tasks.json: {}", e)))?;

        // Check for runOn: folderOpen
        if let Some(tasks) = json.get("tasks").and_then(|t| t.as_array()) {
            for (idx, task) in tasks.iter().enumerate() {
                if let Some(run_options) = task.get("runOptions") {
                    if let Some(run_on) = run_options.get("runOn") {
                        if run_on.as_str() == Some("folderOpen") {
                            threats.push(ThreatResult {
                                file_path: path.to_path_buf(),
                                threat_type: ThreatType::VscodeAutoRun,
                                severity: Severity::Critical,
                                line_number: None,
                                matched_pattern: r#""runOn": "folderOpen""#.to_string(),
                                pattern_name: "VSCODE_AUTORUN".to_string(),
                                context: format!("Task #{} configured to run on folder open", idx + 1),
                                remediation: "Remove runOptions.runOn or change to 'default'. Review task commands for malicious code.".to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }

                // Check presentation settings
                if let Some(presentation) = task.get("presentation") {
                    let reveal = presentation.get("reveal").and_then(|r| r.as_str());
                    let echo = presentation.get("echo").and_then(|e| e.as_bool());
                    
                    if reveal == Some("never") && echo == Some(false) {
                        threats.push(ThreatResult {
                            file_path: path.to_path_buf(),
                            threat_type: ThreatType::VscodeAutoRun,
                            severity: Severity::High,
                            line_number: None,
                            matched_pattern: r#""reveal": "never", "echo": false"#.to_string(),
                            pattern_name: "HIDDEN_EXECUTION".to_string(),
                            context: format!("Task #{} configured to hide execution", idx + 1),
                            remediation: "Tasks with hidden execution are suspicious. Review task commands carefully.".to_string(),
                            timestamp: Utc::now(),
                        });
                    }
                }

                // Check commands for malicious patterns
                let command_fields = ["command", "osx", "linux", "windows"];
                for field in &command_fields {
                    if let Some(cmd_value) = task.get(field) {
                        let cmd_str = if cmd_value.is_string() {
                            cmd_value.as_str().unwrap_or("")
                        } else if let Some(obj) = cmd_value.as_object() {
                            obj.get("command").and_then(|c| c.as_str()).unwrap_or("")
                        } else {
                            continue;
                        };

                        // Check against all patterns
                        for pattern in get_patterns() {
                            if pattern.regex.is_match(cmd_str) {
                                threats.push(ThreatResult {
                                    file_path: path.to_path_buf(),
                                    threat_type: pattern.threat_type.clone(),
                                    severity: pattern.severity,
                                    line_number: None,
                                    matched_pattern: pattern.regex.find(cmd_str).map(|m| m.as_str().to_string()).unwrap_or_default(),
                                    pattern_name: pattern.id.to_string(),
                                    context: format!("Task #{} command in {} field", idx + 1, field),
                                    remediation: pattern.remediation.to_string(),
                                    timestamp: Utc::now(),
                                });
                            }
                        }
                    }
                }
            }
        }

        debug!("VscodeDetector found {} threats in {}", threats.len(), path.display());
        Ok(threats)
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["json"]
    }

    fn priority(&self) -> u8 {
        1
    }
}
