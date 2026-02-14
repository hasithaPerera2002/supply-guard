use crate::detectors::Detector;
use crate::patterns::get_patterns;
use async_trait::async_trait;
use chrono::Utc;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::Path;
use tracing::debug;

pub struct PackageJsonDetector;

#[async_trait]
impl Detector for PackageJsonDetector {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError> {
        if path.file_name() != Some(std::ffi::OsStr::new("package.json")) {
            return Ok(vec![]);
        }

        let mut threats = Vec::new();

        // Parse JSON
        let json: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| ScannerError::ParseError(format!("Failed to parse package.json: {}", e)))?;

        // Check scripts section
        if let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) {
            let dangerous_scripts = ["preinstall", "postinstall", "prepare", "install"];
            
            for script_name in &dangerous_scripts {
                if let Some(script_value) = scripts.get(*script_name) {
                    if let Some(script_str) = script_value.as_str() {
                        // Check against all patterns
                        for pattern in get_patterns() {
                            if pattern.regex.is_match(script_str) {
                                threats.push(ThreatResult {
                                    file_path: path.to_path_buf(),
                                    threat_type: ThreatType::MaliciousInstallScript,
                                    severity: pattern.severity,
                                    line_number: None,
                                    matched_pattern: pattern.regex.find(script_str).map(|m| m.as_str().to_string()).unwrap_or_default(),
                                    pattern_name: pattern.id.to_string(),
                                    context: format!("Script '{}': {}", script_name, script_str),
                                    remediation: pattern.remediation.to_string(),
                                    timestamp: Utc::now(),
                                });
                            }
                        }

                        // Check for node -e with obfuscated code
                        if script_str.contains("node -e") && (script_str.contains("eval") || script_str.contains("Function")) {
                            threats.push(ThreatResult {
                                file_path: path.to_path_buf(),
                                threat_type: ThreatType::ObfuscatedCode,
                                severity: Severity::High,
                                line_number: None,
                                matched_pattern: "node -e with eval/Function".to_string(),
                                pattern_name: "OBFUSCATED_NODE".to_string(),
                                context: format!("Script '{}' uses node -e with potentially obfuscated code", script_name),
                                remediation: "Review node -e scripts carefully. Obfuscated code in install scripts is suspicious.".to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }
            }
        }

        debug!("PackageJsonDetector found {} threats in {}", threats.len(), path.display());
        Ok(threats)
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["json"]
    }

    fn priority(&self) -> u8 {
        1
    }
}
