use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatType {
    VscodeAutoRun,
    GitHookMalware,
    MaliciousInstallScript,
    ReverseShell,
    CredentialTheft,
    ObfuscatedCode,
    SuspiciousNetwork,
    DependencyConfusion,
    BuildScriptAttack,
    CiCdBackdoor,
}

impl ThreatType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatType::VscodeAutoRun => "VS Code Auto-Run Attack",
            ThreatType::GitHookMalware => "Git Hook Malware",
            ThreatType::MaliciousInstallScript => "Malicious Install Script",
            ThreatType::ReverseShell => "Reverse Shell",
            ThreatType::CredentialTheft => "Credential Theft",
            ThreatType::ObfuscatedCode => "Obfuscated Code",
            ThreatType::SuspiciousNetwork => "Suspicious Network Activity",
            ThreatType::DependencyConfusion => "Dependency Confusion",
            ThreatType::BuildScriptAttack => "Build Script Attack",
            ThreatType::CiCdBackdoor => "CI/CD Backdoor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Low" | "low" => Some(Severity::Low),
            "Medium" | "medium" => Some(Severity::Medium),
            "High" | "high" => Some(Severity::High),
            "Critical" | "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResult {
    pub file_path: PathBuf,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub line_number: Option<usize>,
    pub matched_pattern: String,
    pub pattern_name: String,
    pub context: String,
    pub remediation: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: PathBuf,
    pub threats: Vec<ThreatResult>,
    pub scan_duration_ms: u64,
    pub is_clean: bool,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub path: PathBuf,
    pub priority: u8,
    pub event_type: FileEventType,
}

#[derive(Debug, Clone)]
pub enum FileEventType {
    Created,
    Modified,
    Removed,
}
