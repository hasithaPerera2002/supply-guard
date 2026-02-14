use regex::Regex;
use shared::{Severity, ThreatType};
use std::sync::LazyLock;

pub struct ThreatPattern {
    pub id: &'static str,
    pub regex: Regex,
    pub severity: Severity,
    pub threat_type: ThreatType,
    pub description: &'static str,
    pub remediation: &'static str,
}

pub static PATTERNS: LazyLock<Vec<ThreatPattern>> = LazyLock::new(|| {
    vec![
        ThreatPattern {
            id: "VSCODE_AUTORUN",
            regex: Regex::new(r#""runOn"\s*:\s*"folderOpen""#).unwrap(),
            severity: Severity::Critical,
            threat_type: ThreatType::VscodeAutoRun,
            description: "VS Code task configured to run automatically when folder opens",
            remediation: "Remove runOptions.runOn or change to 'default'. Review task commands for malicious code.",
        },
        ThreatPattern {
            id: "CURL_PIPE_SHELL",
            regex: Regex::new(r"curl[^|]*\|[^|]*(sh|bash|zsh)").unwrap(),
            severity: Severity::Critical,
            threat_type: ThreatType::MaliciousInstallScript,
            description: "curl command piping output directly to shell interpreter",
            remediation: "Never pipe curl/wget directly to shell. Download, verify, then execute manually.",
        },
        ThreatPattern {
            id: "WGET_PIPE_SHELL",
            regex: Regex::new(r"wget.*(-qO-|-O-).*\|.*(sh|bash|zsh)").unwrap(),
            severity: Severity::Critical,
            threat_type: ThreatType::MaliciousInstallScript,
            description: "wget command piping output directly to shell interpreter",
            remediation: "Never pipe curl/wget directly to shell. Download, verify, then execute manually.",
        },
        ThreatPattern {
            id: "BASE64_DECODE",
            regex: Regex::new(r"(base64\s+-d|atob).*\|.*(sh|bash|eval)").unwrap(),
            severity: Severity::High,
            threat_type: ThreatType::ObfuscatedCode,
            description: "Base64 encoded payload being decoded and executed",
            remediation: "Decode and inspect base64 content before execution. Obfuscation is a red flag.",
        },
        ThreatPattern {
            id: "URL_SHORTENER",
            regex: Regex::new(r"(bit\.ly|short\.gy|tinyurl\.com|t\.co|goo\.gl|ow\.ly)").unwrap(),
            severity: Severity::High,
            threat_type: ThreatType::SuspiciousNetwork,
            description: "URL shortener detected - may hide malicious destination",
            remediation: "Expand URL shorteners before accessing. Use curl -I to check redirects.",
        },
        ThreatPattern {
            id: "REVERSE_SHELL",
            regex: Regex::new(r"(/dev/tcp|nc\s+-e|bash\s+-i\s+>&)").unwrap(),
            severity: Severity::Critical,
            threat_type: ThreatType::ReverseShell,
            description: "Reverse shell connection pattern detected",
            remediation: "This is a backdoor. Remove immediately and check for other compromised files.",
        },
        ThreatPattern {
            id: "CREDENTIAL_ACCESS",
            regex: Regex::new(r"(/\.ssh/id_|/\.aws/credentials|/\.kube/config|\.npmrc|\.pypirc)").unwrap(),
            severity: Severity::High,
            threat_type: ThreatType::CredentialTheft,
            description: "Access to credential files detected",
            remediation: "Review why this code accesses credential files. May be credential theft attempt.",
        },
        ThreatPattern {
            id: "ENV_EXFILTRATION",
            regex: Regex::new(r"(AWS_|GITHUB|API_KEY|SECRET|TOKEN).*curl").unwrap(),
            severity: Severity::High,
            threat_type: ThreatType::CredentialTheft,
            description: "Environment variable containing credentials being sent via curl",
            remediation: "Check for credential exfiltration. Rotate any exposed credentials immediately.",
        },
        ThreatPattern {
            id: "HIDDEN_EXECUTION",
            regex: Regex::new(r#""reveal"\s*:\s*"never".*"echo"\s*:\s*false"#).unwrap(),
            severity: Severity::High,
            threat_type: ThreatType::VscodeAutoRun,
            description: "VS Code task configured to hide output and execution",
            remediation: "Tasks with hidden execution are suspicious. Review task commands carefully.",
        },
        ThreatPattern {
            id: "OBFUSCATED_EVAL",
            regex: Regex::new(r"(eval|exec)\s*\(.*(base64|fromCharCode|unescape)").unwrap(),
            severity: Severity::High,
            threat_type: ThreatType::ObfuscatedCode,
            description: "Obfuscated code execution using eval/exec",
            remediation: "Deobfuscate and review code before execution. Obfuscation is suspicious.",
        },
    ]
});

pub fn get_patterns() -> &'static [ThreatPattern] {
    &PATTERNS
}
