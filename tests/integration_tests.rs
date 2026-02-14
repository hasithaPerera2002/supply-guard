use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_vscode_autorun_detection() {
    let temp_dir = TempDir::new().unwrap();
    let tasks_path = temp_dir.path().join(".vscode").join("tasks.json");
    
    fs::create_dir_all(tasks_path.parent().unwrap()).unwrap();
    fs::copy("tests/fixtures/malicious_tasks.json", &tasks_path).unwrap();

    let scanner = scanner::ScannerEngine::new(10);
    let result = scanner.scan_file(&tasks_path).await.unwrap();

    assert!(!result.is_clean);
    assert!(result.threats.len() >= 4); // Should detect VSCODE_AUTORUN, CURL_PIPE_SHELL, URL_SHORTENER, HIDDEN_EXECUTION
}

#[tokio::test]
async fn test_package_json_detection() {
    let temp_dir = TempDir::new().unwrap();
    let package_path = temp_dir.path().join("package.json");
    
    fs::copy("tests/fixtures/malicious_package.json", &package_path).unwrap();

    let scanner = scanner::ScannerEngine::new(10);
    let result = scanner.scan_file(&package_path).await.unwrap();

    assert!(!result.is_clean);
    assert!(result.threats.len() >= 2); // Should detect curl and wget patterns
}

#[tokio::test]
async fn test_git_hook_detection() {
    let temp_dir = TempDir::new().unwrap();
    let hook_path = temp_dir.path().join(".git").join("hooks").join("pre-commit");
    
    fs::create_dir_all(hook_path.parent().unwrap()).unwrap();
    fs::copy("tests/fixtures/malicious_git_hook.sh", &hook_path).unwrap();

    let scanner = scanner::ScannerEngine::new(10);
    let result = scanner.scan_file(&hook_path).await.unwrap();

    assert!(!result.is_clean);
    assert!(result.threats.len() >= 2); // Should detect curl and reverse shell
}

#[tokio::test]
async fn test_setup_py_detection() {
    let temp_dir = TempDir::new().unwrap();
    let setup_path = temp_dir.path().join("setup.py");
    
    fs::copy("tests/fixtures/malicious_setup.py", &setup_path).unwrap();

    let scanner = scanner::ScannerEngine::new(10);
    let result = scanner.scan_file(&setup_path).await.unwrap();

    assert!(!result.is_clean);
    assert!(result.threats.len() >= 1); // Should detect module-level execution
}

#[tokio::test]
async fn test_build_rs_detection() {
    let temp_dir = TempDir::new().unwrap();
    let build_path = temp_dir.path().join("build.rs");
    
    fs::copy("tests/fixtures/malicious_build.rs", &build_path).unwrap();

    let scanner = scanner::ScannerEngine::new(10);
    let result = scanner.scan_file(&build_path).await.unwrap();

    assert!(!result.is_clean);
    assert!(result.threats.len() >= 1); // Should detect Command::new("sh")
}
