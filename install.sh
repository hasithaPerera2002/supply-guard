#!/bin/bash
set -e

echo "Installing SupplyGuard..."

# Build release binary
cargo build --release

# Create /usr/local/bin if it doesn't exist
sudo mkdir -p /usr/local/bin

# Copy binary
sudo cp target/release/supplyguard /usr/local/bin/
sudo chown root:wheel /usr/local/bin/supplyguard
sudo chmod 755 /usr/local/bin/supplyguard

# Create directories
sudo mkdir -p /var/log/supplyguard
sudo mkdir -p /var/db/supplyguard/quarantine
mkdir -p ~/.supplyguard/quarantine

# Create default config (if it doesn't exist)
# Ensure HOME is set for config init
export HOME="${HOME:-$(eval echo ~$(whoami))}"
if [ -z "$HOME" ] || [ "$HOME" = "/" ]; then
    # Fallback: try to get home from whoami
    export HOME="/Users/$(whoami)"
fi

# Check if config already exists
CONFIG_PATH="$HOME/.supplyguard/config.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "Initializing config..."
    # Try to init config, but don't fail the install if it errors
    # The daemon will create a default config on first run if needed
    set +e  # Temporarily disable exit on error
    supplyguard config init 2>&1
    EXIT_CODE=$?
    set -e  # Re-enable exit on error
    if [ $EXIT_CODE -eq 0 ]; then
        echo "Config initialized successfully"
    elif [ $EXIT_CODE -eq 137 ]; then
        echo "Warning: Config init was killed (SIGKILL - may be a permissions/security issue)"
        echo "The daemon will create a default config on first run if needed"
    else
        echo "Warning: Config init failed (exit code: $EXIT_CODE)"
        echo "The daemon will create a default config on first run if needed"
    fi
else
    echo "Config already exists at $CONFIG_PATH"
fi

# Install launchd plist
sudo cp com.supplyguard.daemon.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.supplyguard.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/com.supplyguard.daemon.plist

# Load and start
sudo launchctl unload /Library/LaunchDaemons/com.supplyguard.daemon.plist 2>/dev/null || true
sudo launchctl load /Library/LaunchDaemons/com.supplyguard.daemon.plist
sudo launchctl start com.supplyguard.daemon

# Verify
sleep 2
if sudo launchctl list | grep -q supplyguard; then
    echo "✓ SupplyGuard installed and running"
    supplyguard status
else
    echo "✗ Installation failed"
    exit 1
fi
