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
mkdir -p ~/.supplyguard/quarantine

# Create default config
supplyguard config init

# Install launchd plist
sudo cp com.supplyguard.daemon.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.supplyguard.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/com.supplyguard.daemon.plist

# Load and start
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
