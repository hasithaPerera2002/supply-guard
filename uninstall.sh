#!/bin/bash
set -e

echo "Uninstalling SupplyGuard..."

# Stop and unload daemon
if sudo launchctl list | grep -q supplyguard; then
    sudo launchctl stop com.supplyguard.daemon
    sudo launchctl unload /Library/LaunchDaemons/com.supplyguard.daemon.plist
fi

# Remove files
sudo rm -f /usr/local/bin/supplyguard
sudo rm -f /Library/LaunchDaemons/com.supplyguard.daemon.plist
sudo rm -rf /var/log/supplyguard

# Note: User data in ~/.supplyguard is preserved
echo "✓ SupplyGuard uninstalled"
echo "Note: User data in ~/.supplyguard has been preserved"
