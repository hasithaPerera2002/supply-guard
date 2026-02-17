#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Print logo
echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║                                                           ║"
echo "  ║   ${BOLD}${YELLOW}███████╗██╗   ██╗██████╗ ██╗     ██╗    ██╗${NC}${CYAN}   ║"
echo "  ║   ${BOLD}${YELLOW}██╔════╝██║   ██║██╔══██╗██║     ██║    ██║${NC}${CYAN}   ║"
echo "  ║   ${BOLD}${YELLOW}███████╗██║   ██║██████╔╝██║     ██║ █╗ ██║${NC}${CYAN}   ║"
echo "  ║   ${BOLD}${YELLOW}╚════██║██║   ██║██╔═══╝ ██║     ██║███╗██║${NC}${CYAN}   ║"
echo "  ║   ${BOLD}${YELLOW}███████║╚██████╔╝██║     ███████╗╚███╔███╔╝${NC}${CYAN}   ║"
echo "  ║   ${BOLD}${YELLOW}╚══════╝ ╚═════╝ ╚═╝     ╚══════╝ ╚══╝╚══╝ ${NC}${CYAN}   ║"
echo "  ║                                                           ║"
echo "  ║   ${GREEN}🛡️  Supply Chain Attack Detection & Protection${NC}${CYAN}   ║"
echo "  ║   ${NC}${CYAN}              Real-time Threat Monitoring${NC}${CYAN}              ║"
echo "  ║                                                           ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${BOLD}${BLUE}Installing SupplyGuard...${NC}"

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
    echo -e "${CYAN}Initializing config...${NC}"
    # Try to init config, but don't fail the install if it errors
    # The daemon will create a default config on first run if needed
    set +e  # Temporarily disable exit on error
    supplyguard config init 2>&1
    EXIT_CODE=$?
    set -e  # Re-enable exit on error
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}✓ Config initialized successfully${NC}"
    elif [ $EXIT_CODE -eq 137 ]; then
        echo -e "${YELLOW}Warning: Config init was killed (SIGKILL - may be a permissions/security issue)${NC}"
        echo -e "${CYAN}The daemon will create a default config on first run if needed${NC}"
    else
        echo -e "${YELLOW}Warning: Config init failed (exit code: $EXIT_CODE)${NC}"
        echo -e "${CYAN}The daemon will create a default config on first run if needed${NC}"
    fi
else
    echo -e "${GREEN}Config already exists at ${CYAN}$CONFIG_PATH${NC}"
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
    echo -e "\n${GREEN}✓ SupplyGuard installed and running${NC}\n"
    supplyguard status
    echo ""
    echo -e "${CYAN}Checking logs for any errors...${NC}"
    echo -e "${YELLOW}--- Error log (last 20 lines) ---${NC}"
    sudo tail -20 /var/log/supplyguard/error.log 2>/dev/null || echo -e "${RED}No error log found${NC}"
    echo ""
    echo -e "${YELLOW}--- Daemon log (last 20 lines) ---${NC}"
    sudo tail -20 /var/log/supplyguard/daemon.log 2>/dev/null || echo -e "${RED}No daemon log found${NC}"
else
    echo -e "${RED}✗ Installation failed${NC}"
    exit 1
fi
