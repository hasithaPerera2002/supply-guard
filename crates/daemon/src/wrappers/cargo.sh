#!/bin/bash
# SupplyGuard cargo wrapper - intercepts cargo add and build commands

# Find real cargo binary
REAL_CARGO=""
for path in /usr/bin/cargo /usr/local/bin/cargo /opt/homebrew/bin/cargo "$HOME/.cargo/bin/cargo" "$(which cargo 2>/dev/null | grep -v '/usr/local/bin/cargo')"; do
    if [ -x "$path" ] && [ "$path" != "$0" ]; then
        REAL_CARGO="$path"
        break
    fi
done

if [ -z "$REAL_CARGO" ]; then
    echo "Error: Could not find cargo binary" >&2
    exit 1
fi

# Check if this is an add or build command
SCAN_CMD=false
PACKAGE=""
VERSION=""

for arg in "$@"; do
    case "$arg" in
        add|build)
            SCAN_CMD=true
            ;;
        --version|-v|--features|--no-default-features|--path|--git)
            # These are flags, continue
            ;;
        *)
            if [ "$SCAN_CMD" = true ] && [[ ! "$arg" =~ ^- ]]; then
                if [ "$1" = "add" ]; then
                    # Extract package name and version from cargo add
                    if [[ "$arg" =~ ^(.+):(.+)$ ]]; then
                        PACKAGE="${BASH_REMATCH[1]}"
                        VERSION="${BASH_REMATCH[2]}"
                    else
                        PACKAGE="$arg"
                    fi
                fi
            fi
            ;;
    esac
done

# If adding a package, scan it first
if [ "$1" = "add" ] && [ -n "$PACKAGE" ]; then
    echo "🔍 SupplyGuard: Scanning package $PACKAGE${VERSION:+:$VERSION}..."
    
    if supplyguard scan-package cargo "$PACKAGE" ${VERSION:+"$VERSION"} 2>&1; then
        echo "✓ Package scan passed, proceeding with installation..."
    else
        echo ""
        echo "⚠️  SupplyGuard detected threats in this package!"
        echo ""
        read -p "Do you want to proceed anyway? (yes/no): " -r
        echo
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            echo "Installation cancelled."
            exit 1
        fi
        echo "Proceeding with installation (user confirmed)..."
    fi
fi

# Execute real cargo command
exec "$REAL_CARGO" "$@"
