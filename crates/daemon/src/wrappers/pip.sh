#!/bin/bash
# SupplyGuard pip wrapper - intercepts pip install commands

# Find real pip binary
REAL_PIP=""
for path in /usr/bin/pip /usr/local/bin/pip /opt/homebrew/bin/pip "$(which pip 2>/dev/null | grep -v '/usr/local/bin/pip')" "$(which pip3 2>/dev/null | grep -v '/usr/local/bin/pip')"; do
    if [ -x "$path" ] && [ "$path" != "$0" ]; then
        REAL_PIP="$path"
        break
    fi
done

if [ -z "$REAL_PIP" ]; then
    echo "Error: Could not find pip binary" >&2
    exit 1
fi

# Check if this is an install command
INSTALL_CMD=false
PACKAGE=""
VERSION=""

for arg in "$@"; do
    case "$arg" in
        install)
            INSTALL_CMD=true
            ;;
        --upgrade|-U|--user|--no-deps|--force-reinstall)
            # These are flags, continue
            ;;
        *)
            if [ "$INSTALL_CMD" = true ] && [[ ! "$arg" =~ ^- ]]; then
                # Extract package name and version
                if [[ "$arg" =~ ^(.+)==(.+)$ ]]; then
                    PACKAGE="${BASH_REMATCH[1]}"
                    VERSION="${BASH_REMATCH[2]}"
                elif [[ "$arg" =~ ^(.+)@(.+)$ ]]; then
                    PACKAGE="${BASH_REMATCH[1]}"
                    VERSION="${BASH_REMATCH[2]}"
                else
                    PACKAGE="$arg"
                fi
            fi
            ;;
    esac
done

# If installing a specific package, scan it first
if [ "$INSTALL_CMD" = true ] && [ -n "$PACKAGE" ]; then
    echo "🔍 SupplyGuard: Scanning package $PACKAGE${VERSION:+==$VERSION}..."
    
    if supplyguard scan-package pip "$PACKAGE" ${VERSION:+"$VERSION"} 2>&1; then
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

# Execute real pip command
exec "$REAL_PIP" "$@"
