#!/bin/bash
# SupplyGuard npm wrapper - intercepts npm install commands

# Find real npm binary
REAL_NPM=""
for path in /usr/bin/npm /usr/local/bin/npm /opt/homebrew/bin/npm "$(which npm 2>/dev/null | grep -v '/usr/local/bin/npm')"; do
    if [ -x "$path" ] && [ "$path" != "$0" ]; then
        REAL_NPM="$path"
        break
    fi
done

if [ -z "$REAL_NPM" ]; then
    echo "Error: Could not find npm binary" >&2
    exit 1
fi

# Check if this is an install command
INSTALL_CMD=false
PACKAGE=""
VERSION=""

for arg in "$@"; do
    case "$arg" in
        install|i|add)
            INSTALL_CMD=true
            ;;
        --save|--save-dev|--save-optional|--save-peer|--save-prod|-S|-D|-O|-P)
            # These are flags, continue
            ;;
        *)
            if [ "$INSTALL_CMD" = true ] && [[ ! "$arg" =~ ^- ]]; then
                # Extract package name and version
                if [[ "$arg" =~ ^(.+)@(.+)$ ]]; then
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
    echo "🔍 SupplyGuard: Scanning package $PACKAGE${VERSION:+@$VERSION}..."
    
    if supplyguard scan-package npm "$PACKAGE" ${VERSION:+"$VERSION"} 2>&1; then
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

# Execute real npm command
exec "$REAL_NPM" "$@"
