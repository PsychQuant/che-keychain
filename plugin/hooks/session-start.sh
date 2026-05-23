#!/bin/bash
# SessionStart — surface che-keychain install state at session start. Single
# line so the banner stays compact.

set -u

INSTALL_NAME="che-keychain"
BINARY="$HOME/bin/$INSTALL_NAME"
VERSION_FILE="$HOME/bin/.${INSTALL_NAME}.version"

if [[ -x "$BINARY" ]]; then
    VERSION="$(tr -d '[:space:]' < "$VERSION_FILE" 2>/dev/null || echo 'unknown')"
    echo "✓ che-keychain v${VERSION} installed: $BINARY"
else
    echo "ℹ che-keychain not yet downloaded — will install on first invocation (or run \`che-keychain --version\` to seed now)"
fi
