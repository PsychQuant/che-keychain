#!/usr/bin/env bash
# scripts/build-release.sh
# Build universal binary + (optionally) Developer ID sign + notarize.
#
# Modes:
#   default                — universal binary + ad-hoc sign (dev iteration only)
#   REQUIRE_CODESIGN=1     — Developer ID sign + xcrun notarytool submit --wait
#
# Env vars required when REQUIRE_CODESIGN=1:
#   DEVELOPER_ID           — Developer ID Application cert SHA-1 fingerprint
#   NOTARY_PROFILE         — keychain profile name set up via `notarytool store-credentials`
#
# Output:
#   release/CheKeychain          — universal binary
#   release/CheKeychain.sha256   — hash file (for download-integrity checks)

set -euo pipefail

BINARY_NAME="CheKeychain"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_DIR="$REPO_ROOT/release"

# Parse version from Version.swift — single source of truth.
SOURCE_VERSION=$(grep -E 'static let version = "' "$REPO_ROOT/Sources/CheKeychain/Version.swift" | sed -E 's/.*"([^"]+)".*/\1/')
if [[ -z "$SOURCE_VERSION" ]]; then
    echo "✗ Could not parse AppVersion.version from Version.swift" >&2
    exit 1
fi
echo "→ Building che-keychain v$SOURCE_VERSION"

# Step 1: universal binary.
swift build -c release --arch arm64 --arch x86_64
BUILT="$REPO_ROOT/.build/apple/Products/Release/$BINARY_NAME"
if [[ ! -f "$BUILT" ]]; then
    echo "✗ Built binary not found at $BUILT" >&2
    exit 1
fi
mkdir -p "$RELEASE_DIR"
cp "$BUILT" "$RELEASE_DIR/$BINARY_NAME"

# Step 2: sign.
if [[ "${REQUIRE_CODESIGN:-}" == "1" ]]; then
    : "${DEVELOPER_ID:?DEVELOPER_ID not set}"
    : "${NOTARY_PROFILE:?NOTARY_PROFILE not set}"
    echo "→ Signing with Developer ID $DEVELOPER_ID"
    codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" "$RELEASE_DIR/$BINARY_NAME"

    echo "→ Submitting to Apple notarization (1-15 min)"
    NOTARY_ZIP="$RELEASE_DIR/notarize-$BINARY_NAME-$SOURCE_VERSION.zip"
    ditto -c -k --keepParent "$RELEASE_DIR/$BINARY_NAME" "$NOTARY_ZIP"
    xcrun notarytool submit "$NOTARY_ZIP" \
        --keychain-profile "$NOTARY_PROFILE" \
        --wait
    rm -f "$NOTARY_ZIP"
    echo "✓ Notarized — binary validates online on first launch"
else
    echo "→ Ad-hoc signing (dev iteration only)"
    codesign --force --sign - "$RELEASE_DIR/$BINARY_NAME"
fi

# Step 3: emit sha for download-integrity checks.
HASH=$(shasum -a 256 "$RELEASE_DIR/$BINARY_NAME" | awk '{print $1}')
echo "$HASH" > "$RELEASE_DIR/$BINARY_NAME.sha256"

echo ""
echo "✓ Release artefacts:"
echo "  - $RELEASE_DIR/$BINARY_NAME ($HASH)"
echo ""
echo "Next steps for distribution:"
echo "  1. git tag v$SOURCE_VERSION && git push --tags"
echo "  2. gh release create v$SOURCE_VERSION $RELEASE_DIR/$BINARY_NAME $RELEASE_DIR/$BINARY_NAME.sha256 --repo PsychQuant/che-keychain --title 'v$SOURCE_VERSION'"
