#!/bin/bash
# SessionStart — ENSURE ~/bin/che-keychain matches the plugin's binaryVersion
# (download if missing/stale), then print a status banner.
#
# Why download here and not only in the bin/ wrapper: che-keychain is a CLI, not
# an MCP, so the wrapper only fires when something explicitly invokes
# `che-keychain` — which may never happen on a given machine, and a stale
# standalone ~/bin/che-keychain can shadow the plugin wrapper in PATH. Doing the
# ensure at session start means "restart Claude Code" reliably gets the pinned
# binary on every machine that has the plugin. Download logic mirrors the
# che-mcps rush-wrapper.sh (pinned tag -> latest, atomic .tmp+mv, soft-fail).
set -u

REPO="PsychQuant/che-keychain"
ASSET="CheKeychain"                                   # release asset (capitalised)
INSTALL_DIR="${CHE_KEYCHAIN_BIN_DIR:-$HOME/bin}"
BINARY="$INSTALL_DIR/che-keychain"                    # installed lowercase
VERSION_FILE="$INSTALL_DIR/.che-keychain.version"

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PLUGIN_JSON="$PLUGIN_ROOT/.claude-plugin/plugin.json"

DESIRED=""
if [[ -f "$PLUGIN_JSON" ]]; then
    DESIRED=$(grep -oE '"binaryVersion":[[:space:]]*"[^"]+"' "$PLUGIN_JSON" 2>/dev/null | head -1 | cut -d'"' -f4 || true)
    [[ -z "$DESIRED" ]] && DESIRED=$(grep -oE '"version":[[:space:]]*"[^"]+"' "$PLUGIN_JSON" 2>/dev/null | head -1 | cut -d'"' -f4 || true)
fi

installed_version() { [[ -x "$BINARY" ]] && "$BINARY" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }
INSTALLED="$(installed_version)"

NEED=false
if [[ ! -x "$BINARY" ]]; then NEED=true
elif [[ -n "$DESIRED" && "$INSTALLED" != "$DESIRED" ]]; then NEED=true
fi

if $NEED; then
    mkdir -p "$INSTALL_DIR"
    for URL in \
        "${DESIRED:+https://github.com/$REPO/releases/download/v$DESIRED/$ASSET}" \
        "https://github.com/$REPO/releases/latest/download/$ASSET"
    do
        [[ -z "$URL" ]] && continue
        if curl -fsSL --max-time 120 "$URL" -o "${BINARY}.tmp" 2>/dev/null; then
            chmod +x "${BINARY}.tmp" && mv -f "${BINARY}.tmp" "$BINARY"
            INSTALLED="$(installed_version)"
            [[ -n "$INSTALLED" ]] && printf '%s' "$INSTALLED" > "$VERSION_FILE"
            break
        fi
        rm -f "${BINARY}.tmp" 2>/dev/null
    done
fi

if [[ -x "$BINARY" ]]; then
    echo "✓ che-keychain v${INSTALLED:-unknown} installed: $BINARY"
else
    echo "⚠ che-keychain not installed — manual: curl -fsSL https://github.com/$REPO/releases/latest/download/$ASSET -o $BINARY && chmod +x $BINARY"
fi
