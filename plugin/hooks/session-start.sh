#!/bin/bash
# SessionStart — ensure ~/bin/che-keychain is current, then print a banner.
#
# che-mcps servers auto-download via their .mcp.json wrapper, triggered by the
# MCP server launch every session. che-keychain is a CLI with no MCP launch, so
# this hook supplies the missing per-session trigger by INVOKING the same
# bin/ wrapper (the single download authority) — keeping download logic in one
# place rather than duplicating it here. The wrapper compares ~/bin/che-keychain
# to the pinned binaryVersion, downloads if missing/stale, then execs it.
set -u

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
WRAPPER="$PLUGIN_ROOT/bin/che-keychain"
BINARY="$HOME/bin/che-keychain"

# Trigger the wrapper (downloads/updates ~/bin/che-keychain as needed, then execs
# the real binary's --version). Wrapper progress goes to stderr; we read stdout.
VER=""
if [[ -x "$WRAPPER" ]]; then
    VER=$("$WRAPPER" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
[[ -z "$VER" && -x "$BINARY" ]] && VER=$("$BINARY" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

if [[ -x "$BINARY" ]]; then
    echo "✓ che-keychain v${VER:-unknown} installed: $BINARY"
else
    echo "⚠ che-keychain not installed — wrapper download may have failed (check network / GitHub release)"
fi
