# che-keychain (plugin shell)

Plugin distribution wrapper for the `che-keychain` CLI binary.

## What this plugin does

- Exposes `che-keychain` in the Bash tool's `PATH` while enabled
- On first invocation, the wrapper script (`bin/che-keychain`) downloads the **signed + notarized** binary from the [PsychQuant/che-keychain GitHub Release](https://github.com/PsychQuant/che-keychain/releases) to `~/bin/che-keychain`
- Subsequent calls `exec` the cached binary directly — `~/bin/che-keychain` is the single canonical location all consumers reference
- SessionStart hook prints a one-line status banner (installed version, or "not yet downloaded")

## Why ~/bin and not the plugin cache?

Other tools — `CheTransportMCP --setup`, future MCPs, ad-hoc scripts — need to find `che-keychain` via PATH from any process context. Claude Code adds plugin `bin/` to the **Bash tool's** PATH only; MCP server processes and external scripts don't inherit it. `~/bin/` is the stable, system-wide install location that all of those can find.

## Versioning

`plugin.json` carries two fields, like `che-transport-mcp`:

- `version` — plugin-shell version (this directory's contents)
- `binaryVersion` — the `CheKeychain` GitHub Release tag the wrapper will target

A shell-only bump (skill, doc, wrapper logic) ticks `version` without touching `binaryVersion`. A binary release ticks both in lockstep.

## See also

- Top-level [README.md](../README.md) — full project overview, install via curl
- Top-level [CLAUDE.md](../CLAUDE.md) — agent interaction discipline
- Source code: `../Sources/CheKeychain/`
