# CLAUDE.md — che-keychain

This file is read by LLM agents (Claude Code, Codex, etc.) that invoke `che-keychain` from a tool or skill.

## What this CLI is

A trust-isolated credential prompt: an AI/script/MCP asks `che-keychain` to collect a secret; che-keychain pops a **native macOS dialog rendered inside its own signed binary**; the user types; the value goes to keychain via `SecItemAdd`. The caller never receives the typed string.

## When to invoke from an agent

Use `che-keychain` whenever you'd otherwise need to:

- Print a copy-paste `security add-generic-password -w "SECRET"` command for the user (they'd have to retype, secret risks landing in shell history)
- Open a Terminal window via `open -a Terminal <some-setup-script.sh>` just for `read -s` (works but heavier UX than a native dialog)
- Ask the user for a secret in chat (DON'T — leaks to transcript)

## Invocation patterns

```bash
# Single secret — masked
che-keychain set --service <svc> --account <acct> --secure --label "<prompt>"

# ID + secret pair — one dialog
che-keychain set-pair --service <svc> \
  --visible-account <id_account> --secure-account <secret_account> \
  --title "<title>"

# Check existence (does NOT reveal value)
che-keychain has --service <svc> --account <acct>

# Remove
che-keychain unset --service <svc> [--account <acct>]
```

Exit codes you should react to: `0` ok, `1` error (see stderr), `2` user cancelled.

## Discipline

1. **Always pick a meaningful `--label` and `--explain`** — the user sees them in the dialog. "Enter your API token" beats default account-name placeholder.
2. **Service names should be globally unique-ish** — prefix with your tool's namespace (`che-transport-tdx`, `my-app-deploy-key`). Don't reuse common names like `default` / `api-key`.
3. **The destination shown in the dialog is non-negotiable** — che-keychain renders `service=X account=Y` in the informative text. Users can verify it. Don't rely on a custom label hiding the real destination.
4. **Read-back is NOT che-keychain's job** — your consumer binary should do its own `SecItemCopyMatching` under the same service/account. che-keychain has no `get` subcommand on purpose.
5. **`has` before re-prompting** — if `che-keychain has --service X --account Y` exits 0, the entry already exists; ask the user before re-running `set` and overwriting.

## Security boundary

The caller (this agent, this MCP, this script) is **outside** the trust boundary for the typed value. che-keychain is **inside**. The OS keychain is **inside**. The user types into che-keychain's process; the value flows: dialog → SecItemAdd. Caller never on the path.

This means: it doesn't matter how much the caller is trusted. The design works even with a fully-untrusted caller (some random script the user ran). The native dialog showing service+account is the trust anchor.

## What the binary does NOT do

- Read Safari / iCloud Keychain / Passwords.app entries — those require separate entitlements no third-party CLI has
- Sync to iCloud — items go to `login.keychain-db` only
- Provide a value-read API — by design

## Files

- `Sources/CheKeychain/main.swift` — entry, argv parsing, command dispatch
- `Sources/CheKeychain/Commands.swift` — pure `CommandParser` (unit-tested)
- `Sources/CheKeychain/KeychainStore.swift` — `SecItem*` wrappers (unit-tested via round-trip)
- `Sources/CheKeychain/PromptDialog.swift` — `NSAlert` + accessory `NSStackView` with text fields (GUI parts manual-tested; pure helpers unit-tested)
- `Sources/CheKeychain/Version.swift` — single source of truth for version + help text

## Adding subcommands

Pattern: extend `enum Command` + add a parser in `CommandParser` + add a case in `main.swift`. Keep the parser pure (no I/O, no AppKit). Add tests in `Tests/CheKeychainTests/CommandParserTests.swift`.

## Sibling projects (consumers)

- [che-transport-mcp](https://github.com/PsychQuant/che-transport-mcp) — `CheTransportMCP --setup` delegates to `che-keychain set-pair` when found in PATH
- (others will be added as they migrate to this credential-prompt pattern)
