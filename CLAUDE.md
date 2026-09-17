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

# Paste-free (0.3.0+): the user copies the secret, then confirms a dialog that
# names the destination and shows a fingerprint of the value; the clipboard is
# emptied after the store is verified. Prefer this over asking the user to paste.
che-keychain set --service <svc> --account <acct> --from-clipboard

# Trusted automation only (0.3.0+): exactly one line from a pipe, NO dialog
printf '%s\n' "$VALUE" | che-keychain set --service <svc> --account <acct> --stdin

# Check existence (does NOT reveal value)
che-keychain has --service <svc> --account <acct>

# Remove
che-keychain unset --service <svc> [--account <acct>]
```

Exit codes you should react to (`set` / `set-pair`, 0.3.0+): `0` stored and verified · `1` any other error, including "the new value did not land" (see stderr — it says whether the slot is unchanged, holds the restored previous value, is empty, or has an unknown state) · `2` user cancelled · `3` write accepted but could not be verified (cleanup leaves the destination alone; keychain locked or ambiguous match) · `4` a provably bad item is stuck at the destination — run the `unset` the message gives, then retry. `has`: `0` present, `1` absent.

## Discipline

1. **Always pick a meaningful `--label` and `--explain`** — the user sees them in the dialog. "Enter your API token" beats default account-name placeholder. `set --label` sets the dialog title and input field's label only; it does not set the stored item's label in Keychain Access. For `set-pair`, use `--visible-label` / `--secure-label` for the two field labels and `--title` for the dialog title.
2. **Service names should be globally unique-ish** — prefix with your tool's namespace (`che-transport-tdx`, `my-app-deploy-key`). Don't reuse common names like `default` / `api-key`.
3. **The destination shown in the dialog is non-negotiable** — che-keychain renders `service=X account=Y` in the informative text. Users can verify it. Don't rely on a custom label hiding the real destination.
4. **che-keychain has no `get` subcommand on purpose** — your consumer binary reads the value itself with `SecItemCopyMatching` under the same service/account. (Since 0.3.0 every `set` reads its own write back and compares it, so a `0` exit means the value is really there; that read-back is internal and never printed.)
5. **`has` before re-prompting** — if `che-keychain has --service X --account Y` exits 0, the entry already exists; ask the user before re-running `set`. `set` replaces only an item this binary alone can read (its dialog says so on the first line); an item created by another program, or any allow-all (`--daemon`) item, is REFUSED with the exact `che-keychain unset` command to run first — never overwritten silently. Note `has` cannot tell an empty item from a real one (#13).
6. **`--stdin` is not a dialog** — the caller already holds the value, so use it only from automation the user trusts; it refuses to turn an existing prompt-on-read item into a daemon-readable one. Never use it to avoid the dialog for a value the user should type or copy themselves.

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
- `Sources/CheKeychain/KeychainStore.swift` — `SecItem*` wrappers: ownership inspection, refusal policy, write + read-back verification, cleanup outcomes and exit codes (unit-tested against the real login keychain)
- `Sources/CheKeychain/InputSource.swift` — the clipboard and stdin value sources and their one-line rules (unit-tested)
- `Sources/CheKeychain/PromptDialog.swift` — `NSAlert` + accessory `NSStackView` with text fields, and the confirmation-only alert for `--from-clipboard` (GUI parts manual-tested via `scripts/gui-walkthrough.sh` — only the Developer ID-signed build presents dialogs on macOS 27, see #16; pure helpers unit-tested)
- `Sources/CheKeychain/Version.swift` — single source of truth for version + help text

## Adding subcommands

Pattern: extend `enum Command` + add a parser in `CommandParser` + add a case in `main.swift`. Keep the parser pure (no I/O, no AppKit). Add tests in `Tests/CheKeychainTests/CommandParserTests.swift`.

## Sibling projects (consumers)

- [che-transport-mcp](https://github.com/PsychQuant/che-transport-mcp) — `CheTransportMCP --setup` delegates to `che-keychain set-pair` when found in PATH
- (others will be added as they migrate to this credential-prompt pattern)
