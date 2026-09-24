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

Exit codes you should react to (`set` / `set-pair`, 0.3.0+): `0` stored and verified · `1` any other error, including "the new value did not land" — nothing is removed after the keychain accepts the write, though a rotation or `--replace` deleted the previous item before adding (see stderr — it says whether the slot is unchanged, holds a value that read back wrong and was left in place, is empty as far as the command can see, holds a restore of the previous value (verified or not), holds another item found there (left alone), or is unknown) · `2` user cancelled · `3` write accepted but could not be verified (cleanup leaves the destination alone; keychain locked or ambiguous match) · `4` a restore was accepted whose bytes or access settings do not match the backup — the destination holds an item that is not the one that was backed up; inspect it in Keychain Access, do not remove it on this report alone. Plain `has`: `0` present, `1` absent.

## Discipline

1. **Always pick a meaningful `--label` and `--explain`** — the user sees them in the dialog. "Enter your API token" beats default account-name placeholder. `set --label` sets the dialog title and input field's label only; it does not set the stored item's label in Keychain Access. For `set-pair`, use `--visible-label` / `--secure-label` for the two field labels and `--title` for the dialog title.
2. **Service names should be globally unique-ish** — prefix with your tool's namespace (`che-transport-tdx`, `my-app-deploy-key`). Don't reuse common names like `default` / `api-key`.
3. **The destination shown in the dialog is non-negotiable** — che-keychain renders `service=X account=Y` in the informative text. Users can verify it. Don't rely on a custom label hiding the real destination.
4. **che-keychain has no `get` subcommand on purpose** — your consumer binary reads the value itself with `SecItemCopyMatching` under the same service/account. (Since 0.3.0 every `set` reads its own write back and compares it, so a `0` exit means the value is really there; that read-back is internal and never printed.)
5. **`has` before re-prompting** — if `che-keychain has --service X --account Y` exits 0, the entry already exists; ask the user before re-running `set`. Without `--replace`, `set` replaces only an item this binary alone can read (its dialog says so on the first line); an item created by another program, or any allow-all (`--daemon`) item, is REFUSED — never overwritten silently. The refusal names `set --replace` (which backs up the old value only until the new one is verified) and the exact `che-keychain unset` command (which destroys the old value); both are the user's decision — see rules 6 and 7. Plain `has` cannot distinguish an empty item. Use `has --non-empty` when appropriate: 0 non-empty bytes, 1 absent, 2 empty, 3 unavailable. The opt-in check reads only a single own item without interaction; foreign/allow-all/ambiguous/unreadable items return 3, not empty.
6. **`--stdin` is not a dialog** — the caller already holds the value, so use it only from automation the user trusts; it refuses to turn an existing item whose plaintext is not already open to every application into a daemon-readable one. Never use it to avoid the dialog for a value the user should type or copy themselves. `--replace --stdin` deletes and replaces a readable foreign item with no dialog at all. Without `--daemon` the other application's access to the old value ends. With `--daemon` on an allow-all item the result is worse: every program that read the old item keeps reading the same service/account and now gets the value the caller chose, silently. Never pass `--replace` on the user's behalf without their explicit say-so.
7. **Never delete an item on your own initiative** — deleting is the user's decision, because it destroys the only copy of the old value. When `set` refuses an item (rule 5), or `set --replace` reports it cannot establish a restorable backup, tell the user what was reported. If they need the old value kept, it has to be managed with whatever can read it — for a backup refusal che-keychain holds no copy of it. If THEY decide it is expendable, `che-keychain unset` then `che-keychain set` is the path. That two-step is not the routine rotation: rotating che-keychain's own `--daemon` item is `set --replace --daemon` (with the user's say-so), which backs up the old value first and puts it back only if adding the new value itself fails and the slot is then observed empty. It is not atomic: the old item is deleted before the new one is added, so a reader can find nothing in between. After that delete there are exactly five outcomes — a closed list, do not infer others: (1) the new value is added and reads back correctly — exit 0; (2) the add itself fails — the old value is written back only if the slot is then observed empty, and the report names which of these happened: restored and verified; restored but not verifiable; restored but not matching the backup (exit 4); not restored because another item was found there (left alone); or not restored / the restore failed, so the destination's state is unknown — every one of these except the mismatch exits 1; (3) the add succeeds but nothing is found at the destination on read-back — no restore is attempted, and the destination is empty as far as the command can see (exit 1); (4) the add succeeds but the value reads back empty or different — it is left in place and reported, so a reader gets that wrong value (exit 1); (5) the add succeeds but the read-back is unreadable or matches more than one item — it is left in place, unverified (exit 3). This list is for `set --replace`. Plain `set` over this binary's own item also deletes before adding, under the same restore rule — The old value is written back only if adding the new value itself fails, a copy of the old value was obtained before the delete, and the destination is then empty; otherwise it is not written back, and the report says what the destination holds. Plain `set` obtains that copy only when it can read the old value without a prompt; `set --replace` does not start without one. — and its report and exit code follow the exit-code list above (exit 4 included).

For an explicitly requested rotation, `set --replace` can replace a readable foreign/allow-all item after backing up its bytes and checking that its original access policy can be reproduced. A temporary nonsecret probe is created and removed before deletion. If backup or recovery validation fails, follow the exact report; do not claim that the old value/access was restored without verification. This is not an atomic operation, and the stdin ACL-widening guard still applies.

When the binary moves to a different physical path, retain strict ownership checks. Use the original copy to update its items. `set --replace` from the new copy works when the new copy can read the old value with prompts disabled. Observed 2026-09-23: a byte-identical copy of the same build at another path completed `set --replace` and `set --replace --daemon` on items the original created; a copy re-signed ad hoc under another identifier was refused at the backup read, leaving the item untouched. Whether a different Developer ID-signed release is admitted has not been tested — do not promise it either way. A matching code signature is what was observed to work; a matching signing team alone is not evidence. Do not treat a matching filename or signing team as automatic replacement permission, and do not delete an item to get around a failed backup unless the user decides the old value is expendable (rule 7).

## Security boundary

The caller (this agent, this MCP, this script) is **outside** the trust boundary for the typed value. che-keychain is **inside**. The OS keychain is **inside**. The user types into che-keychain's process; the value flows: dialog → SecItemAdd. Caller never on the path.

This means: for the confidentiality of a value the user types, it doesn't matter how much the caller is trusted — the design works even with a fully-untrusted caller (some random script the user ran), and the native dialog showing service+account is the trust anchor. That guarantee is about the typed value only. The paths with no dialog (`--stdin`, and above all `--replace --stdin [--daemon]`) let the caller decide what is stored and what is replaced, so they protect nothing against an untrusted caller: use them only from automation the user trusts (rule 6).

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
