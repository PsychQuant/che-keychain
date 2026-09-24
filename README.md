# che-keychain

A trust-isolated credential prompt for the macOS keychain. The user types into a **native dialog rendered by this signed binary** — the caller (LLM, MCP server, shell script) never observes the input, only learns success / failure. Two more sources exist since 0.3.0: `--from-clipboard` (a confirmation dialog shows the destination, the value comes from the clipboard) and `--stdin` (for automation; the caller supplies the value, so nothing is hidden from it). Every store is read back and verified.

## Why

Every CLI / MCP that needs to store an API key or password has a UX problem:

- `read -s` in a shell script: leaks across odd shells, depends on TTY behavior
- Asking the LLM to handle the value: the secret lands in the conversation transcript
- Custom getpass per tool: every tool re-implements the same prompt, none of them are shared / trusted

`che-keychain` is one signed binary that owns the input UI. Callers invoke it; it pops a native NSAlert; the user types; the value is written to keychain via `SecItemAdd` (plain set recreates items trusted to this binary alone; --replace additionally permits eligible backed-up items; nothing is ever updated in place). The caller's process never sees the typed string — they get an exit code.

## Install

```bash
# From a GitHub release tag (recommended — signed + notarized)
curl -fsSL https://github.com/PsychQuant/che-keychain/releases/latest/download/CheKeychain \
  -o ~/bin/che-keychain && chmod +x ~/bin/che-keychain

# Or build from source
git clone https://github.com/PsychQuant/che-keychain
cd che-keychain
make install   # → ~/bin/che-keychain
```

## Usage

```bash
# Single secret — masked input
che-keychain set --service my-api --account token --secure \
  --label "Enter your API token" \
  --explain "Used by the deploy script."

# ID + secret pair — one dialog, two fields (id visible, secret masked)
che-keychain set-pair --service che-transport-tdx \
  --visible-account client_id \
  --secure-account client_secret \
  --title "TDX setup" \
  --explain "Free TDX account: https://tdx.transportdata.tw/register"

# Paste-free: copy the token; a confirmation dialog shows the destination, whether
# an item already exists there, and a fingerprint of the value (length + SHA-256
# prefix — a screen observer could confirm a guess of a LOW-entropy secret from
# it; Return does nothing, Esc cancels); the clipboard is emptied once the store
# is verified, and only if it still holds what was read
che-keychain set --service my-api --account token --from-clipboard

# Automation: exactly one line from a pipe (a terminal is refused); no dialog —
# the caller holds the value, so use this only from automation you trust
printf '%s\n' "$TOKEN" | che-keychain set --service my-api --account token --stdin

# Every store (set-pair included) is read back and compared; an empty or
# whitespace-only value is refused. The exit code says whether the NEW value
# landed: 1 = no (nothing is removed after the write is accepted, though a
# rotation deleted the previous item first; the report says whether the
# destination is unchanged, holds a value that read back wrong and was left in
# place, is empty as far as the command can see, holds a restore of the previous
# value (verified or not), holds another item found there (left alone), or is unknown),
# 3 = it is in the slot but could not be verified (locked keychain), 4 = a
# restore did not match the backup — inspect the destination before retrying.

# Check existence without revealing the value
che-keychain has --service my-api --account token   # exit 0 if present

# Remove
che-keychain unset --service my-api --account token
che-keychain unset --service my-api                 # removes all accounts under service
```

Exit codes for `set` / `set-pair`: `0` stored and verified · `1` any other error, including "the new value did not land" — nothing is removed after the keychain accepts the write (a rotation or `--replace` has already deleted the previous item before adding); the message says whether the slot is unchanged, holds a value that read back empty or different and was left in place (a name lookup cannot show it is this write's), is empty as far as the command can see, holds a restore of the previous value (verified or not) (only after a failed add, only into an empty slot), holds another item found there (left alone), or is unknown · `2` user cancelled · `3` write accepted but unverified (cleanup leaves the destination alone) · `4` a restore was accepted that differs from the backup in what was compared (the bytes; under `--replace` also the access settings and keychain) — the destination holds an item that is not the one that was backed up; inspect it in Keychain Access before retrying, and do not remove it on this report alone; for `set-pair`, `3`/`4` refer to the account named in the message. `has` without `--non-empty`: `0` present, `1` absent. `unset`: `0`, or `1` when some match could not be removed.

Dialog labels only affect the prompt: `set --label` sets both the dialog title and the input field's label. For `set-pair`, `--visible-label` and `--secure-label` label the two input fields, while `--title` sets the dialog title. None of these options sets the stored item's label in Keychain Access.

`set-pair` remains dialog-only: it does not accept `--stdin`, `--from-clipboard`, or `--daemon`. This keeps both values in one explicit input dialog without introducing an ambiguous two-value stream format. For automation, invoke `set --stdin` separately for each account and check each exit code. The two writes are not an atomic transaction: if the second fails, the first may already be stored. Each write retains its own read-back verification and the exit-code contract above.

Keychain errors from `set`, `set-pair`, or `unset`, including write-verification and restore failures, may include a numeric `OSStatus` followed by a description supplied by macOS. That description can vary with the system language; use the numeric OSStatus when searching for an error, rather than matching the localized wording. For example, `OSStatus -25299` identifies a duplicate-item error regardless of the description's language.

The CLI exit codes listed above describe the command's outcome; they are separate from the underlying OSStatus values in diagnostics. Scripts should use the CLI exit code to determine the outcome and should not depend on the exact stderr wording. `has` without `--non-empty` reports only exit code `0` or `1` and does not print these keychain error descriptions.

`has --non-empty --service S --account A` is an optional, read-only value-shape check: exit `0` means a nonzero byte count, `1` means absent, `2` means present with zero bytes, and `3` means the check was unavailable. It checks only a single item exclusively trusted to this executable with interaction disabled; foreign, allow-all (including `--daemon`), ambiguous and unreadable items return `3`. It never reveals the value or changes the item. Whitespace bytes count as non-empty; this does not validate a token or establish another program's read permission. Plain `has` retains its original existence-only behavior.

Input dialogs show caller-provided explanations in a separate, labeled area. The fixed destination and replacement warning stay together above it; long caller text is shortened to keep them visible. `set-pair` names each account that will be replaced and checks each account's observed existence state again at its write. These checks reject new-versus-existing changes; they do not make the two writes atomic or detect a value change when the item still exists.

Exit `1` also covers cleanup that was not attempted because the destination could not be identified safely. That is not a failed delete: no deletion OSStatus is invented, and the report asks you to inspect the destination rather than blindly remove it. Ambiguous matches require inspection in Keychain Access; unlocking alone does not resolve them. On a pair failure, the report retains the first account's complete diagnosis.

## Security model

| Path | What the caller sees |
|------|----------------------|
| Caller invokes `che-keychain set --service X --account Y --secure` | exit code, stderr message |
| User types into NSSecureTextField inside this binary's process | (only this binary sees it) |
| Caller invokes `… --from-clipboard` | exit code, stderr; the pasteboard itself is readable by the caller and every process. A confirmation dialog (destination + whether an item already exists there + value fingerprint; Return does nothing, Esc cancels) gates the store; the clipboard is emptied afterwards if unchanged |
| Caller invokes `… --stdin` | the caller supplies the value, so it holds it already; no dialog — the destination goes to stderr. Trusted automation only. With `--daemon` it refuses — at write time, inside `save()` — to replace an existing item whose plaintext is not already open to every application (an allow-all entry that only permits wrapped export does not count); a new allow-all item can still be created |
| Binary calls `SecItemAdd` to write to `login.keychain-db`; an existing item is re-created (delete by reference + add, old value read back when possible, for the restore rule in the explicit-replacement section below, which covers plain `set` too) by default only if its ACL trusts this binary alone; without --replace, anything else (another trusted application, or an allow-all entry — including our own `--daemon` items) is refused before the dialog opens; the refusal offers `set --replace` (backup held only while it runs) and `unset` (discards the old value), both the user's decision | (only this binary holds the value in memory, briefly) |
| Anyone reads it back later via `SecItem*` | needs the same service+account and proper keychain access |
| Copies of the value in this process | Only one buffer is wiped: the stdin buffer the value is assembled in is zeroed on every exit of the read (tested on a success and on a throwing path); the chunks read into it are Foundation's own buffers and are released unwiped. Everything else is released without a wipe — the dialog's field, the clipboard string, the new value's string, every read-back, `has --non-empty`'s read, and the copies of the OLD value a rotation or `--replace` holds while it runs (the backup, the preflight check's copy, the pre-delete re-read, a plain rotation's copy). Values read from the keychain arrive bridged from a buffer the Security framework allocated; zeroing the Swift value only zeroes a fresh copy, so che-keychain does not try (observed, and pinned by a test). The pasteboard is emptied only after a verified store and only if unchanged |

Key properties:

- **Caller never sees the value** (dialog only) — the value is read in this binary's process from an AppKit text field; it is not passed through args / env / stdin from the caller. The two other sources do not have this property: with `--from-clipboard` the value sits on the system pasteboard, which the caller (and any process) can read; with `--stdin` the caller pipes it in. Use them where that is acceptable.
- **Dialog shows the destination** — `service` and `account` are rendered in the alert's informative text (the input dialog, and the confirmation dialog `--from-clipboard` shows, which also shows a fingerprint of the value; Return does nothing there, Esc cancels) so the user can verify a malicious caller isn't redirecting writes to a misleading key. `--stdin` has no dialog: it prints the destination on stderr, which a caller can swallow — so `--stdin` is for trusted automation only, and a caller using it can overwrite an item this binary created without a human in the loop.
- **Storage is local** — items go to `login.keychain-db`, not iCloud Keychain. They don't appear in Safari's Passwords app; only in Keychain Access.app.
- **Identifiers are sanity-checked** — empty / control-character service / account names are rejected.

What this does NOT do:

- Read other apps' keychain items (Safari passwords, iCloud Keychain, Passwords.app). Those have separate ACLs and access groups; a generic CLI without those entitlements cannot reach them — by design.
- Provide a value-read API. By design the caller can `has` but not `get`. Reading a stored secret is the consumer binary's job, with its own keychain code (`SecItemCopyMatching`), under its own service identifier.

## Explicit replacement

Use `set --replace` when deliberately replacing an existing foreign or allow-all item, including an existing daemon credential:

```bash
che-keychain set --service my-api --account token --replace --secure
che-keychain set --service my-daemon --account token --replace --daemon --secure
```

Without `--replace`, the existing refusal policy is unchanged. With it, the binary must read the old bytes without interaction and capture the original keychain and access settings before deletion. It reconstructs supported ACL entries in a fresh access object and first verifies the resulting policy (including partition IDs) using a uniquely named temporary item containing only nonsecret probe data. If the backup is unreadable, the policy cannot be reproduced, the probe cannot be removed, or a destination change is observed, the original item is not deleted. A probe cleanup failure reports the probe's identifier for inspection in Keychain Access.

The old value is written back only if adding the new value itself fails, a copy of the old value was obtained before the delete, and the destination is then empty; even then the write-back can fail. Otherwise it is not written back, and the report says what the destination holds or that its state is unknown. Plain `set` and `set-pair` obtain that copy only when they can read the old value without a prompt, and never write back an empty one; `set --replace` does not start without a copy. What is written back is read back: `set --replace` restores the original access settings and compares the bytes, access settings and keychain with the backup; plain `set` and `set-pair` re-create the old value as an item only this binary can read and compare the bytes only. Exit 4 means the comparison found a difference; a comparison that could not be made exits 1. Replacement is not atomic, does not preserve label/comment/date metadata, and does not guarantee zero downtime under arbitrary OS failures. Exit `0` requires a verified new value; failures retain the documented `1`/`3`/`4` outcomes. Success output identifies the previous ownership classification without revealing either value.

`--replace --stdin --daemon` can rotate a backed-up item whose plaintext is already open to every application, but still refuses to widen plaintext access to any other existing item without a dialog. `--replace --stdin` without `--daemon` replaces a readable foreign item with one only this binary can read — the other application's access to the old value ends, with no dialog, so use it only from automation the user trusts. `set-pair` does not support `--replace`. The flag is not a way to bypass unreadable-backup, ambiguous-match or unsupported-keychain refusals. In particular, `--replace` needs to read the old value with prompts disabled (it is the backup that goes back if adding the new value fails and the slot is then empty; even then the write-back can fail), so it refuses any item whose value cannot be read that way — items created by `security add-generic-password` are one tested case. Nothing is deleted. If the old value must be kept, manage the item with whatever can read it; if the user decides it is expendable — the user's decision, not the caller's — `che-keychain unset` then `che-keychain set` replaces it. che-keychain holds no copy of the old value, so that choice discards it.

## Moving or reinstalling the executable

Ownership checks compare resolved executable paths. A symlink to the same executable is treated as the same path; a separate copy at another location is treated as foreign, even if macOS permits that copy to read the item. Matching filenames or a shared signing team do not automatically authorize replacement.

After moving or reinstalling the binary, use the original copy to update its items. `set --replace` from the new copy works when the new copy can read the old value without interaction and reproduce its access policy. Observed on 2026-09-23: a byte-identical copy of the same build at another path completed `set --replace` (and `set --replace --daemon`) on items the original had created, with the backup, replacement and read-back all passing; a copy re-signed ad hoc under another identifier was refused at the backup read, and the original item was left untouched. Those are the two cases observed. Whether a different Developer ID-signed release — the usual upgrade — is admitted has not been tested; try `set --replace` and read the report, which changes nothing when it refuses. Do not assume that being able to read a credential grants permission to silently replace it. If the old value is no longer needed, `che-keychain unset` followed by `che-keychain set` is the way through — that is a decision to discard the old value, so make it deliberately.

## Daemon access

`--daemon` sets an "allow all applications" application ACL. It does not bypass partition-ID authorization or unlock the keychain, and it does not guarantee that another executable can read the item without a prompt. Verify access using the actual consuming executable in its intended background session. A successful store verifies the writer's own read-back, not the consumer's access.

On macOS 27.0 (26A428), a Developer ID-signed 0.3.0 writer stored and verified a test item with `--stdin --daemon`, but a separate ad-hoc reader using `SecItemCopyMatching` with interaction disabled returned `-25293` (`errSecAuthFailed`). The item still had an allow-all application ACL. This demonstrates the cross-executable limitation; it does not by itself prove which authorization check rejected the reader.

If the consumer needs a different partition list, the system tool is `security set-generic-password-partition-list`. First identify the exact item, the intended consumer's signing identity, and the partitions that must remain authorized. The command replaces the partition list; do not apply a blanket list to unrelated items. For example, after substituting the selected service, account, keychain and required partition IDs:

```bash
security set-generic-password-partition-list \
  -s 'SERVICE' -a 'ACCOUNT' -S 'REQUIRED_PARTITION_IDS' 'KEYCHAIN_PATH'
```

Run this interactively and omit `-k`: the tool prompts for the keychain password rather than placing it in arguments or shell history. Do not provide that password to an agent. Changing the partition list grants access and requires a deliberate choice of consumers; `che-keychain` does not perform this step automatically. An inaccessible item should be reported as inaccessible, not treated as an empty or missing credential.

## Signing & notarization

Release builds (`make release-signed`) are signed with the maintainer's Developer ID Application certificate and notarized by Apple. Verify:

```bash
codesign --verify --strict --verbose=2 ~/bin/che-keychain
spctl -a -t exec -vv ~/bin/che-keychain
```

For maintainer setup (one-time):

```bash
xcrun notarytool store-credentials che-mcps-notary \
  --apple-id <your-apple-id> --team-id <your-team-id> --password <app-specific-pwd>

export DEVELOPER_ID=<cert-SHA-1>
export NOTARY_PROFILE=che-mcps-notary
make release-signed
```

## Development

```bash
swift build           # debug build
swift test            # run unit tests (42 tests covering arg parsing, keychain round-trip, dialog text)
make release          # ad-hoc-signed release binary in release/ (dev only)
make release-signed   # signed + notarized for distribution
```

The NSAlert dialog itself isn't unit-tested (it needs a real GUI session); pure helpers (`buildInformativeText`, arg parsing, keychain wrappers) have full coverage.

## License

MIT. See [LICENSE](./LICENSE).
