# che-keychain

A trust-isolated credential prompt for the macOS keychain. The user types into a **native dialog rendered by this signed binary** — the caller (LLM, MCP server, shell script) never observes the input, only learns success / failure. Two more sources exist since 0.3.0: `--from-clipboard` (a confirmation dialog shows the destination, the value comes from the clipboard) and `--stdin` (for automation; the caller supplies the value, so nothing is hidden from it). Every store is read back and verified.

## Why

Every CLI / MCP that needs to store an API key or password has a UX problem:

- `read -s` in a shell script: leaks across odd shells, depends on TTY behavior
- Asking the LLM to handle the value: the secret lands in the conversation transcript
- Custom getpass per tool: every tool re-implements the same prompt, none of them are shared / trusted

`che-keychain` is one signed binary that owns the input UI. Callers invoke it; it pops a native NSAlert; the user types; the value is written to keychain via `SecItemAdd` (an existing item that this binary alone is trusted for is deleted by reference and re-added; nothing is ever updated in place). The caller's process never sees the typed string — they get an exit code.

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
# landed: 1 = no (a garbled store is removed again; on a rotation the previous
# value is re-stored and the report states exactly which outcome happened),
# 3 = it is in the slot but could not be verified (locked keychain), 4 = a
# provably bad item is stuck there — run the `unset` the report gives first.

# Check existence without revealing the value
che-keychain has --service my-api --account token   # exit 0 if present

# Remove
che-keychain unset --service my-api --account token
che-keychain unset --service my-api                 # removes all accounts under service
```

Exit codes for `set` / `set-pair`: `0` stored and verified · `1` any other error, including "the new value did not land" (the slot is unchanged, holds the restored previous value, or is empty — the message says which) · `2` user cancelled · `3` stored but unverified (the item is left in place) · `4` a provably bad item is stuck at the destination (`unset` it, then retry); for `set-pair`, `3`/`4` refer to the account named in the message. `has`: `0` present, `1` absent. `unset`: `0`, or `1` when some match could not be removed.

## Security model

| Path | What the caller sees |
|------|----------------------|
| Caller invokes `che-keychain set --service X --account Y --secure` | exit code, stderr message |
| User types into NSSecureTextField inside this binary's process | (only this binary sees it) |
| Caller invokes `… --from-clipboard` | exit code, stderr; the pasteboard itself is readable by the caller and every process. A confirmation dialog (destination + whether an item already exists there + value fingerprint; Return does nothing, Esc cancels) gates the store; the clipboard is emptied afterwards if unchanged |
| Caller invokes `… --stdin` | the caller supplies the value, so it holds it already; no dialog — the destination goes to stderr. Trusted automation only. With `--daemon` it refuses — at write time, inside `save()` — to replace an existing prompt-on-read item; a new allow-all item can still be created |
| Binary calls `SecItemAdd` to write to `login.keychain-db`; an existing item is re-created (delete by reference + add, old value read back only to restore it if the add fails) only if its ACL trusts this binary alone; anything else (another trusted application, or an allow-all entry — including our own `--daemon` items) is refused before the dialog opens and must be removed explicitly with `unset` first | (only this binary holds the value in memory, briefly) |
| Anyone reads it back later via `SecItem*` | needs the same service+account and proper keychain access |

Key properties:

- **Caller never sees the value** (dialog only) — the value is read in this binary's process from an AppKit text field; it is not passed through args / env / stdin from the caller. The two other sources do not have this property: with `--from-clipboard` the value sits on the system pasteboard, which the caller (and any process) can read; with `--stdin` the caller pipes it in. Use them where that is acceptable.
- **Dialog shows the destination** — `service` and `account` are rendered in the alert's informative text (the input dialog, and the confirmation dialog `--from-clipboard` shows, which also shows a fingerprint of the value and cancels on Return) so the user can verify a malicious caller isn't redirecting writes to a misleading key. `--stdin` has no dialog: it prints the destination on stderr, which a caller can swallow — so `--stdin` is for trusted automation only, and a caller using it can overwrite an item this binary created without a human in the loop.
- **Storage is local** — items go to `login.keychain-db`, not iCloud Keychain. They don't appear in Safari's Passwords app; only in Keychain Access.app.
- **Identifiers are sanity-checked** — empty / control-character service / account names are rejected.

What this does NOT do:

- Read other apps' keychain items (Safari passwords, iCloud Keychain, Passwords.app). Those have separate ACLs and access groups; a generic CLI without those entitlements cannot reach them — by design.
- Provide a value-read API. By design the caller can `has` but not `get`. Reading a stored secret is the consumer binary's job, with its own keychain code (`SecItemCopyMatching`), under its own service identifier.

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
