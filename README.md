# che-keychain

A trust-isolated credential prompt for the macOS keychain. The user types into a **native dialog rendered by this signed binary** — the caller (LLM, MCP server, shell script) never observes the input, only learns success / failure.

## Why

Every CLI / MCP that needs to store an API key or password has a UX problem:

- `read -s` in a shell script: leaks across odd shells, depends on TTY behavior
- Asking the LLM to handle the value: the secret lands in the conversation transcript
- Custom getpass per tool: every tool re-implements the same prompt, none of them are shared / trusted

`che-keychain` is one signed binary that owns the input UI. Callers invoke it; it pops a native NSAlert; the user types; the value is written to keychain via `SecItemAdd`. The caller's process never sees the typed string — they get an exit code.

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

# Check existence without revealing the value
che-keychain has --service my-api --account token   # exit 0 if present

# Remove
che-keychain unset --service my-api --account token
che-keychain unset --service my-api                 # removes all accounts under service
```

Exit codes: `0` success, `1` error, `2` user cancelled.

## Security model

| Path | What the caller sees |
|------|----------------------|
| Caller invokes `che-keychain set --service X --account Y --secure` | exit code, stderr message |
| User types into NSSecureTextField inside this binary's process | (only this binary sees it) |
| Binary calls `SecItemAdd` to write to `login.keychain-db` | (only this binary holds the value in memory, briefly) |
| Anyone reads it back later via `SecItem*` | needs the same service+account and proper keychain access |

Key properties:

- **Caller never sees the value** — typed input is read in this binary's process via AppKit text fields. It is not piped through stdin / args / env from the caller. An LLM driving the caller (a tool that runs this CLI) cannot observe the input.
- **Dialog shows the destination** — `service` and `account` are rendered in the alert's informative text so the user can verify a malicious caller isn't redirecting writes to a misleading key.
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
swift test            # run unit tests (20 tests covering arg parsing, keychain round-trip, dialog text)
make release          # ad-hoc-signed release binary in release/ (dev only)
make release-signed   # signed + notarized for distribution
```

The NSAlert dialog itself isn't unit-tested (it needs a real GUI session); pure helpers (`buildInformativeText`, arg parsing, keychain wrappers) have full coverage.

## License

MIT. See [LICENSE](./LICENSE).
