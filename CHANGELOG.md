# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `set` / `set-pair` on an existing item: the behaviour now depends on who created it (#5). Before, `save()` ran `SecItemDelete` (status discarded) then `SecItemAdd`, so an item created by another program surfaced as `errSecDuplicateItem` (-25299) with no explanation.
  - **Decrypt ACL trusts this binary and nothing else** → value updated in place (`SecItemUpdate`, bound to the inspected item); with `--daemon` the item is deleted by reference and re-added with the allow-all ACL (`SecItemUpdate` cannot change an ACL: it unions entries instead of replacing them). The old value is read first and the old item re-added if the add fails.
  - **"Allow all applications" item** (what `--daemon` writes, but also `security add-generic-password -A`) → carries no owner identity, and any label in it can be forged, so it is never claimed as ours: `set --daemon` updates the value in place (the item is world-readable by construction), plain `set` refuses and names `unset` (switching a daemon item back to prompt-on-read is `unset` then `set`).
  - **Created by another program** (e.g. the `security` CLI, or another copy of che-keychain at a different path), or an item whose ACL cannot be attributed → **refused before the dialog opens**, printing the exact `che-keychain unset --service 'S' --account 'A'` command (shell-quoted) and a warning that it deletes that program's secret. Rationale: `SecItemUpdate` would succeed but leave the new secret inside an item another program manages — and with `--daemon` it silently appended an allow-all ACL entry to that item (the round-1 fix, reverted). Replacing another program's secret is destructive, so it is an explicit `unset`, never a side effect of `set`. Such items are prompt-on-read for other programs, not unreadable; the constraint is ownership.
  - Root cause of the original -25299, pinned down by probe: `SecItemDelete` — by query or by `kSecMatchItemList` — answers `errSecInvalidOwnerEdit` (-25244) on an item another program created, and the old `save()` discarded that status before `SecItemAdd`. `SecKeychainItemDelete(ref)` deletes such items fine; `unset` now uses it.
  - Ownership is decided fail-closed from the item's decrypt ACL: every trusted application must be this binary's real path (an item that also trusts `security` or another copy of che-keychain is foreign, and the co-trusted applications are printed); unreadable or undecodable ACL → refused with the OSStatus.
  - `set` and `set-pair` run the same refusal check for every account **before** the dialog, so a refusal (foreign / allow-all under plain set / ambiguous) is never raised after a secret was typed or after the first account of a pair was stored.
  - More than one item matching `service/account` (e.g. across keychains) is refused as ambiguous instead of writing to whichever one the API picks.
- `unset` deletes each matching item by reference (`SecKeychainItemDelete`), so it also removes items created by other programs — previously the query-based loop threw at the first `-25244` and left the remaining items in place. The sweep now continues past any item it cannot remove (a refused delete, or a match that is not a file-keychain item) and then reports how many were removed and every item that was not, with the `security` remedy — nothing is skipped in silence.
- `-25244` error hint corrected: it now says the keychain refused the owner edit and names `security delete-generic-password` as the remedy (the old text wrongly claimed the ACL could not be changed).
- `--service` / `--account` also reject DEL (0x7f), alongside the control characters already rejected, since they are echoed into the remedy commands.

## [0.2.0] — 2026-06-09

First release since 0.1.0. Both changes below were merged to `main` (PR #2 on 2026-05-29, PR #3 on 2026-06-09) and the source `Version.swift` was bumped to 0.2.0, but no release was ever cut — so every installed `~/bin/che-keychain` was still the 0.1.0 binary, missing both. This release ships them.

### Added

- `set --daemon` — store the item with an **allow-all ACL** (programmatic equivalent of `security add-generic-password -A`) via the legacy `SecAccess`/`SecACL` API through `kSecAttrAccess`, so a headless launchd agent can read the credential with no `SecurityAgent` prompt. Trust-isolation is preserved: `--daemon` relaxes only the storage ACL; the value is still typed into che-keychain's signed NSAlert, never seen by the caller. Use only for low-sensitivity creds a daemon must read unattended (PR #3).

### Fixed

- Credential dialog now accepts **Cmd+V paste** (and Cmd+C / Cmd+X / Cmd+A). `NSAlert.runModal()` runs without a main menu, so macOS had no key-equivalent binding to dispatch `paste:` to the focused text field — the secure password field silently swallowed paste. Fixed by installing a minimal standard Edit menu before the dialog runs (`installEditMenuIfNeeded`, PR #2).

## [0.1.0] — 2026-05-23

First public release. Initial CLI surface.

### Added

- `set` subcommand — prompt for a single credential (visible or `--secure` masked) and write to keychain
- `set-pair` subcommand — prompt for two credentials (e.g. id + secret) in **one** native NSAlert with multi-field accessory view; visible field above, secure field below
- `has` subcommand — check existence by service+account, exit 0/1 without revealing the value
- `unset` subcommand — remove a single account or all accounts under a service (loops `SecItemDelete` because macOS removes one matching item per call)
- `--version`, `--help` flags
- Native macOS NSAlert dialog with destination (`service=X account=Y`) shown in informative text so the user can verify a caller isn't redirecting writes
- `KeychainStore` wrappers around `SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete` for `kSecClassGenericPassword` items in the default keychain (`login.keychain-db`)
- Pure `CommandParser` independently testable (no AppKit / no I/O dependencies)
- 20 unit tests covering arg parsing, validation (identifier sanity, duplicate-account guard in `set-pair`), and live keychain round-trip with UUID-suffixed test services so test runs never pollute real data
- Makefile targets: `build`, `test`, `release`, `release-signed`, `install`, `verify-release-ready`, `clean`
- `scripts/build-release.sh` — universal arm64+x86_64 binary build with ad-hoc or Developer ID signing + Apple notarization via `xcrun notarytool`
- MIT license, README + CLAUDE.md, .gitignore

### Architecture notes

- Caller never observes the typed value — input flows directly from NSSecureTextField in this binary's process to `SecItemAdd`. No stdin pipe, no args, no env vars.
- Storage targets `login.keychain-db` (local, not iCloud-synced). Items are invisible to Safari's Passwords app — only Keychain Access.app shows them.
- No value-read API (`get` subcommand) is intentional: the consumer of a stored secret should call `SecItemCopyMatching` itself under its own service identifier, keeping che-keychain a write-only trust boundary.

[Unreleased]: https://github.com/PsychQuant/che-keychain/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PsychQuant/che-keychain/releases/tag/v0.1.0
