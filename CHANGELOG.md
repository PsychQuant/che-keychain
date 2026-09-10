# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `set` / `set-pair` on an existing item: the behaviour now depends on who created it (#5). Before, `save()` ran `SecItemDelete` (status discarded) then `SecItemAdd`, so an item created by another program surfaced as `errSecDuplicateItem` (-25299) with no explanation.
  - **Created by this binary, same ACL mode** → value updated in place (`SecItemUpdate`, bound to the inspected item).
  - **Created by this binary, other mode** (`--daemon` on a prompt-on-read item or vice versa) → deleted and re-added with the requested ACL. `SecItemUpdate` cannot do this: it unions ACL entries instead of replacing them.
  - **Created by another program** (e.g. the `security` CLI, or another copy of che-keychain at a different path), or an item whose ACL cannot be attributed → **refused before the dialog opens**, printing the exact `che-keychain unset --service 'S' --account 'A'` command (shell-quoted) and a warning that it deletes that program's secret. Rationale: `SecItemUpdate` would succeed but leave the new secret inside an item another program manages — and with `--daemon` it silently appended an allow-all ACL entry to that item (the round-1 fix, reverted). Replacing another program's secret is destructive, so it is an explicit `unset`, never a side effect of `set`. Such items are prompt-on-read for other programs, not unreadable; the constraint is ownership.
  - Root cause of the original -25299, pinned down by probe: `SecItemDelete` — by query or by `kSecMatchItemList` — answers `errSecInvalidOwnerEdit` (-25244) on an item another program created, and the old `save()` discarded that status before `SecItemAdd`. `SecKeychainItemDelete(ref)` deletes such items fine; `unset` now uses it.
  - Ownership is decided fail-closed from the item's decrypt ACL: any trusted-application list that does not contain this binary's real path → foreign; only allow-all entries → ours only if one carries the label `service/account` that `--daemon` writes; unreadable ACL → refused.
  - `set-pair` checks both accounts before the dialog, so a refusal can no longer follow a write of the first account.
  - More than one item matching `service/account` (e.g. across keychains) is refused as ambiguous instead of writing to whichever one the API picks.
- `unset` deletes each matching item by reference (`SecKeychainItemDelete`), so it also removes items created by other programs — previously the query-based loop stopped at the first `-25244` and left the rest untouched without a word. Should a delete still answer `-25244`, the sweep continues and the first such item is reported afterwards.
- `-25244` error hint corrected: it now says the item belongs to another program and names `che-keychain unset` as the remedy (the old text wrongly claimed the ACL could not be changed).

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
