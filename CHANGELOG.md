# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
