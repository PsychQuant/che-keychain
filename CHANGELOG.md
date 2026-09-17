# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Pair consent uses a fail-closed existence snapshot for both accounts, identifies each replacement and passes both claims to save for rechecking. Input-dialog explanations are separated from fixed destination/warning text, with bounded caller text (#14).

- Cleanup refused before a delete now reports a specific refusal with exit 1, not an invented deletion OSStatus or an instruction to remove an unverified item. A rejected restore may leave the destination unknown; exit-code documentation now includes that state (#15).
- Ambiguous read-back directs the user to inspect the matching items; a pair's second-store failure retains the first store's full diagnostic. stdin registers its best-effort buffer wipe before reading, drops long-lived Data slices, and removes the unused EOF flag (#15).
- A clipboard destination that becomes unwritable before confirmation is refused without a contradictory replacement warning. Both set dialog sources check their stated existence claim at write time; pair parity is tracked in #14 (#15).
- Correct the identifier note: C1 controls are refused by set/set-pair, while has/unset retain raw names so legacy items remain reachable (#15).

## [0.3.0] — 2026-09-11

### Changed (values)

- Values are never altered silently. The dialog and both `set-pair` fields store exactly what was typed (as before); `--from-clipboard` and `--stdin` drop only LF/CR at the ends of the value (a paste usually carries a trailing newline) and REFUSE a value with leading or trailing whitespace, a line break inside (any Unicode line separator), or control / format characters (C0, C1, DEL, Cf) — the same predicate `--service` / `--account` already use ("it would be stored as typed"). `--stdin` skips leading blank lines but hands the value's own line over untouched. An empty or whitespace-only value is refused for every caller, `set-pair` included (#6).

### Added

- `set --from-clipboard`: reads the clipboard's text, then shows a confirmation dialog (no input field — the paste problem lived in the input field) with the destination and a fingerprint of the value (length + SHA-256 prefix); Return does nothing, Esc cancels, Store needs a click or ⌘S; the dialog says whether an item already exists at the destination; nothing is stored if the clipboard changed while the dialog was open. Once the value is stored and read back, the clipboard is emptied (every type on it) if it still holds what was read — a clipboard manager or Universal Clipboard may keep a copy; on failure it is left as is. Note the pasteboard is readable by the caller and every process; this source trades the dialog's secrecy for paste-safety. `set --stdin`: takes exactly one line from a pipe, stopping at the line break (LF or CR) without waiting for EOF; refused rather than guessed: a terminal (interactive paste is what bracketed-paste control sequences mangle), invalid UTF-8, more than 64 KiB, no complete line within 30 s, or a second line of content that arrived within 100 ms of the first (a slower writer's later lines are not detected — best-effort). `--stdin` shows no dialog: the caller already holds the value, so it is for trusted automation only and can overwrite an item this binary created without a human in the loop; the destination is printed on stderr. `--stdin --daemon` refuses to replace an existing prompt-on-read item (no dialog may widen an ACL) — decided inside `save()` at write time, so a probe error fails closed and nothing can change between check and write; it can still create a new allow-all item. The stdin read has a 30 s total deadline. The two are mutually exclusive, and `--secure` / `--label` / `--explain` are refused with them. The value never enters argv or stdout (#6).
- Every store is verified: after writing, the item is looked up with the same scope as the pre-write check and its value read back by reference (keychain prompts disabled) and compared byte-for-byte. The exit code answers one question — did the new value land? `1`: no — an empty or different value was removed again; on a rotation the previous value is re-stored and itself read back, and the report distinguishes a verified restore, a restore the keychain accepted but could not read back, and a slot left empty (and why). `3`: it is in the slot but could not be verified (locked keychain, or an ambiguous match); on a rotation the report says it replaced the previous value. `4`: a provably bad item is stuck — its removal was refused, or the restored previous value reads back wrong — and the report gives the `unset` command to run first. Missing → reported as nothing verified stored (exit 1). The same rule applies to `set-pair` and to the recovery after a failed replace. The exit code is non-zero in every mismatch case and the message states exactly what was done. An empty or whitespace-only value is refused in `save()` itself, so it covers all three `set` sources and `set-pair` (#6).

### Fixed

- `set` on an existing item no longer fails with `errSecDuplicateItem` (-25299): an item whose ACL trusts this binary alone is replaced; anything else is refused with the exact command to run first (#5).

### Changed (BREAKING)

- **`set` can now exit non-zero after a write the keychain accepted.** Every store is read back; when the read-back cannot prove the value (locked keychain, a prompt-gated item) the command exits 3 and leaves the item in place, and a value that reads back wrong is removed again (exit 1; exit 4 when the removal is refused, or when the previous value re-stored after a failed rotation or a failed replace itself reads back wrong). 0.2.x exited 0 in all of these cases. There is no opt-out: automation that only tests `$?` must treat 3 as "stored, unverified" (#6).
- **`set --daemon` on an existing daemon item no longer succeeds.** Any item with an "allow all applications" entry — which is exactly what `--daemon` writes — is refused in both modes because such an entry carries no owner identity. Rotating a daemon credential is now two commands: `che-keychain unset --service S --account A` then `che-keychain set --service S --account A --secure --daemon`. Scripts that re-ran `set --daemon` to rotate a token must add the `unset`. A one-step explicit form (`--replace`) is tracked as a follow-up.
- `unset` prints what it removed (`✓ removed N account(s) under S: a, b`) or `nothing to remove under S`, and exits non-zero when some match could not be removed. Wrappers that matched the old `✓ removed S/A` line, or relied on exit 0 after a partial sweep, must adapt. The wording of every keychain error on stderr changed too (operation names, plus the system's text for the OSStatus).
- `set` now sees every match in the keychain search list, iCloud-synchronized / data-protection twins included: two matches (a second keychain, or a twin) are refused as ambiguous, and a twin alone (no local item) is refused as unsupported — both stored fine before, because the old delete query never looked there. `unset` removes what it can and points at Keychain Access for the rest. An own item that lives in a secondary keychain is re-created in that same keychain.
- `set --daemon` success line now reads `✓ stored S/A (daemon-readable: any process can read it without a prompt)`.

- `--service` / `--account` (set / set-pair) now also reject C1 control characters (U+0080–U+009F); 0.2.x accepted them. The same predicate governs the clipboard and stdin value sources.
- `set-pair`: a first store that is "stored but unverified" (exit 3) no longer aborts the pair — the second value is stored too and the command exits 3 at the end; only an outcome that leaves nothing usable stops it.
- The failed-replace recovery (#5's `replaceFailed`) now reads the restored previous value back and reports one of four outcomes (restored / restored but unverifiable / reads back wrong / lost, with the reason) instead of a bare restored-or-not; its wording changed accordingly.
- `set` / `set-pair` on an existing item: the behaviour now depends on what its decrypt ACL says (#5). Before, `save()` ran `SecItemDelete` (status discarded) then `SecItemAdd`, so an item created by another program surfaced as `errSecDuplicateItem` (-25299) with no explanation.
  - **Decrypt ACL trusts this binary and nothing else** → the item is deleted by reference and re-created with the new value and the requested ACL (`--daemon` = allow-all). An in-place `SecItemUpdate` was rejected in review: it keeps whatever ACL the item already has, including an owner entry another program may have pre-planted. The old value is read first (best-effort, keychain prompts disabled) and re-stored as prompt-on-read if the add fails; if it could not be read, the failure report says so.
  - **Decrypt ACL trusts any other application** (the `security` CLI, another copy of che-keychain at a different path, an app the user once clicked "Always Allow" for) → **refused before the dialog opens**, listing the trusted applications and printing the exact `che-keychain unset --service 'S' --account 'A'` command (shell-quoted) with a warning that it deletes the stored secret.
  - **Any "allow all applications" decrypt entry** (what `--daemon` writes, but also `security add-generic-password -A`; alone or mixed with an application list) → refused in **both** modes: such an entry names no application, its label can be forged, so the item cannot be attributed to anyone. Re-setting an existing daemon item is `unset` then `set --daemon`.
  - **Not a file-keychain item** (data-protection / iCloud keychain) → refused: che-keychain cannot inspect its ACL. For an iCloud-synchronized item `unset` tries the generic keychain API and reports the status if that fails; for a plain data-protection item Keychain Access is the only path.
  - Rationale for refusing rather than updating (user decision after verify round 1): `SecItemUpdate` succeeds on an item another program created, but that leaves the new secret inside an item that program manages — and with `--daemon` it silently appended an allow-all ACL entry to that item (the round-1 fix, reverted). Replacing an item that any other application can read is destructive, so it is an explicit `unset`, never a side effect of `set`. "This binary alone" is a path identity, not provenance: an item another program pre-created with a decrypt list naming only che-keychain counts as ours and is replaced (nothing else could read it). Such items are prompt-on-read for other programs, not unreadable; the constraint is who can read.
  - Ownership inspection is fail-closed and covers every authorization that can reveal the secret (decrypt, any, export): any ACL entry, list or trusted application that cannot be read throws the OSStatus; zero such entries are refused; the executable path comes from `Bundle.main` only (no `argv[0]`). Re-creating an item does not preserve its label, comment or dates.
  - `set` and `set-pair` run the same refusal check for every account **before** the dialog, so a refusal is not raised after a secret was typed or after the first account of a pair was stored — unless an item appears while the dialog is open (the check is repeated at write time).
  - More than one item matching `service/account` (e.g. across keychains, or an iCloud-synchronized twin) is refused as ambiguous instead of writing to whichever one the API picks. This configuration previously "worked" by deleting one of them.
  - Root cause of the original -25299, pinned down by probe: `SecItemDelete` — by query or by `kSecMatchItemList` — answers `errSecInvalidOwnerEdit` (-25244) on an item another program created, and the old `save()` discarded that status before `SecItemAdd`. `SecKeychainItemDelete(ref)` deletes such items fine.
- `unset` deletes each matching item by reference (`SecKeychainItemDelete`), so it also removes items created by other programs — previously the query-based loop threw at the first `-25244` and left the remaining items in place. It prints the accounts it removed (or "nothing to remove"), continues past any item it cannot remove and then reports each of those — a refused delete gets a ready-to-run `security delete-generic-password` line, a data-protection / iCloud item (which `SecItemDelete` is tried on first, and which `security` cannot see either) is pointed at Keychain Access — nothing is skipped in silence. Lookups include iCloud-synchronized twins: `set` refuses an ambiguous pair, and `unset` tries to remove a synchronized twin through the generic API (iCloud then propagates the deletion) and reports the status if it cannot; a data-protection item that is not synchronized has no delete path from che-keychain (Keychain Access). `has` deliberately stays local-only: with a twin present, `has || set` then fails loudly at `set` instead of `has` claiming presence and the store being skipped. `--service` sweeps include items other programs created, by design: that is the remedy `set` sends the user to.
- `-25244` error hint corrected: it now says the keychain refused the owner edit and names `security delete-generic-password` as the remedy (the old text wrongly claimed the ACL could not be changed).
- `set` / `set-pair` validation now checks `--service` / `--account` as typed (no leading/trailing whitespace or newlines — they were stored as typed) and also rejects DEL (0x7f); `--label`, `--title` and the pair labels reject control / format (bidi) characters and line breaks; `--explain` may span lines but rejects the same characters. This only removes the cheap tricks next to the "Storing to:" line — look-alike plain text cannot be prevented. `has` and `unset` do not validate, so items stored with such names remain removable.
- Tests: the fixture's service name no longer interpolates an implicitly-unwrapped optional (`che-keychain-test-Optional("…")`); the suite reads its own items in-process (the `security` CLI prompts for the login-keychain password even on allow-all items) and sweeps foreign leftovers with `security` in tearDown.

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
