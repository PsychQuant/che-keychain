## Why

Issue #7 requires an explicit way to replace foreign or allow-all items without weakening the default refusal policy. Existing own-item recovery does not preserve the original access settings, so it cannot be reused unchanged for daemon rotation or the relocation flow in #9.

## What Changes

- Add `set --replace` for deliberate replacement; plain set retains its existing policy.
- Require a readable backup of the previous bytes, original keychain and access object before deleting an existing item.
- Restore the old bytes and access settings after a failed add, only into a destination observed to be empty, verify recovery, and report incomplete recovery honestly.
- Delete nothing at the destination once the keychain has accepted the new value, because an item found by a name lookup cannot be attributed to this write.
- Preserve stdin's prohibition on widening an existing non-allow-all item to an allow-all ACL.

## Capabilities

### New Capabilities

- `explicit-replacement`: opt-in replacement, backup requirements and verified recovery.

### Modified Capabilities

(none)

## Impact

Commands.swift, main.swift, KeychainStore.swift, PromptDialog.swift, Version.swift, README.md, CLAUDE.md, CHANGELOG.md, tests and CLI documentation. No new dependency. Work is serialized with other keychain follow-ups on the same branch, and the outcome-reporting edits are shared with issue #15. No automatic credential migration, force-without-backup option, in-place ACL update, atomicity guarantee, or removal of an item this command cannot prove it wrote.
