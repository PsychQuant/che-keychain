## Why

Issue #7 requires an explicit way to replace foreign or allow-all items without weakening the default refusal policy. Existing own-item recovery does not preserve the original access settings, so it cannot be reused unchanged for daemon rotation or the relocation flow in #9.

## What Changes

- Add `set --replace` for deliberate replacement; plain set retains its existing policy.
- Require a readable backup of the previous bytes, original keychain and access object before deleting an existing item.
- Restore the old bytes and access settings after a failed replacement, verify recovery, and report incomplete recovery honestly.
- Preserve stdin's prohibition on widening an existing non-allow-all item to an allow-all ACL.

## Capabilities

### New Capabilities

- `explicit-replacement`: opt-in replacement, backup requirements and verified recovery.

### Modified Capabilities

(none)

## Impact

Commands.swift, main.swift, KeychainStore.swift, tests and CLI documentation. No new dependency. Work is serialized with other keychain follow-ups on the same branch. No automatic credential migration, force-without-backup option, in-place ACL update or atomicity guarantee.
