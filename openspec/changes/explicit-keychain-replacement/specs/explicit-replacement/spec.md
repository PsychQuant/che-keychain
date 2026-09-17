## ADDED Requirements

### Requirement: Explicit replacement policy
The CLI SHALL accept `--replace` only for `set`. Without the flag, foreign and allow-all items SHALL remain refused. Ambiguous and unsupported destinations SHALL remain refused with the flag.

#### Scenario: Default refusal
- **WHEN** an allow-all item exists and plain set is called
- **THEN** the command SHALL fail without changing the item

#### Scenario: Explicit replacement
- **WHEN** an eligible foreign or allow-all item has a readable backup and set --replace is called
- **THEN** the command SHALL replace that exact item with the requested new value and report its previous classification

### Requirement: Backup and identity checks
Before deleting an existing item, explicit replacement MUST obtain its bytes, original keychain and original access settings with interaction disabled. It SHALL first verify with a nonsecret temporary item that reconstructed access reproduces the original policy, including partition IDs, and remove that temporary item. Record-bound integrity SHALL be regenerated and excluded from policy comparison. If a backup is unavailable, rehearsal or cleanup fails, or a reference, value or ACL change is observed before deletion, the command SHALL fail without deleting the item.

#### Scenario: Access policy cannot be reproduced
- **WHEN** the reconstruction cannot preserve the original normalized policy or its nonsecret probe cannot be removed
- **THEN** the command SHALL refuse without deleting the original item

#### Scenario: Unreadable old secret
- **WHEN** the old item requires a prompt to read
- **THEN** set --replace SHALL return 1 without deleting or modifying it

### Requirement: Recovery with original access
If adding the new value fails, or a proven bad new value is successfully removed, the command SHALL attempt to restore the old bytes and original access settings in the original keychain. It SHALL verify both restored bytes and normalized ACL entries before reporting a verified restore.

#### Scenario: Failed new add
- **WHEN** adding the new value fails after deletion and restoring succeeds
- **THEN** the command SHALL return nonzero and report that the original bytes and access settings were restored

#### Scenario: Recovery mismatch
- **WHEN** restored bytes or access settings differ from the backup
- **THEN** the command SHALL return 4 and report the unverified restore without claiming the old reader can access it

### Requirement: Safe failure handling
Unreadable or ambiguous post-write states SHALL remain untouched by cleanup. Refused cleanup SHALL not be described as an attempted delete. Failed recovery SHALL report the known or unknown destination state.

#### Scenario: Unverifiable new value
- **WHEN** the new write is accepted but read-back is unreadable or ambiguous
- **THEN** the command SHALL return 3 without deleting the destination

### Requirement: Noninteractive access boundary
A stdin invocation SHALL NOT widen the ACL of an existing non-allow-all item to allow-all, even with --replace. Existing allow-all items SHALL support explicit daemon rotation when the backup is readable.

#### Scenario: Widening refused
- **WHEN** set --replace --stdin --daemon targets a non-allow-all item
- **THEN** the command SHALL fail before deletion

### Requirement: Honest guarantees
Documentation SHALL state that replacement is not atomic, requires a readable backup, and does not guarantee recovery from every operating-system failure. No credential value SHALL be printed.

#### Scenario: Successful replacement
- **WHEN** the new value is written and verified
- **THEN** the command SHALL return 0, report the replaced classification and omit both old and new credential values from output
