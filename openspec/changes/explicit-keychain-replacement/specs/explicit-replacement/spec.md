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

#### Scenario: Old value not readable with prompts disabled
- **WHEN** the destination's old value cannot be read with prompts disabled — for example an item created by `security add-generic-password`, with or without `-A`
- **THEN** set --replace SHALL return 1 without deleting or modifying it, the report SHALL state that observed cause and no other, SHALL say that che-keychain holds no copy of the old value, and SHALL present deleting the item only as the user's decision to discard it (`che-keychain unset`, then `set`), never as a way around the refusal

#### Scenario: Backup readable but policy not reproducible
- **WHEN** the old value and access settings are readable but the access policy cannot be rebuilt and reproduced in a nonsecret test item
- **THEN** set --replace SHALL return 1 without deleting or modifying it, and the report SHALL NOT claim the value was unreadable

### Requirement: Recovery with original access
If adding the new value fails, the command SHALL attempt to restore the old bytes and original access settings in the original keychain. It SHALL verify both restored bytes and normalized ACL entries before reporting a verified restore. Restoration SHALL be attempted only into a destination observed to hold no item; if any item is present, the command SHALL leave it untouched and report that the backup was not restored. After the keychain accepts the new value, the command SHALL NOT restore a backup over the destination under any outcome.

#### Scenario: Failed new add
- **WHEN** adding the new value fails after deletion, the destination holds no item, and restoring succeeds
- **THEN** the command SHALL return nonzero and report that the original bytes and access settings were restored

#### Scenario: Destination occupied at restore
- **WHEN** adding the new value fails after deletion but an item is present at the destination
- **THEN** the command SHALL leave that item untouched, SHALL NOT write the backup, and SHALL report that the previous value was not restored

#### Scenario: Recovery mismatch
- **WHEN** restored bytes or access settings differ from the backup
- **THEN** the command SHALL return 4 and report the unverified restore without claiming the old reader can access it

### Requirement: Safe failure handling
Once the keychain has accepted the new value, the command SHALL NOT delete any item at the destination, whatever the read-back reports. A name lookup identifies the item currently carrying that service and account; it does not establish that the item is the one this invocation wrote, and ACL classification establishes only which binary may read an item, not which write created it. Refused cleanup SHALL name the reason and SHALL NOT be described as an attempted delete. Failed recovery SHALL report the known or unknown destination state.

#### Scenario: Unverifiable new value
- **WHEN** the new write is accepted but read-back is unreadable or ambiguous
- **THEN** the command SHALL return 3 without deleting the destination

#### Scenario: Proven bad value that cannot be attributed
- **WHEN** the new write is accepted but read-back proves the destination empty or different
- **THEN** the command SHALL leave the destination untouched, SHALL report that removal was not attempted because the item there cannot be proven to be this write, and SHALL NOT restore the backup

### Requirement: Noninteractive access boundary
A stdin invocation SHALL NOT widen plaintext access to an existing item, even with --replace: it SHALL rotate with --daemon only an item that already has an allow-all entry granting the plaintext (decrypt, any or export-clear), when the backup is readable. An allow-all entry that permits only export-wrapped SHALL NOT count, because exporting the wrapped value does not reveal the plaintext; nor SHALL a plaintext allow-all entry whose prompt selector is nonzero, because what the selector requires of a reader is not verified (fail-closed). The decision SHALL be taken from the access settings captured in the backup and confirmed by the immediately pre-delete observation; an earlier classification SHALL NOT authorize the write on its own. An item whose ACL carries a plaintext allow-all entry SHALL be eligible for rotation even when that ACL also names applications, because such a write widens nothing.

#### Scenario: Widening refused
- **WHEN** set --replace --stdin --daemon targets a non-allow-all item
- **THEN** the command SHALL fail before deletion

#### Scenario: A prompt-selector allow-all entry is not counted as open
- **WHEN** set --replace --stdin --daemon targets an item whose plaintext allow-all entry carries a nonzero prompt selector
- **THEN** the command SHALL fail before deletion and the item SHALL be unchanged

#### Scenario: Export-wrapped allow-all is not plaintext access
- **WHEN** set --replace --stdin --daemon targets an item whose only allow-all entry permits export-wrapped
- **THEN** the command SHALL fail before deletion and the item SHALL be unchanged

### Requirement: Consent names the access being replaced
The dialog SHALL state what the destination exposes now and what the replacement exposes, from the same classification the write uses. An allow-all entry that permits only export-wrapped, or that carries a nonzero prompt selector, SHALL NOT be described as readable by every application; a plaintext allow-all entry SHALL be described as open at the application-ACL layer only, and a --daemon replacement of any item whose plaintext is not already open to every application SHALL be named as widening access. An allow-all entry SHALL NOT be counted as an application.

#### Scenario: Wrapped-only item replaced with --daemon
- **WHEN** the dialog is shown for set --replace --daemon on an item whose only allow-all entry permits export-wrapped
- **THEN** the warning SHALL name the replacement as widening access and SHALL NOT say every application can already read it

### Requirement: Consent is bound to the class at deletion
The access class the dialog described SHALL be compared with the class observed immediately before deletion, not only with the first inspection; a difference SHALL refuse with nothing deleted.

#### Scenario: Class changes after the dialog
- **WHEN** another writer changes the item's access class after the first inspection and before the backup
- **THEN** the replacement SHALL fail with destinationClassChanged and the item SHALL be unchanged

#### Scenario: Access tightened after the first inspection
- **WHEN** an item classified allow-all at inspection carries no allow-all entry in the backup or in the pre-delete observation
- **THEN** set --replace --stdin --daemon SHALL refuse before deletion

#### Scenario: Mixed allow-all and application entries
- **WHEN** the destination's decrypt ACL carries an allow-all entry alongside named applications and a backup is readable
- **THEN** set --replace --stdin --daemon SHALL proceed

### Requirement: Honest guarantees
Documentation SHALL state that replacement is not atomic, requires a readable backup, and does not guarantee recovery from every operating-system failure. No credential value SHALL be printed.

#### Scenario: Successful replacement
- **WHEN** the new value is written and verified
- **THEN** the command SHALL return 0, report the replaced classification and omit both old and new credential values from output
