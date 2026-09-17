## Context

The writer deliberately recreates items to avoid retaining another program's ACL for new data. Issue #7 adds explicit replacement; issue #9 can reuse it for relocated binaries without weakening path-based identity.

## Goals / Non-Goals

Goals: deliberate replacement, mandatory pre-delete backup, recovery of old bytes and access settings, and accurate failure reporting.

Non-goals: atomic transactions, universal daemon read access, automatic migration, replacement without a readable backup, preservation of item label/comment/dates, or changes to set-pair input sources.

## Decisions

### Explicit replacement policy

Use a set-only Boolean flag, default false. Preflight and save share the policy. Unsupported or ambiguous items remain refused. Without the flag, existing behavior is unchanged. A missing item follows normal add behavior.

### Backup and identity checks

Read old bytes with interaction disabled, copy the original SecAccess and containing keychain, and serialize the ACL entries in memory for comparison (excluding record-bound integrity, retaining partition policy). Do not print bytes or access descriptors. Failure to obtain any part aborts before deletion. Reinspect the reference, bytes and ACL before deleting to reject an observed change; a race after that check remains a documented limitation.

### Recovery with original access

Live probes found that reusing a stored SecAccess returns -25293, and removing its derived entries alone still returns -67702 (invalid ACL). Rebuild its simple application/owner ACL entries in a new SecAccess. Apple Security's Item.cpp also regenerates integrity and partition metadata when copying records; it is not safe to treat a stored ACL object as a reusable creation template.

Before deleting the original, create a uniquely named nonsecret recovery probe in the same keychain with rebuilt access. Require the resulting policy records, including partition IDs, to equal the backup, then delete the probe. Refuse replacement if policy differs or probe cleanup fails; report a leftover probe identifier if necessary. The original stays untouched in those cases. Recovery rebuilds another fresh access object and compares the restored policy again. This supports representable, reproducible ACLs, not arbitrary complex/custom access policies.

Recreate the new value with a fresh requested ACL. On add failure, try restoring old bytes with the original SecAccess in the original keychain. On proven read-back mismatch, first use the existing guarded cleanup; restore only after cleanup removes the new item. Do not delete an unreadable or ambiguous destination. Verify restored bytes and normalized ACL entries; do not claim recovery from a successful add status alone.

### Outcome reporting

General errors and unavailable recovery return 1; accepted but unverifiable new writes return 3; a proven mismatched restore or failed deletion of a proven bad item returns 4. Exit 0 requires a verified new value. Report whether original bytes/access were restored, remain unverified or failed. No failure path issues an instruction to blindly remove an unidentified item.

## Implementation Contract

`SetArgs.replace: Bool = false`, `set --replace`, `KeychainStore.preflight(..., allowReplacement: Bool = false)` and `save(..., allowReplacement: Bool = false)` carry the policy. `save` returns the observed original classification so CLI success output identifies own/foreign/allow-all replacement. `set-pair` does not gain the flag.

A noninteractive stdin replacement MUST NOT widen an existing non-allow-all item's ACL; rotating an existing allow-all item with --daemon is allowed. All tests use uniquely named synthetic services, never production credentials. Tests cover default refusal, no-backup refusal with original data unchanged, explicit replacement and recovery of bytes plus ACL. Deterministic Security API failure injection is restricted to the existing DEBUG seam pattern.

## Risks / Trade-offs

- Delete plus add is not atomic → mandatory backup, an immediate identity check and explicit recovery outcomes; no promise of zero downtime under arbitrary OS failures.
- SecItemAdd can normalize access metadata → compare recovered ACL contents and report mismatch instead of claiming success.
- A foreign secret cannot be read noninteractively → refuse before deleting; the user must establish access through the appropriate trusted application outside this command.

## Migration Plan

Keep plain set unchanged. Document --replace as an opt-in alternative to unset followed by set, including the readable-backup prerequisite. The PR remains unmerged until user review.

## Evidence

The local nonsecret probes separately exercised copied Access reuse, derived-entry removal, and fresh simple-entry reconstruction. Only the fresh reconstruction succeeded. The recovery and foreign/allow-all tests then passed with original-policy equality and pre-delete rehearsal. Primary implementation reference: https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/Item.cpp (copyTo/updateSSGroup).

## Open Questions

None for implementation. The documented OS race and unsupported arbitrary-failure guarantees remain limitations, not hidden acceptance claims.
