## Context

The writer deliberately recreates items to avoid retaining another program's ACL for new data. Issue #7 adds explicit replacement; issue #9 can reuse it for relocated binaries without weakening path-based identity.

## Goals / Non-Goals

Goals: deliberate replacement, mandatory pre-delete backup, recovery of old bytes and access settings, and accurate failure reporting.

Non-goals: atomic transactions, universal daemon read access, automatic migration, replacement without a readable backup, preservation of item label/comment/dates, changes to set-pair input sources, attributing an item found at the destination to a particular write by this or any other process, or replacing an item whose value cannot be read with prompts disabled — which includes every item created by `security add-generic-password` (partition `apple-tool:`), with or without `-A`. Issue #7's acceptance was narrowed to this on 2026-09-22 (decision comment on #7): the alternative, prompting for the login-keychain password during the backup, would break the prompts-disabled invariant and is deferred to a separate issue if ever wanted.

## Decisions

### Explicit replacement policy

Use a set-only Boolean flag, default false. Preflight and save share the policy. Unsupported or ambiguous items remain refused. Without the flag, existing behavior is unchanged. A missing item follows normal add behavior.

### Backup and identity checks

Read old bytes with interaction disabled, copy the original SecAccess and containing keychain, and serialize the ACL entries in memory for comparison (excluding record-bound integrity, retaining partition policy). Do not print bytes or access descriptors. Failure to obtain any part aborts before deletion. Reinspect the reference, bytes and ACL before deleting to reject an observed change; a race after that check remains a documented limitation.

### Recovery with original access

Live probes found that reusing a stored SecAccess returns -25293, and removing its derived entries alone still returns -67702 (invalid ACL). Rebuild its simple application/owner ACL entries in a new SecAccess. Apple Security's Item.cpp also regenerates integrity and partition metadata when copying records; it is not safe to treat a stored ACL object as a reusable creation template.

Before deleting the original, create a uniquely named nonsecret recovery probe in the same keychain with rebuilt access. Require the resulting policy records, including partition IDs, to equal the backup, then delete the probe. Refuse replacement if policy differs or probe cleanup fails; report a leftover probe identifier if necessary. The original stays untouched in those cases. Recovery rebuilds another fresh access object and compares the restored policy again. This supports representable, reproducible ACLs, not arbitrary complex/custom access policies.

Recreate the new value with a fresh requested ACL. On add failure, try restoring old bytes with the original SecAccess in the original keychain, and only when the destination is observed to hold no item; an occupied destination is left alone and reported as not restored. Verify restored bytes and normalized ACL entries; do not claim recovery from a successful add status alone.

Once the keychain has accepted the new value, nothing at the destination is deleted, whatever the read-back says. The reason is attribution, not caution: `SecItemAdd` is called without capturing a reference to the record it creates, so the only later handle on "the item we wrote" is a fresh name lookup — and a name lookup returns whichever record currently carries that service and account. The guarded cleanup this change previously reused (`deleteWritten`) compares two such lookups and requires the result to be `own`, but `own` states which binary may read the item, not which write created it: a second process running the same binary produces an indistinguishable item. A competitor that deletes and recreates the destination between our add and our read-back therefore satisfies both guards, and the old path would delete that item and then write our older backup over the slot. A proven-bad value that is left in place is a visible, recoverable defect; deleting another writer's credential and reinstating stale bytes is neither. Restoring an identifying reference from `SecItemAdd` would not settle it either: probes found that a delete-and-recreate can yield an equal general query reference and equal persistent-reference bytes, while reading the reference the add itself returned gave -67701. Until an identity primitive is established, this change does not delete after a successful add.

### Outcome reporting

General errors and unavailable recovery return 1; accepted but unverifiable new writes return 3; exit 4 means a restore was accepted whose bytes or access settings do not match the backup — the destination holds an item this command cannot prove is its restore — and the remedy on every path is to inspect in Keychain Access, never a blind `unset`, because the re-add and the read-back are both by name. One sentence covers both the help text and the two documentation files, so the code, `Version.swift`, `README.md` and `CLAUDE.md` do not drift into separate definitions again. Exit 0 requires a verified new value. Report whether original bytes/access were restored, remain unverified or failed. No failure path issues an instruction to blindly remove an unidentified item.

## Implementation Contract

`SetArgs.replace: Bool = false`, `set --replace`, `KeychainStore.preflight(..., allowReplacement: Bool = false)` and `save(..., allowReplacement: Bool = false)` carry the policy. `save` returns the observed original classification so CLI success output identifies own/foreign/allow-all replacement. `set-pair` does not gain the flag.

A noninteractive stdin replacement MUST NOT widen an existing non-allow-all item's ACL; rotating an existing allow-all item with --daemon is allowed. The widening decision is taken from the access settings captured in the backup and reconfirmed by the pre-delete observation, because the first inspection happens before the backup and another writer can tighten the ACL in between; the early classification stays only as a cheap refusal. Eligibility asks whether an allow-all decrypt entry exists, not whether the item classifies as `allowAll`: an ACL that carries an allow-all entry alongside named applications is already readable by everything, so rotating it widens nothing. All tests use uniquely named synthetic services, never production credentials. Tests cover default refusal, no-backup refusal with original data unchanged, explicit replacement and recovery of bytes plus ACL. Deterministic Security API failure injection is restricted to the existing DEBUG seam pattern.

## Risks / Trade-offs

- Delete plus add is not atomic → mandatory backup, an immediate identity check and explicit recovery outcomes; no promise of zero downtime under arbitrary OS failures.
- SecItemAdd can normalize access metadata → compare recovered ACL contents and report mismatch instead of claiming success.
- A foreign secret cannot be read noninteractively → refuse before deleting; the user must establish access through the appropriate trusted application outside this command.
- An item found at the destination cannot be attributed to this write → after a successful add nothing is deleted and no backup is written over it; a proven-bad value can survive at the destination and the report says so rather than removing it.

## Migration Plan

Keep plain set unchanged. Document --replace as an opt-in alternative to unset followed by set, including the readable-backup prerequisite. The PR remains unmerged until user review.

## Evidence

The local nonsecret probes separately exercised copied Access reuse, derived-entry removal, and fresh simple-entry reconstruction. Only the fresh reconstruction succeeded. The recovery and foreign/allow-all tests then passed with original-policy equality and pre-delete rehearsal. Primary implementation reference: https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/Item.cpp (copyTo/updateSSGroup).

## Open Questions

None for implementation. The documented OS race and unsupported arbitrary-failure guarantees remain limitations, not hidden acceptance claims.

Round-2 amendment (issue #7, verify FAIL on PR #17): the two HIGH findings are resolved by narrowing what the command promises, not by adding coordination. H1 — the noninteractive widening check now reads the backup and pre-delete observations. H2 — no deletion follows a successful add. A cross-process safe replacement would need an item-identity primitive this platform has not been shown to offer; if one appears, reopening the automatic-rollback question is a separate change, not a quiet reinstatement of this one.
