## 1. Policy and preparation

- [x] 1.1 Deliver Explicit replacement policy through set --replace while preserving default refusal; verify parser and default-policy tests.
- [x] 1.2 Deliver Backup and identity checks before deletion; verify unreadable-backup and nonsecret-rehearsal refusal leave the original item unchanged.

## 2. Replacement and recovery

- [x] 2.1 Deliver Recovery with original access after add or read-back failure; verify original bytes and allow-all ACL survive injected failures.
- [x] 2.2 Deliver Safe failure handling and Outcome reporting; verify unavailable read-back is left alone and failed recovery is not reported as restored.
- [x] 2.3 Preserve the Noninteractive access boundary; verify stdin refuses widening a non-allow-all item and allows backed-up allow-all rotation.

## 3. Documentation and verification

- [x] 3.1 Publish Honest guarantees and the migration prerequisites in help/README; review actual CLI help and output for no secret disclosure.
- [x] 3.2 Run the complete tests and spectra validate; confirm all requirements and design decisions above have passing evidence.

## 4. Round 2 — narrow the promises (verify FAIL on PR #17)

Sections 1-3 shipped in `7082713` and their evidence stands. Independent verification then found two HIGH defects in the paths below; the decision recorded on issue #7 narrows what the command promises rather than adding cross-process coordination. Tasks 4.6 and 4.7 belong to issue #15 and edit the same declarations, so they are done in this batch.

- [x] 4.1 Take the noninteractive widening decision from the backup and the pre-delete observation instead of the first inspection (H1); verify a deterministic interleaving that tightens the ACL after inspection is refused before deletion.
- [x] 4.2 Decide eligibility on the presence of an allow-all decrypt entry rather than the `allowAll` classification, and align the `Existing.allowAll` documentation with `classify`'s ordering (M1); verify a mixed allow-all-plus-applications item rotates instead of being refused.
- [x] 4.3 Stop deleting at the destination once the add succeeded, in all three call sites that share the cleanup helper — explicit replacement, the fresh-add path and own-item rotation (H2); verify a deterministic interleaving where a competitor recreates the destination leaves that item in place and writes no backup over it.
- [x] 4.4 Restrict backup restoration to a destination observed to hold no item, and report an occupied destination as not restored; verify the backup is not written over a present item.
- [x] 4.5 Report the new refusal and the unremoved proven-bad value in terms of what was established, including the dialog's account of which access class is being replaced and what the replacement changes (L1); verify the wording against each read-back outcome.
- [x] 4.6 State one meaning for exit 4 in the code, the help text, `README.md` and `CLAUDE.md`, and give the remedy that fits the case at hand (M2, shared with issue #15).
- [x] 4.7 Carry the read-back reason through the unverified-restore outcomes so an ambiguous destination is not told to unlock the keychain, and stop the pair's exit 3 from reporting both halves as in place (M3 and M4, issue #15); verify each message against the outcome it describes.
- [x] 4.8 Run the complete suite plus the new interleaving tests, then `/idd-verify --pr 17`; a pass requires no HIGH finding and no message that claims more than the code establishes. — Round-2 verify ran 2026-09-20: FAIL (2 HIGH, 4 MEDIUM); findings became section 5.

## 5. Round 3 — round-2 verify findings

- [x] 5.1 (F1) Establish, by test, what happens to a `security`-created item under `--replace`: refused at the noninteractive backup read (partition `apple-tool:`), nothing deleted. Acceptance narrowed by decision on #7 (2026-09-22); the refusal names the cause and the way through.
- [x] 5.2 (F2/F16) Exit 1 described removal and restore that no longer happen; help, README and CLAUDE.md now enumerate the states the code can leave, including a proven-bad value left in place.
- [x] 5.3 (F3) The own-rotation exit-4 message no longer hands out `unset`; every exit-4 surface says inspect.
- [x] 5.4 (F4) "The only outcome that leaves an unproven item behind" struck from README, help and CHANGELOG; design.md's exit-4 definition aligned (F17).
- [x] 5.5 (F5) `--replace` consent is bound to the access class the dialog described: a class change by write time refuses (`destinationClassChanged`).
- [x] 5.6 (F6/F9/F10/F13/F18) Messages say only what was observed: explicit-path `.missing` states the previous item is gone and not put back; a failed inspect during restore is `destinationUnknown`, not "an item was there"; `ReadBack.item` and stale comments removed; foreign+daemon dialog wording no longer contradicts itself.
- [ ] 5.7 Full suite green, then `/idd-verify --pr 17` round 3 (Codex quota permitting).
