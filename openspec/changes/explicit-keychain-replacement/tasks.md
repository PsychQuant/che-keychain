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

- [ ] 4.1 Take the noninteractive widening decision from the backup and the pre-delete observation instead of the first inspection (H1); verify a deterministic interleaving that tightens the ACL after inspection is refused before deletion.
- [ ] 4.2 Decide eligibility on the presence of an allow-all decrypt entry rather than the `allowAll` classification, and align the `Existing.allowAll` documentation with `classify`'s ordering (M1); verify a mixed allow-all-plus-applications item rotates instead of being refused.
- [ ] 4.3 Stop deleting at the destination once the add succeeded, in all three call sites that share the cleanup helper — explicit replacement, the fresh-add path and own-item rotation (H2); verify a deterministic interleaving where a competitor recreates the destination leaves that item in place and writes no backup over it.
- [ ] 4.4 Restrict backup restoration to a destination observed to hold no item, and report an occupied destination as not restored; verify the backup is not written over a present item.
- [ ] 4.5 Report the new refusal and the unremoved proven-bad value in terms of what was established, including the dialog's account of which access class is being replaced and what the replacement changes (L1); verify the wording against each read-back outcome.
- [ ] 4.6 State one meaning for exit 4 in the code, the help text, `README.md` and `CLAUDE.md`, and give the remedy that fits the case at hand (M2, shared with issue #15).
- [ ] 4.7 Carry the read-back reason through the unverified-restore outcomes so an ambiguous destination is not told to unlock the keychain, and stop the pair's exit 3 from reporting both halves as in place (M3 and M4, issue #15); verify each message against the outcome it describes.
- [ ] 4.8 Run the complete suite plus the new interleaving tests, then `/idd-verify --pr 17`; a pass requires no HIGH finding and no message that claims more than the code establishes.
