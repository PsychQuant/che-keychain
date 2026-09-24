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
- [x] 5.7 Full suite green, then `/idd-verify --pr 17` round 3 — ran 2026-09-23 (Codex disabled by owner): FAIL; findings became section 6.

## 6. Round 4 — round-3 verify findings

- [x] 6.1 (G1/G2) `replacementBackupUnavailable` carries the observed cause (value unreadable / access unreadable / policy not reproducible); each message states that cause only and none suggests deleting the item. Tests assert the cause for the `security`-created case and the policy case, and assert no deletion advice. _(Superseded in part by the 2026-09-24 decision on #7: deletion is offered as the user's decision; see 7.1 and 8.2.)_
- [x] 6.2 (G3) Tests for `destinationClassChanged`, `destinationUnknown` on both restore paths (through a DEBUG inspect seam), and the explicit path's `.notAttempted` report.
- [x] 6.3 (G8/G9/G10) Exit 1 says nothing is removed AFTER an accepted write and names the deleted-previous-item state; `removalNotAttempted` says the item was left in place; stale comments corrected.
- [x] 6.4 (G4/G5/G6) The narrowed acceptance is stated by its real criterion; README, spec and design drop the deletion path and the unobserved password-prompt claim; CLAUDE.md warns agents about `--replace --stdin` and about deleting to bypass a refusal; errata posted on the #7 decision. _(Superseded in part by the 2026-09-24 decision on #7: deletion is offered as the user's decision; see 7.1 and 8.2.)_
- [x] 6.5 Full suite green, then `/idd-verify --pr 17` round 4 — ran 2026-09-23 (Codex off): FAIL, 0 HIGH; findings became section 7.

## 7. Round 5 — docs-only, round-4 verify findings

- [x] 7.1 (H1/H3) CLAUDE.md rule 7 now says an agent never deletes on its own initiative; the user decides whether the old value is expendable. Rule 5, the #9 paragraph, the refusal message, README and help agree. The refusal offers `che-keychain unset` framed as that decision, backed by `testUnsetRemovesItemsCreatedByOtherProgramsToo` and an observed run on both `security` shapes; "cannot take" (permanent) became "did not take".
- [x] 7.2 (H2) CLAUDE.md states the `--replace --stdin --daemon` silent substitution and limits the Security-boundary claim to the typed value.
- [x] 7.3 (H6) #9 docs (README, help, CLAUDE.md) no longer promise `--replace` from a new copy; they call the refusal a prediction, name the original copy as the path, and give the discard decision as the alternative.
- [x] 7.4 (H4/H7/H8) `policyNotReproducible` wording covers a failed probe add; message-level test for all three causes (`accessUnreadable` has no reachable fixture); `removalNotAttempted` says "after the write"; help short summary and `empty` wording; doc comment.
- [x] 7.5 (H5) G7 recorded as an accepted residual in design.md and filed as #22.
- [x] 7.6 Full suite green, then `/idd-verify --pr 17` round 5 — ran 2026-09-23 (Codex off): FAIL (1 HIGH: the #9 prediction was wrong, confirmed by an observed run); findings became section 8.

## 8. Round 6 — round-5 verify findings

- [x] 8.1 (I1/I2) #9 docs (README, help, CLAUDE.md, design.md) state the observed result: the same build at another path migrates with `--replace`; a differently signed copy is refused at the backup read. #9's option 3 holds; no narrowing of #9.
- [x] 8.2 (I3/I4) Rule 7: the routine rotation for own `--daemon` items is `set --replace --daemon`; `unset` then `set` only after a backup refusal and the user's decision. The refusal message gives the keep option first and tells the caller not to run the `unset` line without the user's explicit confirmation; tests pin the order and the wording.
- [x] 8.3 (I5) Decision on #7 (https://github.com/PsychQuant/che-keychain/issues/7#issuecomment-5798429935) records that deletion is the user's decision, superseding the errata's "no deletion advice".
- [x] 8.4 (LOW) `policyNotReproducible` wording covers the rebuild failure; help summary names both remedies; the `unset` test covers the `-A` shape; stale test names and 6.1/6.4 notes updated.
- [x] 8.5 Full suite green, then `/idd-verify --pr 17` round 6 — ran 2026-09-24 with Codex enabled (6-AI): FAIL (2 HIGH); findings became section 9.

## 9. Round 7 — round-6 verify findings

- [x] 9.1 (J1, HIGH, cross-model) The widening guard uses a plaintext-only authorization set (decrypt, any, export-clear); an allow-all export-wrapped entry no longer counts as "readable by everything". RED test reproduced the widening before the fix; ownership classification stays conservative.
- [x] 9.2 (J2/J3) Help and the plain-`set` refusals (`unattributable`, `foreignOwned`) give the backed-up `set --replace [--daemon]` path first and `unset` only as the user's decision; a test pins the order and wording.
- [x] 9.3 (J4) CLAUDE.md rule 7 no longer promises the reader is never without a credential; it states the non-atomic window.
- [x] 9.4 (J5) A new `--daemon` item's dialog warning states the all-applications scope.
- [x] 9.5 (J6) #9 docs state the two observed cases only and say a different Developer ID-signed release is untested.
- [x] 9.6 (LOW) Test force-unwrap removed; CHANGELOG records the rotation change, the #9 observation and the J1 fix. A repo-wide grep for rotation, `unset` and #9 wording was run before and after the edits.
- [x] 9.7 Full suite green (119/0), then `/idd-verify --pr 17` round 7 — ran 2026-09-24 with Codex on (6-AI): FAIL (0 HIGH, 4 MEDIUM groups); findings became section 10.

## 10. Round 8 — round-7 verify findings

- [x] 10.1 (K1) The access class carries what an allow-all entry exposes (`allowAll(.plaintext | .wrappedOnly)`, same on `foreign`); `Found.allowAllPlaintextEntry` removed so no consumer can miss it. The dialog no longer calls a wrapped-only item readable by any application, names a plaintext widening "WIDENS access", and no longer counts an allow-all entry as an application; the unattributable/foreign refusals and the success evidence line state the scope. Tests: classification of the J1 fixture, `warningText` for both scopes and for foreign, the mixed-ACL owners list.
- [x] 10.2 (K2/K3) Every refusal that offers `set --replace` or `unset` frames both as the user's decision before either command, says the backup lives only until the new value is verified, and states the refusal of unreadable old values; `aclWideningRefused` no longer says "prompt-on-read item". The ordering test now covers all four refusals.
- [x] 10.3 (K4) CLAUDE.md rule 7 says a restore happens only after a failed add into an empty slot and that a wrongly read-back new value is left in place.
- [x] 10.4 (K5 / #22) The dialog's class is compared again with the observation immediately before the delete. RED reproduced (an own item made foreign after the dialog was replaced), then fixed.
- [x] 10.5 (LOW) Help, CLAUDE.md rule 5/6, README (security table rows), the `save()` policy comment, the OSStatus / unsupported / ambiguous fallbacks, a test comment, and the openspec/CHANGELOG eligibility criterion aligned; direct tests for `hasAllowAllPlaintextEntry` on captured records and for the help text's rotation order. Closing check: every deletion suggestion in `Sources/` listed and compared with rules 6 and 7, not a keyword grep.
- [x] 10.6 Full suite green (123/0), then `/idd-verify --pr 17` round 8 — ran 2026-09-24 with Codex on (6-AI): FAIL (0 HIGH, 2 MEDIUM groups); findings became section 11.

## 11. Round 9 — round-8 verify findings

- [x] 11.1 (L1) The generic `set (…)` OSStatus fallback no longer offers `set --replace` (most of the operations that reach it are inspection failures that `--replace` repeats; `set (add)` has nothing to replace). Test pins it.
- [x] 11.2 (L2) `foreign.owners` excludes this binary; the dialog built from a REAL classification of a co-trusted item says "1 other application". RED reproduced "2 other applications" first.
- [x] 11.3 (LOW) Allow-all label listed first (cap cannot hide it; success line marks truncation); foreignOwned says "access list", not "decrypt ACL"; `replaceBackupTerms` names `--replace` as its subject, says `security` items are "one tested case", and says `set-pair` has no --replace; wrapped-only unattributable no longer says it looks like a `--daemon` item and says --stdin is refused; `destinationClassChanged` says "the item was not changed"; `save` returns the class observed before the delete; positive #22 tests for unchanged `.allowAll(.plaintext)` and `.foreign`; CLAUDE.md rule 7 lists the five post-delete outcomes (closed list; round-9 verify found outcome (2)'s restore-failure branch overstated — corrected in §12); design.md first sentence uses the plaintext criterion.
- [x] 11.4 Full suite green (125/0), then `/idd-verify --pr 17` round 9 — ran 2026-09-24 with Codex on (6-AI): FAIL (0 HIGH, 2 MEDIUM groups); findings became section 12.

## 12. Round 10 — round-9 verify findings

- [x] 12.1 (M1) CLAUDE.md rule 7 outcome (2) names every restore result the code reports — checked by enumerating `ExplicitRestoreOutcome` case by case (restored / unverified / mismatch→4 / destinationOccupied / preparationFailed, failed, destinationUnknown → unknown); outcome (3) says "empty as far as the command can see". The exit-code lists in help, README and CLAUDE.md gained the occupied state.
- [x] 12.2 (M2) The dialog says a foreign item's access list "also trusts N other applications" instead of "N other applications can read" (owners include wrapped-export-only entries); RED test with a named wrapped-export-only application first.
- [x] 12.3 (LOW) The foreign refusal says "applications other than this binary", no longer "not only this binary"; `foreignOwned` doc comment updated; tests pin the allow-all-first order through `save`, the success line (extracted to `replacementEvidence`) and exit 3 on the explicit path; README `--replace` paragraph uses the plaintext criterion, frames `unset` as the user's decision, and says the backup goes back only if adding fails; tasks 11.1/11.3 wording corrected.
- [x] 12.4 Full suite green (129/0), then `/idd-verify --pr 17` round 10 — ran 2026-09-24 with Codex on (6-AI): FAIL (0 HIGH, 2 MEDIUM groups); 12.1 had claimed the help's lists were updated when only the summary was — corrected in section 13.

## 13. Round 11 — round-10 verify findings

- [x] 13.1 (Codex) The `--from-clipboard` own-item confirmation no longer promises a restore "if the store fails"; extracted to `ownItemOverwriteNotice` and tested.
- [x] 13.2 (help list) All five exit-1 state lists (help detailed + summary, README comment + line, CLAUDE.md) name the same six states, with "another item found there" instead of "another writer put there" (the code observes an item, not its writer). `testEveryExitOneStateListNamesTheSameStates` pins them; mutation-checked (removing the phrase from the help's detailed list fails it).
- [x] 13.3 (LOW) foreignOwned carries the allow-all scope separately and says "access list" throughout; dialog "trusts N applications other than this binary"; explicit-path `destinationOccupied` tested end to end; rule 7 says its closed list is for `set --replace` and how plain `set` over an own item differs; help "re-stored only if" and README "slot is then empty" qualifications.
- [x] 13.4 Full suite green (132/0), then `/idd-verify --pr 17` round 11 — ran 2026-09-24 with Codex on (6-AI): FAIL (0 HIGH, 4 MEDIUM, all the same class: recovery promises in texts other than the one fixed); findings became section 14.

## 14. Round 12 — round-11 verify findings

- [x] 14.1 (restore promise, 4 MEDIUM) One restore rule (`AppVersion.restoreRule` + `copyRule`) quoted verbatim in the help (plain-set and --replace paragraphs), README (--replace paragraph; the security table points to it), CLAUDE.md (rule 7's plain-set sentence) and the clipboard confirmation; the rule-7 plain-set sentence no longer enumerates a partial state list and points to the exit-code list (exit 4 included). `testEveryRecoveryClaimQuotesTheOneRestoreRule` pins the rule in all four texts and bans the superseded phrasings; mutation-checked.
- [x] 14.2 (LOW) exit-1 lists say "a restore of the previous value (verified or not)"; help "Without --replace, che-keychain never overwrites…" and the plaintext widening criterion; foreign refusal judges "entries that can reveal the value"; success line states the allow-all entry apart; --daemon foreign dialog does not say access ends; `foreignOwned.allowAll` has no default; CHANGELOG bullets folded so none contradicts another.
- [x] 14.3 One full-suite run took 435 s instead of ~14 s; two immediate reruns of KeychainStoreTests took 12.8 s with no test over 5 s — recorded as a one-off environment stall, not a test change.
- [x] 14.4 Full suite green (134/0), then `/idd-verify --pr 17` round 12 — ran 2026-09-24 with Codex on (6-AI): FAIL (0 HIGH, 4 MEDIUM, one defect: a README sentence round 12 added claimed the --replace restore checks for plain `set` too); findings became section 15.

## 15. Round 13 — round-12 verify findings

- [x] 15.1 (MEDIUM) New `AppVersion.verifyRule` states how a written-back value is checked on each path (`--replace`: original access settings restored, bytes + access settings + keychain compared; plain `set` / `set-pair`: re-created for this binary only, bytes compared); quoted in help, README and CLAUDE.md, replacing the README sentence that applied the --replace checks to both. Checked against `restoreExplicit` / `restorePrevious` line by line.
- [x] 15.2 (LOW) `restoreRule` adds "even then the write-back can fail" and "or that its state is unknown"; `copyRule` names `set-pair` and the non-empty condition of the plain path. "Backed up until verified" (help, README, CLAUDE.md rule 5, refusal terms, doc comments) became "held only while it runs". CHANGELOG: plaintext criterion in the Added bullet, #14 recorded as done, no bullet quotes a superseded phrasing. `replacementEvidence` doc comment matches the code. #22 issue body gained a Current Status saying it is fixed in PR #17.
- [x] 15.3 The pinning test now requires `verifyRule` in help/README/CLAUDE.md and scans CHANGELOG [Unreleased] for the banned phrasings; it caught two quoted phrasings in the new CHANGELOG bullet on its first run.
- [x] 15.4 Full suite green (134/0), then `/idd-verify --pr 17` round 13 — ran 2026-09-24 with Codex on: no MEDIUM or HIGH from the five reviewers that completed (Codex: no blocking defect); the Devil's Advocate did not complete (session limit), so the run is incomplete and is repeated in round 14. LOW findings became section 16.

## 16. Round 14 — round-13 verify LOW findings

- [x] 16.1 Exit 4 is defined the same way in the help, README, CLAUDE.md, the `--replace` restore reports and the `RestoreOutcome` doc: a restore accepted that differs from the backup in what was compared (bytes; under `--replace` also access settings and keychain). `verifyRule` ends "Exit 4 means the comparison found a difference; a comparison that could not be made exits 1."
- [x] 16.2 A lost plain-path restore with no copy (unreadable or empty old value) reports the destination's state as unknown instead of inferring "absent"; tested with a real empty own item.
- [x] 16.3 The plain restore is asserted to re-create an item only this binary can read (`.own`).
- [x] 16.4 The `--replace` pre-delete re-read of the old value is zeroed like the backup; the README "Copies" row lists the copies of the OLD value and which are zeroed.
- [x] 16.5 The CHANGELOG slice in the pinning test no longer force-unwraps and ends at the next heading after [Unreleased]; the CHANGELOG states which rules are pinned where; README's "slot is then empty" carries the write-back-can-fail qualifier; CLAUDE.md rule 7's plain-path referent is explicit; #7's Current Status resynced.
- [x] 16.6 Full suite green (135/0), then `/idd-verify --pr 17` round 14 — ran 2026-09-24, Codex on, all six reviewers completed: FAIL (0 HIGH, 1 MEDIUM from Codex — the preflight backup copy of the old value was dropped without a wipe, which the round-14 README "Copies" row did not account for); findings became section 17.

## 17. Round 15 — round-14 verify findings

- [x] 17.1 (MEDIUM) The preflight backup check wipes the copy it reads; `replacementBackup` wipes the value it read when it then throws on unreadable access settings. The README "Copies" row says a wipe is attempted, best-effort, on the backup, the preflight copy, the pre-delete re-read and a plain rotation's copy (bridged buffers from the Security framework may be released unwiped), and that read-backs are not wiped; "are zeroed" is banned by the pinning test.
- [x] 17.2 (LOW) `RestoreLoss` doc comment matches the reports; message tests for `previousUnreadable` (unknown) and `readdVanished` (empty as far as the command can see); CHANGELOG records the lost-restore report change and the wipes; #9, #11–#15 Current Status resynced. #15 item 5 (stdin buffer wipe) is discharged by the best-effort statement, not a test: a memory wipe of a bridged buffer is not observable from a test, which is why the docs say best-effort — recorded on #15.
- [ ] 17.3 Full suite green, then `/idd-verify --pr 17` round 15 (Codex on, all reviewers completing).
