// Sources/CheKeychain/KeychainStore.swift
import Foundation
import Security

enum MismatchReason: String {
    /// The item is not there at all after a successful write status.
    case missing
    /// The item is there but its value could not be read (locked keychain, or a prompt would be needed).
    case unreadable
    case empty, differs
    /// More than one item matched, so the written one could not be identified.
    case ambiguous
}

/// Why a rotation's previous value could not be put back. Most cases leave the
/// slot empty; `readdFailed` and `destinationUnknown` leave it unknown and
/// `destinationOccupied` leaves whatever another writer put there.
enum RestoreLoss: Equatable {
    /// The previous value could not be read before the replace (locked keychain / prompt needed).
    case previousUnreadable
    /// The previous value was read and was itself empty (the #5 bad-item state) — nothing worth restoring.
    case previousEmpty
    /// Re-adding the previous value failed with this status.
    case readdFailed(OSStatus)
    /// The keychain accepted the re-add, yet no item exists afterwards.
    case readdVanished
    /// An item was already at the destination, so the backup was not written:
    /// restoring must never overwrite whatever is there now.
    case destinationOccupied
    /// The destination could not be inspected (lookup error or ambiguous match),
    /// so nothing was written: refusing on an unknown state is not the same as
    /// having seen an item there.
    case destinationUnknown
}

/// What happened to a rotation's previous value after it was put back.
/// Produced by `restorePrevious`; consumed by both the mismatch report and the
/// failed-replace report, so the two tell one story.
enum RestoreOutcome: Equatable {
    /// Re-added and read back intact.
    case restored
    /// Re-added (the keychain accepted it) but the read-back could not prove it.
    /// The reason is carried so the report can give the remedy that fits:
    /// `.unreadable` is answered by unlocking, `.ambiguous` never is.
    case restoredUnverified(MismatchReason)
    /// Re-added, but reads back empty / different / missing — an unverified item sits in the slot.
    case mismatch(MismatchReason)
    /// Could not be put back at all; `RestoreLoss` says why and what that leaves.
    case lost(RestoreLoss)

    /// The new value never landed (1), unless a restore was accepted whose bytes
    /// or access settings do not match the backup (4) — the one thing this
    /// command can still leave at a destination without being able to prove it.
    var exitCode: Int32 { if case .mismatch = self { return 4 }; return 1 }
}

/// Why no delete was attempted at a destination.
enum CleanupRefusal: String {
    /// A name lookup found an item at the destination, but nothing proves it is
    /// the one this invocation wrote: `SecItemAdd` is called without capturing a
    /// reference to the record it creates, and ownership says which binary may
    /// read an item, not which write created it.
    case writeNotAttributable = "the item at the destination cannot be proven to be this write"
}

enum MismatchCleanup: Equatable {
    /// Exit code for the CLI, based on observed results.
    ///   1: error; the destination was left alone or holds nothing.
    ///   3: write accepted but not verified (locked keychain / ambiguous).
    /// Nothing here returns 4: once the keychain has accepted a write this
    /// command neither deletes nor restores, so it can no longer produce the
    /// "could not prove what is at the destination" outcome that 4 names.
    var exitCode: Int32 {
        switch self {
        case .nothingStored, .removalNotAttempted: return 1
        case .leftInPlace: return 3
        }
    }
    /// The item was left in place (unreadable / ambiguous: nothing proves it is bad).
    /// `previousReplaced` = this was a rotation, so the previous value is gone and the
    /// unverified new one now occupies the slot.
    case leftInPlace(previousReplaced: Bool)
    /// Cleanup was refused before any delete API was called (`CleanupRefusal` says
    /// why): the item found at the destination is left in place, and the report
    /// says what it read back as. Not a deletion failure.
    case removalNotAttempted(CleanupRefusal, previousReplaced: Bool)
    /// Nothing to clean up: the write reported success but no item exists.
    /// `previousReplaced` = rotation: the previous value is gone too.
    case nothingStored(previousReplaced: Bool)
}

enum NonEmptyStatus {
    case present, missing, empty, unavailable

    var exitCode: Int32 {
        switch self {
        case .present: return 0
        case .missing: return 1
        case .empty: return 2
        case .unavailable: return 3
        }
    }
}

/// Why an explicit replacement could not establish a restorable backup. Each
/// case names what was actually observed, so the report never states a cause
/// the code did not see (#7 G1/G2).
enum BackupRefusal: Equatable {
    /// The old value could not be read with prompts disabled.
    case valueUnreadable
    /// The value was read, but the item's access settings or keychain could not be.
    case accessUnreadable
    /// The value and access settings were read, but the policy could not be
    /// rebuilt and reproduced in a nonsecret test item.
    case policyNotReproducible
}

enum ExplicitRestoreOutcome {
    case restored, unverified, mismatch, preparationFailed, failed(OSStatus)
    /// An item was already at the destination; the backup was not written.
    case destinationOccupied
    /// The destination could not be inspected; the backup was not written.
    case destinationUnknown
    /// No restore was tried: the keychain had accepted the new value, and after
    /// that this command does not put a backup back.
    case notAttempted
    var exitCode: Int32 { if case .mismatch = self { return 4 }; return 1 }
}

enum KeychainError: Error, LocalizedError {
    case osStatus(OSStatus, operation: String)
    case notFound
    case replacementBackupUnavailable(service: String, account: String, cause: BackupRefusal)
    case replacementChanged(service: String, account: String)
    case replacementProbeCleanupFailed(probeService: String)
    case explicitReplacementFailed(service: String, account: String, detail: String, recovery: ExplicitRestoreOutcome)
    /// The item's decrypt ACL trusts some application other than this binary
    /// (`owners` lists every trusted application found), or no decrypt entry at
    /// all could be attributed (`owners` empty). che-keychain never silently
    /// replaces such an item — SecItemUpdate would "succeed" while leaving the
    /// secret under another program's ACL (round 1 of #5) — so it refuses and
    /// names the explicit remedy.
    case foreignOwned(service: String, account: String, owners: [String], selfPath: String)
    /// A caller without a dialog (`--stdin`) asked to re-create an existing
    /// prompt-on-read item as allow-all: no dialog may widen an ACL.
    case aclWideningRefused(service: String, account: String)
    /// The caller confirmed the store against a stated slot state ("new item" /
    /// "replaces the existing value") and the write-time inspection disagrees.
    case destinationChanged(service: String, account: String, expectedExisting: Bool)
    /// The dialog described the destination's access class (own / allow-all /
    /// foreign) and the user consented to replacing THAT; by write time it is a
    /// different class. Consent does not carry over (#7 L1).
    case destinationClassChanged(service: String, account: String)
    /// The match is not a file-keychain item (data-protection / iCloud keychain):
    /// che-keychain can neither inspect its ACL nor delete it by reference.
    case unsupportedItem(service: String, account: String)
    /// More than one item matches service/account (e.g. one per keychain in the
    /// search list). We refuse to guess which one the caller means.
    case ambiguous(service: String, account: String, count: Int)
    /// The item's decrypt ACL has an "allow all applications" entry (alone or
    /// mixed with an application list). Such an entry carries no owner identity
    /// and any label in it can be forged, so the item cannot be attributed to
    /// this binary; overwriting it would change a value another program may
    /// own. Both `set` and `set --daemon` refuse; the remedy is `unset`.
    case unattributable(service: String, account: String)
    /// `unset` deleted `deleted` account(s) but could not delete `refused`
    /// (account → why). Reported after the sweep so the user sees exactly what
    /// remains; the remedy is the `security` CLI, not `unset` again.
    case undeletable(service: String, deleted: [String], refused: [(account: String, reason: String, fileKeychain: Bool)])
    /// A mode switch (delete + re-add) failed after the delete; the original
    /// item was restored (or not — `restored` says which).
    case replaceFailed(service: String, account: String, addStatus: OSStatus, restore: RestoreOutcome)

    /// The CLI exit code for this error — one accessor, so no error case can
    /// miss the mapping: 1 unless a cleanup outcome says 3 or 4.
    var exitCode: Int32 {
        switch self {
        case .explicitReplacementFailed(_, _, _, let recovery): return recovery.exitCode
        case .replacementBackupUnavailable, .replacementChanged, .replacementProbeCleanupFailed: return 1
        case .storedValueMismatch(_, _, _, let cleanup): return cleanup.exitCode
        case .replaceFailed(_, _, _, let restore):       return restore.exitCode
        case .osStatus, .notFound, .foreignOwned, .aclWideningRefused, .destinationChanged, .destinationClassChanged, .unsupportedItem, .ambiguous, .unattributable, .undeletable, .emptyValue:
            return 1   // exhaustive on purpose: a new case must choose
        }
    }
    /// Refused to store an empty value (#6): an empty item blocks later writes
    /// and is exactly the silent failure `security add-generic-password` has
    /// from a non-tty.
    case emptyValue(service: String, account: String)
    /// The value read back right after the write was not the value written
    /// (#6). `cleanup` says what was done about the item afterwards.
    case storedValueMismatch(service: String, account: String, reason: MismatchReason, cleanup: MismatchCleanup)

    var errorDescription: String? {
        switch self {
        case .osStatus(let status, let op):
            let text = (SecCopyErrorMessageString(status, nil) as String?) ?? ""
            var msg = "keychain \(op) failed (OSStatus \(status)\(text.isEmpty ? "" : ": \(text)"))"
            switch status {
            case errSecInvalidOwnerEdit:   // -25244
                msg += "\n  The keychain refused to let this binary modify or delete the item (owner edit)."
                msg += "\n  Remove it with: security delete-generic-password -s <service> -a <account>"
            case errSecDuplicateItem:      // -25299
                msg += "\n  An item with this service/account appeared between the ownership check and the write. Retry."
            default:
                if op.hasPrefix("set (") {
                    msg += "\n  Nothing was written. If this persists, remove the item first (`che-keychain unset --service <service> --account <account>`, or Keychain Access) and retry."
                }
            }
            return msg
        case .replacementBackupUnavailable(let svc, let acct, let cause):
            // Only what was observed. Deletion is offered solely as the user's decision to
            // discard the old value (same remedy plain `set` gives) — never as a way around
            // the refusal — because che-keychain holds no
            // copy of this value, and deleting to bypass a failed backup is exactly
            // what the backup exists to prevent (CLAUDE.md, README).
            let observed: String
            switch cause {
            case .valueUnreadable:
                observed = "its value cannot be read with prompts disabled, so there would be no copy to put back if the new value failed to land. Items created by `security add-generic-password` are one tested case of this"
            case .accessUnreadable:
                observed = "its value was read, but its access settings or keychain could not be, so the original access could not be restored if the new value failed to land"
            case .policyNotReproducible:
                observed = "its value and access settings were read, but that access policy could not be rebuilt, or a nonsecret test item carrying the rebuilt policy could not be created or did not reproduce it exactly, so a restore could not be trusted to put it back as it was"
            }
            return """
            cannot establish a restorable noninteractive backup of \(sanitize(svc))/\(sanitize(acct)) — no deletion was attempted on the original item.
              \(observed). `--replace` did not take this item. Nothing was deleted, and che-keychain holds no copy of the old value.
              To keep the old value, leave the item as it is and manage it with a program that can read it.
              To discard it — the user's decision, not the caller's; do not run this without the user's explicit confirmation, it permanently deletes the old value — remove it, then store again:
                che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
            """
        case .replacementProbeCleanupFailed(let probeService):
            return "the nonsecret recovery probe could not be removed: service=\(probeService), account=probe. The original item was not deleted; inspect the probe in Keychain Access before retrying."
        case .replacementChanged(let svc, let acct):
            return "the item, value or access settings changed before replacing \(sanitize(svc))/\(sanitize(acct)) — no deletion was attempted on the original item. Inspect the destination and retry."
        case .explicitReplacementFailed(let svc, let acct, let detail, let recovery):
            let outcome: String
            switch recovery {
            case .restored: outcome = "The original bytes and access settings were restored and verified; other metadata (label, comments, dates) was not preserved."
            case .unverified: outcome = "The restore was accepted but the original bytes and access settings could not be verified. Inspect the destination before retrying."
            case .mismatch: outcome = "The restore was accepted but its bytes or access settings differ from the backup. The destination is UNVERIFIED; inspect it in Keychain Access before taking further action."
            case .preparationFailed: outcome = "The original access settings could NOT be prepared for restoration; the destination's state is unknown. Inspect it before retrying."
            case .failed(let st): outcome = "The original item could NOT be restored (OSStatus \(st)); the destination's state is unknown. Inspect it before retrying."
            case .destinationOccupied: outcome = "An item was already at the destination, so the backup was NOT written over it. Inspect what is there in Keychain Access before taking further action."
            case .destinationUnknown: outcome = "The destination could not be inspected, so the backup was NOT written (restoring blind could write over something). Its state is unknown; inspect it in Keychain Access before taking further action."
            case .notAttempted: outcome = "The PREVIOUS item was deleted for the replace and has NOT been put back; the keychain accepted the new value, but nothing can now be found at the destination. After a successful write this command does not restore a backup (it cannot show that what is at the destination is its own). The destination is EMPTY as far as this command can see: store the secret again."
            }
            return "explicit replacement of \(sanitize(svc))/\(sanitize(acct)) failed: \(detail).\n  \(outcome)"
        case .notFound: return "keychain item not found"
        case .foreignOwned(let svc, let acct, let owners, let me):
            let shown = owners.prefix(8).joined(separator: ", ") + (owners.count > 8 ? ", … and \(owners.count - 8) more" : "")
            let evidence = owners.isEmpty
                ? "its decrypt ACL has no entry that names an application, so nothing ties it to this binary"
                : "its decrypt ACL trusts \(shown) — not only this binary (\(me))"
            return """
            keychain item \(svc)/\(acct) already exists but is not exclusively trusted to this che-keychain binary:
              \(evidence).
              Nothing was written to \(svc)/\(acct). che-keychain only overwrites items whose decrypt ACL trusts this \
            binary alone; anything else may belong to another program, and replacing it would destroy that program's secret.
              To replace it while keeping a backup: `che-keychain set --replace` with the same service/account. \
            It proceeds only if this binary can read the old value without a prompt, and otherwise refuses and changes nothing.
              To discard the old value instead — the user's decision, not the caller's; it permanently deletes the stored secret — \
            remove it explicitly, then retry:
                che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
              (`unset` removes every match it can, an iCloud-synchronized twin included; `security delete-generic-password \
            -s \(shellQuote(svc)) -a \(shellQuote(acct))` removes one local match per call.)
              If it was created by another copy of che-keychain (different install path), use that copy, or `set --replace` from this one. \
            If you added another application via "Always Allow", `set --replace` re-creates it trusted to this binary only.
            """
        case .unsupportedItem(let svc, let acct):
            return """
            keychain item \(svc)/\(acct) exists but is not a file-keychain item (data-protection or iCloud keychain), \
            so che-keychain cannot inspect its ACL and will not overwrite it. Nothing was written.
              If it is an iCloud-synchronized item, `unset` will try to remove it through the generic keychain API \
            and tell you if it cannot:
                che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
              Otherwise (data-protection keychain) remove or rename it in Keychain Access, then retry.
            """
        case .ambiguous(let svc, let acct, let n):
            return """
            \(n) keychain items match \(svc)/\(acct) (e.g. one per keychain in the search list, or an iCloud-synchronized twin). \
            Refusing to guess which one to write.
              Inspect them with:  security find-generic-password -s \(shellQuote(svc)) -a \(shellQuote(acct))
              To remove them:  che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
                (removes every match it can — an iCloud twin included, which iCloud then propagates — and reports any it cannot)
              To remove one local match per call:  security delete-generic-password -s \(shellQuote(svc)) -a \(shellQuote(acct))
              A twin that neither can remove lives in the iCloud / data-protection keychain: remove it in Keychain Access.
            """
        case .unattributable(let svc, let acct):
            return """
            keychain item \(svc)/\(acct) already exists with an "allow all applications" decrypt entry, which carries \
            no owner identity — che-keychain cannot tell whether it created it (this is also what `--daemon` items look like).
              Nothing was written to \(svc)/\(acct). Overwriting an item that may belong to another program is destructive, \
            so it is never a side effect of `set` — not even with --daemon.
              To rotate it while keeping a backup (the routine case for a --daemon item): `che-keychain set --replace --daemon` \
            with the same service/account.
              To discard the old value instead — the user's decision, not the caller's; it deletes the stored secret — remove it \
            explicitly first, then retry with the mode you want:
                che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
            """
        case .undeletable(let svc, let deleted, let refused):
            // The remedy command carries the RAW account (only shell-quoted): a
            // sanitized copy could name a different item. `sanitize` is display-only.
            let list = refused.map { r -> String in
                let head = "    \(r.account.isEmpty ? "(account attribute missing)" : sanitize(r.account)): \(r.reason)"
                guard r.fileKeychain else {
                    return head + "\n      → remove it in Keychain Access (it is not a file-keychain item; `security` cannot see it either)"
                }
                if r.account.isEmpty {
                    return head + "\n      security delete-generic-password -s \(shellQuote(svc))   # deletes the FIRST local match under the service — check with `security find-generic-password -s …` which one that is"
                }
                guard sanitize(r.account) == r.account else {
                    return head + "\n      → its account name contains control characters; remove it in Keychain Access"
                }
                return head + "\n      security delete-generic-password -s \(shellQuote(svc)) -a \(shellQuote(r.account))   # deletes the first local match"
            }.joined(separator: "\n")
            let done = deleted.isEmpty ? "removed nothing" : "removed \(deleted.count) account(s): \(deleted.map(sanitize).joined(separator: ", "))"
            return """
            unset \(sanitize(svc)): \(done); \(refused.count) match(es) could not be removed by che-keychain:
            \(list)
            """
        case .emptyValue(let svc, let acct):
            return "refusing to store an empty (or whitespace-only) value for \(sanitize(svc))/\(sanitize(acct)) — nothing was written."
        case .destinationClassChanged(let svc, let acct):
            return "the access class of \(sanitize(svc))/\(sanitize(acct)) changed after the dialog described it — nothing was written. The consent given was for the item the dialog showed; run the command again to see the current one."
        case .destinationChanged(let svc, let acct, let expected):
            return expected
                ? "the dialog said an item exists at \(sanitize(svc))/\(sanitize(acct)) and would be replaced, but none exists now — nothing was written. Retry."
                : "the dialog said \(sanitize(svc))/\(sanitize(acct)) was a new item, but an item exists there now — nothing was written; run again so the dialog can show what Store would replace."
        case .aclWideningRefused(let svc, let acct):
            return "--stdin --daemon would replace the existing prompt-on-read item \(sanitize(svc))/\(sanitize(acct)) with an allow-all one without any dialog — refused; nothing was written. Use the dialog or --from-clipboard for that, or `che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))` first."
        case .storedValueMismatch(let svc, let acct, let reason, let cleanup):
            let what: String
            switch reason {
            case .missing:    what = "the write reported success but no item exists at that service/account afterwards (if the write landed in a keychain outside the search list, an unverified copy may exist there)"
            case .unreadable: what = "the item is there but its value could not be read back (keychain locked, or a prompt would have been needed)"
            case .empty:      what = "the stored value read back empty"
            case .differs:    what = "the stored value read back differs from what was written"
            case .ambiguous:  what = "more than one item matched when reading back, so the written item could not be identified"
            }
            func status(_ st: OSStatus) -> String {
                let text = (SecCopyErrorMessageString(st, nil) as String?) ?? ""
                return "OSStatus \(st)\(text.isEmpty ? "" : ": \(text)")"
            }
            // The remedy depends on what was actually established. Ambiguity is
            // never answered by unlocking, so it never gets that advice (#15 M4).
            func remedy(for reason: MismatchReason) -> String {
                reason == .ambiguous
                    ? "Inspect the matching items in Keychain Access and resolve the ambiguity before retrying; no item was selected for removal."
                    : "Check the keychain's lock state and the consuming program's access before retrying."
            }
            let done: String
            switch cleanup {
            case .leftInPlace(let replaced):
                done = (replaced
                    ? "The new item was left in place but is UNVERIFIED; the previous value is GONE (it was deleted for the replace and nothing was put back). "
                    : "The item was left in place: nothing proves it is bad, and deleting it could destroy a good secret. ") + remedy(for: reason)
            case .removalNotAttempted(let why, let replaced):
                done = "Nothing was removed after the write — \(why.rawValue) — so the item found there (\(what)) was LEFT IN PLACE. "
                    + (replaced ? "The previous item was deleted for the replace and has not been restored. " : "")
                    + "Inspect the destination in Keychain Access before taking further action."
            case .nothingStored(let replaced):
                done = replaced
                    ? "Nothing is at that service/account now: the previous value was deleted for the replace, the new one cannot be found, and no backup was put back. Store the secret again."
                    : "Nothing was found at that service/account, so nothing verified is stored; if the write landed in a keychain outside the search list, an unverified copy may exist there. Retry."
            }
            return """
            stored value mismatch for \(sanitize(svc))/\(sanitize(acct)): \(what).
              \(done)
            """
        case .replaceFailed(let svc, let acct, let st, let restore):
            let text = (SecCopyErrorMessageString(st, nil) as String?) ?? ""
            let outcome: String
            switch restore {
            case .restored:
                outcome = "The previous value was re-stored as a prompt-on-read item trusted to this binary and read back; other item attributes (label, dates) were not preserved."
            case .restoredUnverified(let why):
                // `.ambiguous` means two items matched: unlocking cannot resolve
                // that, so it must not be the advice given (#15 M4).
                let how = why == .ambiguous
                    ? "more than one item matches, so the re-added value could not be identified — inspect the matching items in Keychain Access and resolve the ambiguity"
                    : "the read-back could not be performed (keychain locked, or a prompt would have been needed) — once the keychain is unlocked, read it with the program that uses it, or store it again"
                outcome = "The previous value was re-added as a prompt-on-read item (the keychain accepted it) but could not be read back to prove it: \(how)."
            case .mismatch(let why):
                // No `unset` here: the re-add was by name and so was the read-back,
                // so the item that reads back wrong cannot be shown to be the one
                // this command put there (#7 H2 applies to advice as well as code).
                outcome = "The previous value was re-added but reads back \(why.rawValue) — the destination holds an item this command cannot prove is its restore. Inspect it in Keychain Access before taking further action."
            case .lost(let loss):
                let why: String
                switch loss {
                case .previousUnreadable: why = "it could not be read before the replace"
                case .previousEmpty:      why = "it was itself empty"
                case .readdFailed(let rs): why = "re-add failed: OSStatus \(rs)"
                case .readdVanished:      why = "the keychain accepted the re-add, yet no item exists afterwards"
                case .destinationOccupied: why = "an item was already at the destination and restoring must never write over it"
                case .destinationUnknown:  why = "the destination could not be inspected, and restoring blind could write over something"
                }
                if case .readdFailed = loss {
                    outcome = "The previous item could NOT be restored (\(why)); the destination's state is unknown. Inspect it before retrying."
                } else if case .destinationOccupied = loss {
                    outcome = "The previous item was NOT restored (\(why)). Whatever is at \(sanitize(svc))/\(sanitize(acct)) now was left untouched; inspect it in Keychain Access before taking further action."
                } else if case .destinationUnknown = loss {
                    outcome = "The previous item was NOT restored (\(why)); the destination's state is unknown. Inspect it in Keychain Access before taking further action."
                } else {
                    outcome = "The previous item could NOT be restored (\(why)) — \(sanitize(svc))/\(sanitize(acct)) is now absent (unless something else re-created it meanwhile). Re-run `set` to store it again."
                }
            }
            return """
            replacing \(sanitize(svc))/\(sanitize(acct)) failed: the old item was deleted but adding the new one failed \
            (OSStatus \(st)\(text.isEmpty ? "" : ": \(text)")).
              \(outcome)
            """
        }
    }
}

/// Strings read from the keychain are written by other programs: strip
/// control characters before they reach a terminal, and cap the length.
func sanitize(_ s: String) -> String {
    let cleaned = s.unicodeScalars.filter { u in
        let cat = u.properties.generalCategory
        return u.value >= 0x20 && u.value != 0x7f && cat != .control && cat != .format
    }
    let capped = String(String.UnicodeScalarView(cleaned).prefix(256))
    return cleaned.count > 256 ? capped + "…" : capped
}

/// Single-quote a value for copy-paste into a POSIX shell. The remedy lines above
/// are the only exit from a refusal; a service containing a space or `;` must
/// not turn them into a different command.
func shellQuote(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// Thin wrapper over SecItem* for generic-password items stored in the
/// default keychain (login.keychain-db on macOS). Mirrors the surface
/// che-transport-mcp's Auth.swift uses so other che-* projects can adopt
/// the same shape.
enum KeychainStore {
    /// What already lives at service/account, as seen through its decrypt ACL.
    enum Existing: Equatable {
        case none
        /// Not created (solely) by this binary: some ACL entry that can reveal
        /// the secret (decrypt / any / export) trusts an application other than
        /// this binary's real path. `owners` lists every trusted application
        /// found; empty when no such entry names any application at all.
        case foreign(owners: [String])
        /// Every decrypt entry names applications, and every one of them is
        /// this binary's real path.
        case own
        /// Some entry that can reveal the secret is "allow all applications" and
        /// no such entry names another application — the shape `--daemon`
        /// writes, but also `security add-generic-password -A`. An allow-all
        /// entry mixed with a FOREIGN application classifies `.foreign` (that
        /// rule wins); whether an allow-all entry that hands over the
        /// plaintext exists is reported separately as `Found.allowAllPlaintextEntry`. No owner identity exists for
        /// such items (labels are forgeable).
        case allowAll
        /// Not a file-keychain item; ACL not inspectable, not deletable by us.
        case unsupported
    }

    /// Public view of `inspect` without the item reference.
    static func inspectExisting(service: String, account: String) throws -> Existing {
        try inspect(service: service, account: account).existing
    }

    /// Every authorization through which the secret can leave the keychain.
    static let revealingAuthorizations: Set<String> = Set(
        [kSecACLAuthorizationDecrypt, kSecACLAuthorizationAny,
         kSecACLAuthorizationExportClear, kSecACLAuthorizationExportWrapped].map { $0 as String })

    /// The authorizations that hand over the PLAINTEXT. `revealingAuthorizations`
    /// also counts export-wrapped, which is right for the conservative ownership
    /// question (anything that lets the secret leave counts against "ours alone")
    /// but wrong for "is this already readable by everything": exporting the
    /// wrapped value does not reveal it. The widening guard needs this set
    /// (round-6 verify J1, found by the cross-model reviewer).
    static let plaintextAuthorizations: Set<String> = Set(
        [kSecACLAuthorizationDecrypt, kSecACLAuthorizationAny,
         kSecACLAuthorizationExportClear].map { $0 as String })

    /// True when some entry that hands over the plaintext trusts every
    /// application — the shape `--daemon` writes. Judged on the serialized
    /// records, so the answer comes from access settings that were actually
    /// captured rather than from a classification taken earlier (#7 H1). An
    /// allow-all entry that only permits export-wrapped does not count (J1).
    static func hasAllowAllPlaintextEntry(_ records: [String]) -> Bool {
        records.contains { record in
            guard let data = record.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let auths = obj["authorizations"] as? [String],
                  auths.contains(where: plaintextAuthorizations.contains) else { return false }
            // `accessRecords` serializes "trusts every application" as a null
            // application list, the same shape `classify` reads from the API.
            return obj["applications"] is NSNull
        }
    }

    /// Refuse-before-typing check: throws exactly the refusal `save` would throw
    /// (foreign / unattributable / ambiguous), without writing anything.
    /// `set` and `set-pair` run it for every account before the dialog, so a
    /// policy refusal is never raised after a secret was typed or partially
    /// stored. With `allowReplacement` the backup and rehearsal still run after
    /// the dialog, so `replacementBackupUnavailable` / `replacementChanged` can
    /// follow a typed secret; they leave the original item untouched.
    @discardableResult
    static func preflight(service: String, accounts: [String], allowReplacement: Bool = false) throws -> [String: Bool] {
        var states: [String: Bool] = [:]
        for account in accounts {
            let found = try inspect(service: service, account: account)
            if !allowReplacement || found.existing == .unsupported {
                try refusal(for: found.existing, service: service, account: account)
            }
            if allowReplacement, let item = found.item {
                _ = try replacementBackup(item, service: service, account: account)
            }
            states[account] = found.existing != .none
        }
        return states
    }

    /// The single place that decides which existing items `save` refuses. The
    /// refusal set is deliberately identical for `set` and `set --daemon` —
    /// round 1 of #5 regressed precisely by making it mode-dependent.
    private static func refusal(for existing: Existing, service: String, account: String) throws {
        switch existing {
        case .foreign(let owners):
            throw KeychainError.foreignOwned(service: service, account: account, owners: owners, selfPath: try selfPath())
        case .allowAll:
            throw KeychainError.unattributable(service: service, account: account)
        case .unsupported:
            throw KeychainError.unsupportedItem(service: service, account: account)
        case .none, .own:
            return
        }
    }

    /// Write a value. Policy (decided in #5 after verify round 1, refined by
    /// verify rounds 2–4):
    ///
    ///   existing item                              set / set --daemon
    ///   absent                                     Add (allow-all ACL with --daemon)
    ///   own (decrypt trusts only this binary)      delete by reference + Add  (fresh ACL, requested mode)
    ///   foreign (decrypt trusts another app)       refuse + remedy (`unset`)
    ///   allow-all entry present (no identity)      refuse + remedy (`unset`)
    ///   not a file-keychain item                   refuse (Keychain Access)
    ///
    /// Why refuse foreign / allow-all items instead of updating them (user
    /// decision on #5): SecItemUpdate DOES succeed on an item another program
    /// created, but that leaves the new secret inside an item that program
    /// manages — and with --daemon it silently appended an allow-all ACL entry
    /// to that item (round 1). Replacing an item whose ACL lets any other
    /// application read it is a destructive act on someone else's secret, so
    /// it must be an explicit `unset` by the user, never a side effect of
    /// `set`. "Own" is a path identity, not provenance: an item some other
    /// program pre-created with a decrypt list naming only this binary is
    /// treated as ours (nothing else can read it) and IS replaced. An
    /// allow-all entry names no application, so such items (including our own
    /// --daemon items) cannot be told apart from anyone else's; refused in
    /// both modes.
    ///
    /// Why delete + add for our own items instead of an in-place update: an
    /// in-place update keeps whatever ACL the item already has, including an
    /// owner (ChangeACL) entry pre-planted by another program that only put
    /// this binary in the decrypt list — it could later widen the ACL and read
    /// the secret. Delete by reference and re-add gives a fresh ACL created by
    /// this binary (what the original code did). The old value is read first
    /// and re-stored if the add fails.
    ///
    /// API facts (probed 2026-09-10): SecItemDelete — by query or by
    /// kSecMatchItemList — answers errSecInvalidOwnerEdit (-25244) on an item
    /// another program created (this is where the original -25299 came from);
    /// SecKeychainItemDelete(ref) deletes it. SecItemUpdate with kSecAttrAccess
    /// unions ACL entries (5→7→9…), it never replaces them.
    ///
    /// `mayWidenExistingACL: false` (the `--stdin` caller): an existing own
    /// item is NOT re-created allow-all — no dialog may widen an ACL. Decided
    /// here, on the same inspection that decides the replace, so a probe error
    /// fails closed and nothing can change between the check and the write.
    /// A new allow-all item may still be created (documented decision).
    ///
    /// `expectingExisting` (the clipboard dialog): the user confirmed against
    /// "new item" (false) or "replaces the existing value" (true); if the
    /// write-time inspection disagrees, nothing is written.
    @discardableResult
    static func save(service: String, account: String, value: String, daemon: Bool = false, mayWidenExistingACL: Bool = true, expectingExisting: Bool? = nil, allowReplacement: Bool = false, expectedClass: Existing? = nil) throws -> Existing {
        // Empty or whitespace-only is refused for EVERY caller (set's three
        // sources and set-pair): such an item looks stored but cannot
        // authenticate and blocks the next write — the #6 failure class. The
        // value itself is stored as given: callers decide about line breaks
        // (InputSource.normalizeLine) and nothing is trimmed here.
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw KeychainError.emptyValue(service: service, account: account)
        }
        let found = try inspect(service: service, account: account)
        if let expected = expectingExisting {
            let exists: Bool
            if case .none = found.existing { exists = false } else { exists = true }
            guard exists == expected else { throw KeychainError.destinationChanged(service: service, account: account, expectedExisting: expected) }
        }
        if let expectedClass, found.existing != expectedClass {
            throw KeychainError.destinationClassChanged(service: service, account: account)
        }
        if allowReplacement, found.existing != .none, found.existing != .unsupported, let item = found.item {
            // A cheap early refusal only: an ACL carrying an allow-all entry is
            // already readable by everything, so rotating it widens nothing even
            // when another application in the same ACL makes it classify foreign
            // (#7 M1). The decision that authorizes the write is taken again
            // inside `replaceExplicitly`, against the captured access settings.
            if daemon && !mayWidenExistingACL && !found.allowAllPlaintextEntry {
                throw KeychainError.aclWideningRefused(service: service, account: account)
            }
            try replaceExplicitly(item, service: service, account: account, value: value,
                                  daemon: daemon, mayWidenExistingACL: mayWidenExistingACL)
            return found.existing
        }
        try refusal(for: found.existing, service: service, account: account)
        switch found.existing {
        case .none:
            try add(service: service, account: account, value: value, daemon: daemon)
            #if DEBUG
            afterAddHook?(service, account)
            #endif
            let rb = readBack(service: service, account: account, expected: Data(value.utf8))
            if let why = rb.mismatch {
                // Nothing is removed. A name lookup cannot show that the item now
                // at the destination is the one this call wrote, so even a proven
                // bad value is left alone and reported (#7 H2).
                let cleanup: MismatchCleanup
                switch why {
                case .empty, .differs:        cleanup = .removalNotAttempted(.writeNotAttributable, previousReplaced: false)
                case .missing:                cleanup = .nothingStored(previousReplaced: false)
                case .unreadable, .ambiguous: cleanup = .leftInPlace(previousReplaced: false)
                }
                throw KeychainError.storedValueMismatch(service: service, account: account, reason: why, cleanup: cleanup)
            }
        case .own:
            if daemon && !mayWidenExistingACL {
                throw KeychainError.aclWideningRefused(service: service, account: account)
            }
            try replaceOwnItem(found.item!, service: service, account: account, value: value, daemon: daemon)
        case .foreign, .allowAll, .unsupported:
            preconditionFailure("refusal(for:) must have thrown")
        }
        return found.existing
    }

    #if DEBUG
    /// Test seams (#6, debug builds only). `readBackOverride` replaces the real
    /// read-back (nil = item missing; empty / other data as returned);
    /// `readBackReasonOverride` forces a reason the override cannot express
    /// (`.unreadable`, `.ambiguous`); the
    /// cleanup outcome so the `.removalFailed` path is testable.
    static var readBackOverride: ((String, String) -> Data?)?
    /// Consulted on every read-back; a non-nil result forces that reason (so a
    /// test can make the SECOND read-back — the restore's — unreadable).
    static var readBackReasonOverride: ((String, String) -> MismatchReason?)?
    static var addRawStatusOverride: ((String, String, Data) -> OSStatus?)?
    /// Runs after the destination was classified and before its replacement
    /// backup is taken — the window in which another writer can tighten an ACL
    /// (#7 H1).
    static var afterInspectHook: ((String, String) -> Void)?
    /// Runs after the keychain accepted a write and before the read-back — the
    /// window in which another writer can delete and recreate the destination
    /// (#7 H2).
    static var afterAddHook: ((String, String) -> Void)?
    /// Makes `inspect` throw when it returns true, so a test can reach the
    /// "destination could not be inspected" branches (#7 G3).
    static var inspectErrorOverride: ((String, String) -> Bool)?
    /// The serialized access records currently at a destination, for tests that
    /// need to see what `replaceExplicitly` would judge.
    static func debugAccessRecords(service: String, account: String) -> [String]? {
        guard let item = (try? inspect(service: service, account: account))?.item else { return nil }
        return try? accessRecords({ var a: SecAccess?; _ = SecKeychainItemCopyAccess(item, &a); return a! }())
    }
    #endif

    /// Run `body` with keychain user interaction disabled: our own items
    /// decrypt without a prompt, and a prompt would hang a headless caller.
    /// The setting is process-global and `set-pair` performs a second save
    /// afterwards, so the prior state is always restored — to what was read,
    /// or to the interactive default when the probe itself failed.
    private static func withoutInteraction<T>(_ body: () throws -> T) rethrows -> T {
        var wasAllowed: DarwinBoolean = true
        _ = SecKeychainGetUserInteractionAllowed(&wasAllowed)
        _ = SecKeychainSetUserInteractionAllowed(false)
        defer { _ = SecKeychainSetUserInteractionAllowed(wasAllowed.boolValue) }
        return try body()
    }

    private struct ReadBack { let mismatch: MismatchReason? }

    /// Post-write read-back (#6). Looks the item up with the same scope as
    /// `inspect` (synchronizable twins included) so that verification looks
    /// where the write went; exactly one file-keychain item must match.
    private static func readBack(service: String, account: String, expected: Data) -> ReadBack {
        #if DEBUG
        if let forced = readBackReasonOverride?(service, account) { return ReadBack(mismatch: forced) }
        #endif
        return withoutInteraction {
            let q: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnRef as String: true
            ]
            var out: CFTypeRef?
            let st = SecItemCopyMatching(q as CFDictionary, &out)
            if st == errSecItemNotFound { return ReadBack(mismatch: .missing) }
            guard st == errSecSuccess, let refs = out as? [AnyObject] else { return ReadBack(mismatch: .unreadable) }
            if refs.isEmpty { return ReadBack(mismatch: .missing) }
            guard refs.count == 1 else { return ReadBack(mismatch: .ambiguous) }
            guard CFGetTypeID(refs[0]) == SecKeychainItemGetTypeID() else { return ReadBack(mismatch: .unreadable) }
            let item = refs[0] as! SecKeychainItem
            let data: Data?
            #if DEBUG
            if let o = readBackOverride {
                // The seam replaces only the bytes read; the lookup stays real so
                // cleanup operates on the actual item.
                guard let d = o(service, account) else { return ReadBack(mismatch: .missing) }
                data = d
            } else {
                data = readValue(of: item)
            }
            #else
            data = readValue(of: item)
            #endif
            guard let d = data else { return ReadBack(mismatch: .unreadable) }
            if d.isEmpty { return ReadBack(mismatch: .empty) }
            return ReadBack(mismatch: d == expected ? nil : .differs)
        }
    }

    private static func readValue(of item: SecKeychainItem) -> Data? {
        let rq: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecMatchItemList as String: [item], kSecReturnData as String: true]
        var data: CFTypeRef?
        guard SecItemCopyMatching(rq as CFDictionary, &data) == errSecSuccess else { return nil }
        return data as? Data
    }

    /// Delete the item the read-back identified (the very reference it read),
    /// with prompts disabled. Never the broad `unset` sweep (#5 policy).
    /// Remove the item the read-back found — but only if it is still ours:
    /// a third party could have replaced our just-written item before the
    /// read-back, and `SecKeychainItemDelete(ref)` would delete theirs. The
    /// same inspection that guards every write guards this delete (`.own`,
    /// or `.allowAll` for a daemon write, and the very same reference).
    private struct ReplacementBackup {
        var data: Data
        let access: SecAccess
        let keychain: SecKeychain
        let accessRecords: [String]
    }

    /// Compare API-visible ACL contents in memory; comparison records are never
    /// logged or printed. Entry and application-list ordering is immaterial.
    private static func accessRecords(_ access: SecAccess) throws -> [String] {
        var list: CFArray?
        guard SecAccessCopyACLList(access, &list) == errSecSuccess, let acls = list as? [SecACL] else {
            throw KeychainError.osStatus(errSecDecode, operation: "decode access backup")
        }
        return try acls.compactMap { acl -> String? in
            guard let authorizations = SecACLCopyAuthorizations(acl) as? [String] else {
                throw KeychainError.osStatus(errSecDecode, operation: "decode access authorizations")
            }
            // Integrity binds the particular database record and is regenerated;
            // all authorization policy, including partition IDs, is compared.
            if authorizations == [kSecACLAuthorizationIntegrity as String] { return nil }
            var apps: CFArray?; var description: CFString?
            var selector = SecKeychainPromptSelector(rawValue: 0)
            guard SecACLCopyContents(acl, &apps, &description, &selector) == errSecSuccess else {
                throw KeychainError.osStatus(errSecDecode, operation: "decode access contents")
            }
            var record: [String: Any] = ["authorizations": authorizations.sorted(), "selector": selector.rawValue,
                                         "applications": NSNull(), "description": NSNull()]
            if let description { record["description"] = description as String }
            if let apps {
                guard let trusted = apps as? [SecTrustedApplication] else {
                    throw KeychainError.osStatus(errSecDecode, operation: "decode trusted applications")
                }
                record["applications"] = try trusted.map { app -> String in
                    var data: CFData?
                    guard SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let bytes = data as Data? else {
                        throw KeychainError.osStatus(errSecDecode, operation: "decode trusted application")
                    }
                    return bytes.base64EncodedString()
                }.sorted()
            }
            return String(decoding: try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]), as: UTF8.self)
        }.sorted()
    }

    private static func replacementBackup(_ item: SecKeychainItem, service: String, account: String) throws -> ReplacementBackup {
        try withoutInteraction {
            guard let data = readValue(of: item) else {
                throw KeychainError.replacementBackupUnavailable(service: service, account: account, cause: .valueUnreadable)
            }
            var access: SecAccess?; var keychain: SecKeychain?
            guard SecKeychainItemCopyAccess(item, &access) == errSecSuccess, let access,
                  SecKeychainItemCopyKeychain(item, &keychain) == errSecSuccess, let keychain,
                  let records = try? accessRecords(access) else {
                throw KeychainError.replacementBackupUnavailable(service: service, account: account, cause: .accessUnreadable)
            }
            return ReplacementBackup(data: data, access: access, keychain: keychain, accessRecords: records)
        }
    }

    /// Stored ACL objects carry database-specific handles and integrity data.
    /// Rebuild supported simple entries in a fresh Access instead of reusing
    /// that object. Partition metadata is regenerated by macOS; the rehearsal
    /// below requires it to match before the original is touched.
    private static func rebuiltAccess(_ original: SecAccess) throws -> SecAccess {
        var fresh: SecAccess?
        let created = SecAccessCreate("che-keychain recovery" as CFString, nil, &fresh)
        guard created == errSecSuccess, let fresh else { throw KeychainError.osStatus(created, operation: "prepare recovery access") }
        var defaults: CFArray?; var originalList: CFArray?
        guard SecAccessCopyACLList(fresh, &defaults) == errSecSuccess, let initial = defaults as? [SecACL],
              SecAccessCopyACLList(original, &originalList) == errSecSuccess, let entries = originalList as? [SecACL] else {
            throw KeychainError.notFound
        }
        var newOwner: SecACL?
        for acl in initial {
            guard let rights = SecACLCopyAuthorizations(acl) as? [String] else { throw KeychainError.notFound }
            if rights == [kSecACLAuthorizationChangeACL as String] { newOwner = acl }
            else { guard SecACLRemove(acl) == errSecSuccess else { throw KeychainError.notFound } }
        }
        guard let newOwner else { throw KeychainError.notFound }
        var owners = 0
        for acl in entries {
            guard let rights = SecACLCopyAuthorizations(acl) as? [String], !rights.isEmpty else { throw KeychainError.notFound }
            // PartitionID is the value returned by SecACLCopyAuthorizations;
            // no private Security API is called. Unknown forms fail rehearsal.
            if rights == [kSecACLAuthorizationIntegrity as String] || rights == ["ACLAuthorizationPartitionID"] { continue }
            var apps: CFArray?; var description: CFString?
            var selector = SecKeychainPromptSelector(rawValue: 0)
            guard SecACLCopyContents(acl, &apps, &description, &selector) == errSecSuccess, let description else { throw KeychainError.notFound }
            if rights == [kSecACLAuthorizationChangeACL as String] {
                owners += 1
                guard owners == 1, SecACLSetContents(newOwner, apps, description, selector) == errSecSuccess else { throw KeychainError.notFound }
            } else {
                guard !rights.contains(kSecACLAuthorizationChangeACL as String) else { throw KeychainError.notFound }
                var entry: SecACL?
                guard SecACLCreateWithSimpleContents(fresh, apps, description, selector, &entry) == errSecSuccess, let entry,
                      SecACLUpdateAuthorizations(entry, rights as CFArray) == errSecSuccess else { throw KeychainError.notFound }
            }
        }
        guard owners == 1 else { throw KeychainError.notFound }
        return fresh
    }

    private static func rehearseRecovery(_ backup: ReplacementBackup, service: String, account: String) throws {
        try withoutInteraction {
            let access: SecAccess
            do { access = try rebuiltAccess(backup.access) }
            catch { throw KeychainError.replacementBackupUnavailable(service: service, account: account, cause: .policyNotReproducible) }
            let probeService = "che-keychain-recovery-probe-" + UUID().uuidString
            let probeData = Data("nonsecret recovery capability check".utf8)
            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: probeService,
                kSecAttrAccount as String: "probe", kSecValueData as String: probeData, kSecAttrAccess as String: access,
                kSecUseKeychain as String: backup.keychain, kSecReturnRef as String: true]
            var result: CFTypeRef?
            let status = SecItemAdd(query as CFDictionary, &result)
            guard status == errSecSuccess else { throw KeychainError.replacementBackupUnavailable(service: service, account: account, cause: .policyNotReproducible) }
            guard let result, CFGetTypeID(result) == SecKeychainItemGetTypeID() else {
                throw KeychainError.replacementProbeCleanupFailed(probeService: probeService)
            }
            let probe = result as! SecKeychainItem
            let read = try? replacementBackup(probe, service: probeService, account: "probe")
            let matches = read?.data == probeData && read?.accessRecords == backup.accessRecords
            guard SecKeychainItemDelete(probe) == errSecSuccess else {
                throw KeychainError.replacementProbeCleanupFailed(probeService: probeService)
            }
            guard matches else { throw KeychainError.replacementBackupUnavailable(service: service, account: account, cause: .policyNotReproducible) }
        }
    }

    private static func restoreExplicit(_ backup: ReplacementBackup, service: String, account: String) -> ExplicitRestoreOutcome {
        withoutInteraction {
            guard let access = try? rebuiltAccess(backup.access) else { return .preparationFailed }
            // Never write over whatever is at the destination now: the backup may
            // be older than an item another writer has since put there.
            guard let seen = try? inspect(service: service, account: account) else { return .destinationUnknown }
            guard case .none = seen.existing else { return .destinationOccupied }
            let status = addRaw(service: service, account: account, data: backup.data, access: access, keychain: backup.keychain)
            guard status == errSecSuccess else { return .failed(status) }
            guard let found = try? inspect(service: service, account: account), let item = found.item,
                  let restored = try? replacementBackup(item, service: service, account: account) else { return .unverified }
            return restored.data == backup.data && restored.accessRecords == backup.accessRecords && CFEqual(restored.keychain, backup.keychain)
                ? .restored : .mismatch
        }
    }

    private static func replaceExplicitly(_ item: SecKeychainItem, service: String, account: String, value: String, daemon: Bool, mayWidenExistingACL: Bool = true) throws {
        #if DEBUG
        afterInspectHook?(service, account)
        #endif
        var backup = try replacementBackup(item, service: service, account: account)
        defer { backup.data.resetBytes(in: 0..<backup.data.count) }
        try rehearseRecovery(backup, service: service, account: account)
        // Prepare fresh access before deleting anything. The new value never
        // inherits the old item's owner/change-ACL permissions.
        let access = daemon ? try allowAllAccess(label: daemonLabel(service: service, account: account)) : nil
        guard let current = try? inspect(service: service, account: account), let currentItem = current.item,
              CFEqual(currentItem, item),
              let now = try? replacementBackup(currentItem, service: service, account: account),
              now.data == backup.data, now.accessRecords == backup.accessRecords, CFEqual(now.keychain, backup.keychain) else {
            throw KeychainError.replacementChanged(service: service, account: account)
        }
        // The classification in `save` was taken before this backup existed, so
        // another writer could have tightened the ACL in between. Decide again on
        // what was actually captured and on what is there immediately before the
        // delete; an earlier reading never authorizes the write by itself (#7 H1).
        if daemon && !mayWidenExistingACL {
            guard hasAllowAllPlaintextEntry(backup.accessRecords),
                  hasAllowAllPlaintextEntry(now.accessRecords) else {
                throw KeychainError.aclWideningRefused(service: service, account: account)
            }
        }
        // This is an immediate observation, not a transaction or a lock against
        // another process changing the item after this check.
        let deleted = withoutInteraction { SecKeychainItemDelete(item) }
        guard deleted == errSecSuccess else { throw KeychainError.osStatus(deleted, operation: "explicit replacement (delete backed-up item)") }
        let added = addRaw(service: service, account: account, data: Data(value.utf8), access: access, keychain: backup.keychain)
        #if DEBUG
        if added == errSecSuccess { afterAddHook?(service, account) }
        #endif
        guard added == errSecSuccess else {
            throw KeychainError.explicitReplacementFailed(service: service, account: account,
                detail: "adding the new value returned OSStatus \(added)", recovery: restoreExplicit(backup, service: service, account: account))
        }
        let read = readBack(service: service, account: account, expected: Data(value.utf8))
        guard let reason = read.mismatch else { return }
        switch reason {
        case .unreadable, .ambiguous:
            throw KeychainError.storedValueMismatch(service: service, account: account, reason: reason,
                cleanup: .leftInPlace(previousReplaced: true))
        case .empty, .differs:
            throw KeychainError.storedValueMismatch(service: service, account: account, reason: reason,
                cleanup: .removalNotAttempted(.writeNotAttributable, previousReplaced: true))
        case .missing:
            throw KeychainError.explicitReplacementFailed(service: service, account: account,
                detail: "new value verification returned \(reason.rawValue)", recovery: .notAttempted)
        }
    }

    /// Own item → delete by reference and re-add with the requested access.
    /// The SecAccess is built before the delete. The old value is read first —
    /// best-effort and with keychain prompts disabled, so a locked keychain or
    /// a partition-ID gate can never hang a headless caller here — purely so
    /// it can be re-added if the Add fails; if it could not be read, the
    /// failure report says the item could not be restored.
    private static func replaceOwnItem(_ item: SecKeychainItem, service: String, account: String, value: String, daemon: Bool) throws {
        // Best-effort read of the current value, prompts disabled (never hang).
        var old: Data? = nil
        do {
            var oldData: CFTypeRef?
            let rq: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecMatchItemList as String: [item], kSecReturnData as String: true]
            var wasAllowed: DarwinBoolean = true
            _ = SecKeychainGetUserInteractionAllowed(&wasAllowed)
            _ = SecKeychainSetUserInteractionAllowed(false)
            let rst = SecItemCopyMatching(rq as CFDictionary, &oldData)
            _ = SecKeychainSetUserInteractionAllowed(wasAllowed.boolValue)
            if rst == errSecSuccess { old = oldData as? Data }
        }
        // Best-effort wipe of the restore buffer only; the new value itself
        // (String from the dialog) is not wiped — pre-existing, see README.
        defer { if old != nil { old!.resetBytes(in: 0..<old!.count) } }   // in place: `old` is the sole reference
        let access = daemon ? try allowAllAccess(label: daemonLabel(service: service, account: account)) : nil
        // Re-create the item in the keychain it lives in, not the default one.
        var keychain: SecKeychain?
        _ = SecKeychainItemCopyKeychain(item, &keychain)
        let dst = SecKeychainItemDelete(item)
        guard dst == errSecSuccess else { throw KeychainError.osStatus(dst, operation: "set (delete own item before re-creating it)") }
        let ast = addRaw(service: service, account: account, data: Data(value.utf8), access: access, keychain: keychain)
        #if DEBUG
        if ast == errSecSuccess { afterAddHook?(service, account) }
        #endif
        guard ast == errSecSuccess else {
            // Same restore + read-back as a failed rotation: the report says which
            // of the four outcomes happened, never a bare "restored"/"lost".
            let restore = restorePrevious(old, service: service, account: account, keychain: keychain)
            throw KeychainError.replaceFailed(service: service, account: account, addStatus: ast, restore: restore)
        }
        // Verify the write. Once the keychain has accepted it, the previous value
        // is NOT put back and nothing is deleted: a name lookup cannot show that
        // what is at the destination is this write (#7 H2). The report names the
        // state that was actually established.
        let rb = readBack(service: service, account: account, expected: Data(value.utf8))
        if let why = rb.mismatch {
            let cleanup: MismatchCleanup
            switch why {
            case .empty, .differs:        cleanup = .removalNotAttempted(.writeNotAttributable, previousReplaced: true)
            case .missing:                cleanup = .nothingStored(previousReplaced: true)
            case .unreadable, .ambiguous: cleanup = .leftInPlace(previousReplaced: true)
            }
            throw KeychainError.storedValueMismatch(service: service, account: account, reason: why, cleanup: cleanup)
        }
    }

    /// Re-add the previous value (prompt-on-read) after a failed rotation and
    /// read it back; the outcome names exactly what happened to it.
    private static func restorePrevious(_ old: Data?, service: String, account: String, keychain: SecKeychain?) -> RestoreOutcome {
        guard let o = old else { return .lost(.previousUnreadable) }
        guard !o.isEmpty else { return .lost(.previousEmpty) }
        // Same rule as the explicit path: restore only into an empty destination.
        guard let seen = try? inspect(service: service, account: account) else { return .lost(.destinationUnknown) }
        guard case .none = seen.existing else { return .lost(.destinationOccupied) }
        let st = addRaw(service: service, account: account, data: o, access: nil, keychain: keychain)
        guard st == errSecSuccess else { return .lost(.readdFailed(st)) }
        // Proof of failure vs inability to prove success — same split as the main path.
        switch readBack(service: service, account: account, expected: o).mismatch {
        case nil:                           return .restored
        case .unreadable?:                 return .restoredUnverified(.unreadable)
        case .ambiguous?:                  return .restoredUnverified(.ambiguous)
        case .missing?:                     return .lost(.readdVanished)
        case .empty?:                       return .mismatch(.empty)
        case .differs?:                     return .mismatch(.differs)
        }
    }

    private static func add(service: String, account: String, value: String, daemon: Bool) throws {
        // Daemon-readable application ACL; partition-ID and lock state still apply.
        // Use ONLY for low-sensitivity creds a headless launchd agent reads.
        // Fail loudly if the access can't be built — never silently store a
        // prompt-on-read item, which would hang the very daemon this serves.
        let access = daemon ? try allowAllAccess(label: daemonLabel(service: service, account: account)) : nil
        let st = addRaw(service: service, account: account, data: Data(value.utf8), access: access)
        guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "set (add)") }
    }

    private static func addRaw(service: String, account: String, data: Data, access: SecAccess?, keychain: SecKeychain? = nil) -> OSStatus {
        #if DEBUG
        if let forced = addRawStatusOverride?(service, account, data) { return forced }
        #endif
        var add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]
        if let access = access { add[kSecAttrAccess as String] = access }
        if let keychain = keychain { add[kSecUseKeychain as String] = keychain }
        return SecItemAdd(add as CFDictionary, nil)
    }

    /// Optional shape check. Never prompt, reveal the value, or widen access;
    /// a foreign, allow-all, ambiguous or unreadable item is not "empty".
    static func nonEmptyStatus(service: String, account: String) -> NonEmptyStatus {
        guard let found = try? inspect(service: service, account: account) else { return .unavailable }
        if found.existing == .none { return .missing }
        guard found.existing == .own, let item = found.item else { return .unavailable }
        return withoutInteraction {
            guard let bytes = readValue(of: item) else { return .unavailable }
            return bytes.isEmpty ? .empty : .present
        }
    }

    static func has(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// Delete one account, or every account under a service. Returns the
    /// accounts removed. Each matching item is deleted by reference
    /// (SecKeychainItemDelete), which — unlike the query-based SecItemDelete the
    /// old loop used (it threw at the first -25244 and left the rest) — also
    /// removes items created by other programs, so `unset` is the remedy `set`
    /// names for them. Nothing is skipped in silence: a match that is not a
    /// file-keychain item, or a delete the keychain refuses, is reported after
    /// the sweep with the `security` remedy, together with what was removed.
    @discardableResult
    static func unset(service: String, account: String? = nil) throws -> [String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true
        ]
        if let account = account { query[kSecAttrAccount as String] = account }
        var out: CFTypeRef?
        let st = SecItemCopyMatching(query as CFDictionary, &out)
        if st == errSecItemNotFound { return [] }
        guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "unset (list items)") }
        guard let rows = out as? [[String: Any]] else { throw KeychainError.osStatus(errSecDecode, operation: "unset (decode item list)") }
        var deleted: [String] = []
        var refused: [(account: String, reason: String, fileKeychain: Bool)] = []
        func statusText(_ st: OSStatus) -> String {
            let text = (SecCopyErrorMessageString(st, nil) as String?) ?? ""
            return "OSStatus \(st)\(text.isEmpty ? "" : " (\(text))")"
        }
        for row in rows {
            let acct = row[kSecAttrAccount as String] as? String ?? account ?? ""
            let synced = (row[kSecAttrSynchronizable as String] as? Bool) == true || (row[kSecAttrSynchronizable as String] as? Int) == 1
            guard let ref = row[kSecValueRef as String], CFGetTypeID(ref as CFTypeRef) == SecKeychainItemGetTypeID() else {
                // Not a file-keychain item: SecKeychainItemDelete cannot take it,
                // and kSecMatchItemList accepts SecKeychainItemRefs only, so try
                // the generic API by attributes (synchronizable items only —
                // a non-synced query could hit a local twin instead). The
                // status is reported verbatim; nothing is assumed from it.
                if synced, !acct.isEmpty {
                    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                            kSecAttrAccount as String: acct, kSecAttrSynchronizable as String: true]
                    let st = SecItemDelete(q as CFDictionary)
                    if st == errSecSuccess || st == errSecItemNotFound { deleted.append(acct); continue }
                    refused.append((acct, "iCloud-synchronized item; SecItemDelete answered \(statusText(st))", false))
                } else {
                    refused.append((acct, "not a file-keychain item (data-protection keychain); no delete path from che-keychain", false))
                }
                continue
            }
            let del = SecKeychainItemDelete(ref as! SecKeychainItem)
            switch del {
            case errSecSuccess: deleted.append(acct)
            default: refused.append((acct, statusText(del), true))
            }
        }
        var seen = Set<String>()
        let uniqueDeleted = deleted.filter { seen.insert($0).inserted }
        if !refused.isEmpty {
            throw KeychainError.undeletable(service: service, deleted: uniqueDeleted, refused: refused)
        }
        return uniqueDeleted
    }

    // MARK: - Ownership inspection

    private struct Found {
        let existing: Existing
        let item: SecKeychainItem?
        /// Some entry that can reveal the secret trusts every application. Kept
        /// separately from `existing` because a foreign application in the same
        /// ACL wins the classification while saying nothing about whether the
        /// item is already readable by everything (#7 M1).
        var allowAllPlaintextEntry: Bool = false
    }

    private static func inspect(service: String, account: String) throws -> Found {
        #if DEBUG
        if inspectErrorOverride?(service, account) == true {
            throw KeychainError.osStatus(errSecInteractionNotAllowed, operation: "set (look up existing item) [test seam]")
        }
        #endif
        // Inspection never needs the user's approval; make sure it can never
        // block a headless caller on a SecurityAgent prompt either.
        var wasAllowed: DarwinBoolean = true
        _ = SecKeychainGetUserInteractionAllowed(&wasAllowed)
        _ = SecKeychainSetUserInteractionAllowed(false)
        defer { _ = SecKeychainSetUserInteractionAllowed(wasAllowed.boolValue) }
        var out: CFTypeRef?
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return Found(existing: .none, item: nil) }
        guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "set (look up existing item)") }
        guard let refs = out as? [AnyObject] else { throw KeychainError.osStatus(errSecDecode, operation: "set (decode lookup result)") }
        if refs.isEmpty { return Found(existing: .none, item: nil) }
        guard refs.count == 1 else {
            throw KeychainError.ambiguous(service: service, account: account, count: refs.count)
        }
        guard CFGetTypeID(refs[0]) == SecKeychainItemGetTypeID() else {
            // Not a file-keychain item (e.g. data-protection keychain): we cannot
            // read its ACL or delete it. Refuse rather than crash or guess.
            return Found(existing: .unsupported, item: nil)
        }
        let item = refs[0] as! SecKeychainItem
        let verdict = try classify(item: item, service: service, account: account)
        return Found(existing: verdict.existing, item: item, allowAllPlaintextEntry: verdict.allowAllPlaintextEntry)
    }

    /// Decide ownership from every ACL entry that can reveal the secret
    /// (decrypt, "any", export clear / wrapped), fail-closed:
    ///  1. any such entry that trusts an application other than this binary's
    ///     real path → foreign (all applications reported). `security -T a -T b`
    ///     puts both apps in ONE entry, so the rule is over applications.
    ///  2. otherwise, any "allow all applications" entry (nil list) → allowAll,
    ///     even when mixed with an entry naming only this binary.
    ///  3. otherwise (every entry names only this binary) → own.
    ///  4. no such entry at all → foreign with no owners (nothing ties it to us).
    ///  5. anything that cannot be read or decoded → thrown OSStatus (the caller
    ///     refuses; nothing is written).
    private static func classify(item: SecKeychainItem, service: String, account: String) throws -> (existing: Existing, allowAllPlaintextEntry: Bool) {
        var access: SecAccess?
        let ast = SecKeychainItemCopyAccess(item, &access)
        guard ast == errSecSuccess, let acc = access else {
            throw KeychainError.osStatus(ast, operation: "set (read item ACL)")
        }
        var aclArray: CFArray?
        let lst = SecAccessCopyACLList(acc, &aclArray)
        guard lst == errSecSuccess else { throw KeychainError.osStatus(lst, operation: "set (list ACL entries)") }
        guard let allAcls = aclArray as? [SecACL] else {
            throw KeychainError.osStatus(errSecDecode, operation: "set (decode ACL entries)")
        }
        let revealing = revealingAuthorizations
        var acls: [SecACL] = []
        for acl in allAcls {
            guard let auths = SecACLCopyAuthorizations(acl) as? [String] else {
                throw KeychainError.osStatus(errSecDecode, operation: "set (decode ACL authorizations)")
            }
            if auths.contains(where: revealing.contains) { acls.append(acl) }
        }
        var apps: [String] = []      // raw paths, compared unsanitized
        var sawAllowAll = false          // any revealing entry is allow-all (ownership: conservative)
        var sawAllowAllPlaintext = false // an allow-all entry hands over the plaintext (widening guard)
        for acl in acls {
            var appList: CFArray?; var desc: CFString?; var sel = SecKeychainPromptSelector(rawValue: 0)
            let cst = SecACLCopyContents(acl, &appList, &desc, &sel)
            guard cst == errSecSuccess else { throw KeychainError.osStatus(cst, operation: "set (read ACL entry)") }
            guard let appsArray = appList else {                                  // nil application list = any application
                sawAllowAll = true
                if let auths = SecACLCopyAuthorizations(acl) as? [String], auths.contains(where: plaintextAuthorizations.contains) {
                    sawAllowAllPlaintext = true
                }
                continue
            }
            guard let list = appsArray as? [SecTrustedApplication] else {
                throw KeychainError.osStatus(errSecDecode, operation: "set (decode trusted-application list)")
            }
            for app in list {
                guard let path = trustedApplicationPath(app) else {
                    throw KeychainError.osStatus(errSecDecode, operation: "set (read trusted application)")
                }
                apps.append(path)
            }
        }
        let me = try selfPath()
        // Only an absolute path can be resolved without consulting the caller's
        // working directory; anything else is treated as another application.
        let isMe: (String) -> Bool = { $0.hasPrefix("/") && realpath($0) == me }
        if apps.contains(where: { !isMe($0) }) {
            var seen = Set<String>()
            var owners = apps.map { sanitize($0) }.filter { seen.insert($0).inserted }
            if sawAllowAll { owners.append("any application (allow-all entry)") }
            return (.foreign(owners: owners), sawAllowAllPlaintext)
        }
        if sawAllowAll { return (.allowAll, sawAllowAllPlaintext) }
        if apps.isEmpty { return (.foreign(owners: []), false) }
        return (.own, false)
    }

    /// The ACL description we stamp on daemon items (display only — it is NOT
    /// an ownership fingerprint: any program can write the same string).
    private static func daemonLabel(service: String, account: String) -> String { "\(service)/\(account)" }

    /// SecTrustedApplicationCopyData returns the application's path as a
    /// NUL-terminated C string. Returned raw (nil if unreadable or not valid
    /// UTF-8 — the caller throws); sanitize only when displaying.
    private static func trustedApplicationPath(_ app: SecTrustedApplication) -> String? {
        var data: CFData?
        guard SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let d = data as Data? else { return nil }
        return String(bytes: d.prefix { $0 != 0 }, encoding: .utf8)
    }

    /// The keychain records trusted applications by their real path, while
    /// Bundle.main.executablePath may be a symlink (e.g. Xcode's usr/bin/xctest
    /// → Agents/xctest). Compare both sides fully resolved. This is a path
    /// identity, stricter than the keychain's own code-signature trust: a copy
    /// of che-keychain at another path is treated as foreign (documented).
    private static func realpath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    private static func selfPath() throws -> String {
        // Never fall back to argv[0]: it is caller-controlled and would enter
        // the ownership decision.
        guard let exe = Bundle.main.executablePath else {
            throw KeychainError.osStatus(errSecInternalError, operation: "set (locate own executable)")
        }
        return realpath(exe)
    }

    /// Builds a SecAccess whose application lists trust *all* applications,
    /// the programmatic equivalent of `security add-generic-password -A`.
    /// The application-list check permits other readers; partition-ID authorization
    /// and keychain lock state may still deny access or require a prompt.
    /// Uses the legacy SecAccess/SecACL API (deprecated but functional on the
    /// macOS file keychain, where generic-password items live).
    private static func allowAllAccess(label: String) throws -> SecAccess {
        var access: SecAccess?
        let createStatus = SecAccessCreate(label as CFString, nil, &access)
        guard createStatus == errSecSuccess, let acc = access else {
            throw KeychainError.osStatus(createStatus, operation: "SecAccessCreate")
        }
        var aclList: CFArray?
        let listStatus = SecAccessCopyACLList(acc, &aclList)
        guard listStatus == errSecSuccess, let acls = aclList as? [SecACL] else {
            throw KeychainError.osStatus(listStatus, operation: "SecAccessCopyACLList")
        }
        for acl in acls {
            // nil trusted-application list = any application may use the item
            // at the application-list layer ("Allow all applications" in Keychain Access).
            let setStatus = SecACLSetContents(acl, nil, label as CFString,
                                              SecKeychainPromptSelector(rawValue: 0))
            guard setStatus == errSecSuccess else {
                throw KeychainError.osStatus(setStatus, operation: "SecACLSetContents")
            }
        }
        return acc
    }
}
