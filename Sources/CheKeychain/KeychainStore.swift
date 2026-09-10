// Sources/CheKeychain/KeychainStore.swift
import Foundation
import Security

enum KeychainError: Error, LocalizedError {
    case osStatus(OSStatus, operation: String)
    case notFound
    /// The item's decrypt ACL trusts some application other than this binary
    /// (`owners` lists every trusted application found), or no decrypt entry at
    /// all could be attributed (`owners` empty). che-keychain never silently
    /// replaces such an item — SecItemUpdate would "succeed" while leaving the
    /// secret under another program's ACL (round 1 of #5) — so it refuses and
    /// names the explicit remedy.
    case foreignOwned(service: String, account: String, owners: [String], selfPath: String)
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
    case replaceFailed(service: String, account: String, addStatus: OSStatus, restored: Bool)

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
              If nothing else needs it — this permanently deletes the stored secret — remove it explicitly, then retry:
                che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
              (`unset` removes every match it can, an iCloud-synchronized twin included; `security delete-generic-password \
            -s \(shellQuote(svc)) -a \(shellQuote(acct))` removes one local match per call.)
              If it was created by another copy of che-keychain (different install path), use that copy instead. \
            If you added another application via "Always Allow", the same `unset` then `set` re-creates it trusted to this binary only.
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
              Remove it explicitly first (this deletes the stored secret), then retry with the mode you want:
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
        case .replaceFailed(let svc, let acct, let st, let restored):
            let text = (SecCopyErrorMessageString(st, nil) as String?) ?? ""
            return """
            replacing \(svc)/\(acct) failed: the old item was deleted but adding the new one failed \
            (OSStatus \(st)\(text.isEmpty ? "" : ": \(text)")).
              \(restored ? "The previous value was re-stored as a prompt-on-read item trusted to this binary; other item attributes (label, dates) were not preserved." : "The previous item could NOT be restored — \(svc)/\(acct) is now absent (unless something else re-created it meanwhile). Re-run `set` to store it again.")
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
        /// Some decrypt entry is "allow all applications" (alone or mixed with
        /// application lists) — the shape `--daemon` writes, but also
        /// `security add-generic-password -A`. No owner identity exists for
        /// such items (labels are forgeable).
        case allowAll
        /// Not a file-keychain item; ACL not inspectable, not deletable by us.
        case unsupported
    }

    /// Public view of `inspect` without the item reference.
    static func inspectExisting(service: String, account: String) throws -> Existing {
        try inspect(service: service, account: account).existing
    }

    /// Refuse-before-typing check: throws exactly the refusal `save` would throw
    /// (foreign / unattributable / ambiguous), without writing anything.
    /// `set` and `set-pair` run it for every account before the dialog, so a
    /// refusal is never raised after a secret was typed or partially stored.
    static func preflight(service: String, accounts: [String]) throws {
        for account in accounts {
            try refusal(for: try inspect(service: service, account: account).existing, service: service, account: account)
        }
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
    static func save(service: String, account: String, value: String, daemon: Bool = false) throws {
        let found = try inspect(service: service, account: account)
        try refusal(for: found.existing, service: service, account: account)
        switch found.existing {
        case .none:
            try add(service: service, account: account, value: value, daemon: daemon)
        case .own:
            try replaceOwnItem(found.item!, service: service, account: account, value: value, daemon: daemon)
        case .foreign, .allowAll, .unsupported:
            preconditionFailure("refusal(for:) must have thrown")
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
        guard ast == errSecSuccess else {
            let restored = old.map { addRaw(service: service, account: account, data: $0, access: nil, keychain: keychain) == errSecSuccess } ?? false
            throw KeychainError.replaceFailed(service: service, account: account, addStatus: ast, restored: restored)
        }
    }

    private static func add(service: String, account: String, value: String, daemon: Bool) throws {
        // Daemon-readable: any process may read without a keychain prompt.
        // Use ONLY for low-sensitivity creds a headless launchd agent reads.
        // Fail loudly if the access can't be built — never silently store a
        // prompt-on-read item, which would hang the very daemon this serves.
        let access = daemon ? try allowAllAccess(label: daemonLabel(service: service, account: account)) : nil
        let st = addRaw(service: service, account: account, data: Data(value.utf8), access: access)
        guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "set (add)") }
    }

    private static func addRaw(service: String, account: String, data: Data, access: SecAccess?, keychain: SecKeychain? = nil) -> OSStatus {
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

    private struct Found { let existing: Existing; let item: SecKeychainItem? }

    private static func inspect(service: String, account: String) throws -> Found {
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
        return Found(existing: try classify(item: item, service: service, account: account), item: item)
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
    private static func classify(item: SecKeychainItem, service: String, account: String) throws -> Existing {
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
        // Every authorization through which the secret can leave the keychain.
        let revealing: Set<String> = [kSecACLAuthorizationDecrypt, kSecACLAuthorizationAny,
                                      kSecACLAuthorizationExportClear, kSecACLAuthorizationExportWrapped].map { $0 as String }.reduce(into: []) { $0.insert($1) }
        var acls: [SecACL] = []
        for acl in allAcls {
            guard let auths = SecACLCopyAuthorizations(acl) as? [String] else {
                throw KeychainError.osStatus(errSecDecode, operation: "set (decode ACL authorizations)")
            }
            if auths.contains(where: revealing.contains) { acls.append(acl) }
        }
        var apps: [String] = []      // raw paths, compared unsanitized
        var sawAllowAll = false
        for acl in acls {
            var appList: CFArray?; var desc: CFString?; var sel = SecKeychainPromptSelector(rawValue: 0)
            let cst = SecACLCopyContents(acl, &appList, &desc, &sel)
            guard cst == errSecSuccess else { throw KeychainError.osStatus(cst, operation: "set (read ACL entry)") }
            guard let appsArray = appList else { sawAllowAll = true; continue }   // nil application list = any application
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
            return .foreign(owners: owners)
        }
        if sawAllowAll { return .allowAll }
        if apps.isEmpty { return .foreign(owners: []) }
        return .own
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

    /// Builds a SecAccess whose every ACL trusts *all* applications (no prompt),
    /// the programmatic equivalent of `security add-generic-password -A`. Lets a
    /// headless launchd daemon read the item without a SecurityAgent dialog.
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
            // without being prompted ("Allow all applications" in Keychain Access).
            let setStatus = SecACLSetContents(acl, nil, label as CFString,
                                              SecKeychainPromptSelector(rawValue: 0))
            guard setStatus == errSecSuccess else {
                throw KeychainError.osStatus(setStatus, operation: "SecACLSetContents")
            }
        }
        return acc
    }
}
