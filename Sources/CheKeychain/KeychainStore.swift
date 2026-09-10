// Sources/CheKeychain/KeychainStore.swift
import Foundation
import Security

enum KeychainError: Error, LocalizedError {
    case osStatus(OSStatus, operation: String)
    case notFound
    /// The item exists but was not created by this binary: its decrypt ACL does
    /// not trust us (or its ACL could not be attributed to us). che-keychain
    /// never silently replaces such an item — SecItemUpdate would "succeed" while
    /// leaving the secret under another program's ACL (round 1 of #5) — so it
    /// refuses and names the explicit remedy. `owners` is empty when no
    /// trusted-application list could be read.
    case foreignOwned(service: String, account: String, owners: [String], selfPath: String)
    /// More than one item matches service/account (e.g. one per keychain in the
    /// search list). We refuse to guess which one the caller means.
    case ambiguous(service: String, account: String, count: Int)
    /// The item's decrypt ACL is only "allow all applications": it carries no
    /// owner identity and any label in it can be forged, so it cannot be
    /// attributed to this binary. Plain `set` refuses (replacing it would be a
    /// destructive act on a possibly-foreign item); `set --daemon` may update
    /// the value in place (the item is world-readable by construction).
    case unattributable(service: String, account: String)
    /// `unset` deleted `deleted` item(s) but could not delete `refused`
    /// (account → why). Reported after the sweep so the user sees exactly what
    /// remains; the remedy is the `security` CLI, not `unset` again.
    case undeletable(service: String, deleted: Int, refused: [(account: String, reason: String)])
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
            default: break
            }
            return msg
        case .notFound: return "keychain item not found"
        case .foreignOwned(let svc, let acct, let owners, let me):
            let evidence = owners.isEmpty
                ? "no trusted-application list could be read from its decrypt ACL, so it cannot be attributed to this binary"
                : "its decrypt ACL trusts \(owners.joined(separator: ", ")) — not this binary (\(me))"
            return """
            keychain item \(svc)/\(acct) already exists and was not created by this che-keychain binary:
              \(evidence).
              Nothing was written to \(svc)/\(acct). che-keychain never silently replaces an item it did not \
            create: an in-place update would leave the new secret under that program's ACL and only look like success.
              If that program no longer needs it — this permanently deletes the secret it stored — remove it explicitly, then retry:
                che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
              (equivalent: security delete-generic-password -s \(shellQuote(svc)) -a \(shellQuote(acct)))
              If it was created by another copy of che-keychain (different install path), use that copy instead.
            """
        case .ambiguous(let svc, let acct, let n):
            return """
            \(n) keychain items match \(svc)/\(acct) (e.g. one per keychain in the search list). \
            Refusing to guess which one to write.
              Inspect them with:  security find-generic-password -s \(shellQuote(svc)) -a \(shellQuote(acct))
              To remove ALL of them:  che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
              To remove one at a time (each call deletes the first match):  security delete-generic-password -s \(shellQuote(svc)) -a \(shellQuote(acct))
            """
        case .unattributable(let svc, let acct):
            return """
            keychain item \(svc)/\(acct) already exists with an "allow all applications" ACL, which carries no \
            owner identity — che-keychain cannot tell whether it created it.
              Nothing was written to \(svc)/\(acct). Replacing an item that may belong to another program is destructive, \
            so it is never a side effect of `set`.
              If you want a prompt-on-read item here, remove it explicitly first (this deletes the stored secret), then retry:
                che-keychain unset --service \(shellQuote(svc)) --account \(shellQuote(acct))
              If you meant to update a daemon-readable item, pass --daemon (updates the value in place).
            """
        case .undeletable(let svc, let deleted, let refused):
            let list = refused.map { "    \($0.account): \($0.reason)" }.joined(separator: "\n")
            return """
            unset --service \(svc): removed \(deleted) item(s); \(refused.count) could not be removed by che-keychain:
            \(list)
              Remove those with the security CLI (each call deletes the first match):
                security delete-generic-password -s \(shellQuote(svc)) -a <account>
            """
        case .replaceFailed(let svc, let acct, let st, let restored):
            let text = (SecCopyErrorMessageString(st, nil) as String?) ?? ""
            return """
            switching the ACL mode of \(svc)/\(acct) failed: the old item was deleted but re-adding it failed \
            (OSStatus \(st)\(text.isEmpty ? "" : ": \(text)")).
              \(restored ? "The previous item was restored with its previous value and mode; nothing changed." : "The previous item could NOT be restored — \(svc)/\(acct) is now absent. Re-run `set` to store it again.")
            """
        }
    }
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
        /// Not created (solely) by this binary: the decrypt ACL trusts some
        /// application other than this binary's real path. `owners` lists every
        /// trusted application found. Also used, with empty `owners`, for a
        /// match that is not a file-keychain item (no readable ACL).
        case foreign(owners: [String])
        /// The decrypt ACL trusts this binary's real path and nothing else.
        case own
        /// The decrypt ACL has only "allow all applications" entries — the
        /// shape `--daemon` writes, but also `security add-generic-password -A`.
        /// No owner identity exists for such items (labels are forgeable).
        case allowAll
    }

    /// Public view of `inspect` without the item reference.
    static func inspectExisting(service: String, account: String) throws -> Existing {
        try inspect(service: service, account: account).existing
    }

    /// Refuse-before-typing check: throws exactly the refusal `save` would throw
    /// (foreign / unattributable / ambiguous), without writing anything.
    /// `set` and `set-pair` run it for every account before the dialog, so a
    /// refusal is never raised after a secret was typed or partially stored.
    static func preflight(service: String, accounts: [String], daemon: Bool) throws {
        for account in accounts {
            try refusal(for: try inspect(service: service, account: account).existing,
                        service: service, account: account, daemon: daemon)
        }
    }

    /// The single place that decides which existing items `save` refuses.
    private static func refusal(for existing: Existing, service: String, account: String, daemon: Bool) throws {
        switch existing {
        case .foreign(let owners):
            throw KeychainError.foreignOwned(service: service, account: account, owners: owners, selfPath: selfPath())
        case .allowAll where !daemon:
            throw KeychainError.unattributable(service: service, account: account)
        case .none, .own, .allowAll:
            return
        }
    }

    /// Write a value. Policy (decided in #5 after verify round 1, refined by
    /// verify rounds 2–3):
    ///
    ///   existing item                         set                   set --daemon
    ///   absent                                Add                   Add + allow-all ACL
    ///   foreign (ACL trusts another app)      refuse + remedy       refuse + remedy
    ///   own, prompt-on-read                   value-only update     delete + Add (switch)
    ///   allow-all only (no owner identity)    refuse + remedy       value-only update
    ///
    /// Why refuse foreign items instead of updating them (user decision on #5):
    /// SecItemUpdate DOES succeed on an item another program created, but that
    /// leaves the new secret inside an item that program manages — and with
    /// --daemon it silently appended an allow-all ACL entry to that item
    /// (round 1). Replacing it is a destructive act on someone else's secret,
    /// so it must be an explicit `unset` by the user, never a side effect of
    /// `set`. Such items are prompt-on-read for other programs, not
    /// unreadable; the constraint is ownership.
    ///
    /// Why allow-all items are never claimed as ours: an allow-all ACL entry has
    /// no application list, and its description can be forged with one
    /// `security add-generic-password -A -l` call (verify round 3). Updating
    /// the value of such an item under --daemon exposes nothing new (it is
    /// world-readable by construction); deleting it under plain `set` might
    /// destroy another program's secret, so that is refused.
    ///
    /// API facts (probed 2026-09-10): SecItemDelete — by query or by
    /// kSecMatchItemList — answers errSecInvalidOwnerEdit (-25244) on an item
    /// another program created (this is where the original -25299 came from);
    /// SecKeychainItemDelete(ref) deletes it. `unset` uses the latter.
    ///
    /// Why delete+add for a mode switch on our own item: SecItemUpdate with
    /// kSecAttrAccess unions ACL entries (5→7→9…), it never replaces them. The
    /// old value is read first and the old item re-added if the Add fails.
    static func save(service: String, account: String, value: String, daemon: Bool = false) throws {
        let found = try inspect(service: service, account: account)
        try refusal(for: found.existing, service: service, account: account, daemon: daemon)
        switch found.existing {
        case .none:
            try add(service: service, account: account, value: value, daemon: daemon)
        case .own where !daemon, .allowAll:
            // Value-only update, bound to the very item we inspected. Never
            // touch kSecAttrAccess on an existing item (ACL union, see above).
            try updateValue(of: found.item!, value: value)
        case .own:
            try replaceOwnItem(found.item!, service: service, account: account, value: value, daemon: daemon)
        case .foreign:
            preconditionFailure("refusal(for:) must have thrown")
        }
    }

    private static func updateValue(of item: SecKeychainItem, value: String) throws {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecMatchItemList as String: [item]]
        let st = SecItemUpdate(q as CFDictionary, [kSecValueData as String: Data(value.utf8)] as CFDictionary)
        guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "set (update value)") }
    }

    /// Own prompt-on-read item → daemon-readable: delete by reference and re-add
    /// with the allow-all access. Everything that can fail before the delete is
    /// done first (read old value, build the SecAccess); if the Add still fails,
    /// the old item is re-added so the secret is not lost.
    private static func replaceOwnItem(_ item: SecKeychainItem, service: String, account: String, value: String, daemon: Bool) throws {
        var oldData: CFTypeRef?
        let rq: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecMatchItemList as String: [item], kSecReturnData as String: true]
        let rst = SecItemCopyMatching(rq as CFDictionary, &oldData)
        guard rst == errSecSuccess, let old = oldData as? Data else { throw KeychainError.osStatus(rst, operation: "set (read current value before replacing)") }
        let access = daemon ? try allowAllAccess(label: daemonLabel(service: service, account: account)) : nil
        let dst = SecKeychainItemDelete(item)
        guard dst == errSecSuccess else { throw KeychainError.osStatus(dst, operation: "set (delete own item to switch ACL mode)") }
        let ast = addRaw(service: service, account: account, data: Data(value.utf8), access: access)
        guard ast == errSecSuccess else {
            let restored = addRaw(service: service, account: account, data: old, access: nil) == errSecSuccess
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

    private static func addRaw(service: String, account: String, data: Data, access: SecAccess?) -> OSStatus {
        var add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]
        if let access = access { add[kSecAttrAccess as String] = access }
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

    /// Delete one account, or every account under a service. Each matching item
    /// is deleted by reference (SecKeychainItemDelete), which — unlike the
    /// query-based SecItemDelete the old loop used (it threw at the first
    /// -25244 and left the rest) — also removes items created by other
    /// programs, so `unset` is the remedy `set` names for them. Nothing is
    /// skipped in silence: a match that is not a file-keychain item, or a delete
    /// the keychain refuses, is reported after the sweep with the `security`
    /// remedy, together with how many items were removed.
    static func unset(service: String, account: String? = nil) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true
        ]
        if let account = account { query[kSecAttrAccount as String] = account }
        var out: CFTypeRef?
        let st = SecItemCopyMatching(query as CFDictionary, &out)
        if st == errSecItemNotFound { return }
        guard st == errSecSuccess, let rows = out as? [[String: Any]] else {
            throw KeychainError.osStatus(st, operation: "unset (list items)")
        }
        var deleted = 0
        var refused: [(account: String, reason: String)] = []
        for row in rows {
            let acct = row[kSecAttrAccount as String] as? String ?? account ?? "?"
            guard let ref = row[kSecValueRef as String], CFGetTypeID(ref as CFTypeRef) == SecKeychainItemGetTypeID() else {
                refused.append((acct, "not a file-keychain item (no item reference); che-keychain cannot delete it"))
                continue
            }
            let del = SecKeychainItemDelete(ref as! SecKeychainItem)
            switch del {
            case errSecSuccess: deleted += 1
            default:
                let text = (SecCopyErrorMessageString(del, nil) as String?) ?? ""
                refused.append((acct, "OSStatus \(del)\(text.isEmpty ? "" : " (\(text))")"))
            }
        }
        if !refused.isEmpty {
            throw KeychainError.undeletable(service: service, deleted: deleted, refused: refused)
        }
    }

    // MARK: - Ownership inspection

    private struct Found { let existing: Existing; let item: SecKeychainItem? }

    private static func inspect(service: String, account: String) throws -> Found {
        var out: CFTypeRef?
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return Found(existing: .none, item: nil) }
        guard st == errSecSuccess, let refs = out as? [AnyObject] else {
            throw KeychainError.osStatus(st, operation: "set (look up existing item)")
        }
        if refs.isEmpty { return Found(existing: .none, item: nil) }
        guard refs.count == 1 else {
            throw KeychainError.ambiguous(service: service, account: account, count: refs.count)
        }
        guard CFGetTypeID(refs[0]) == SecKeychainItemGetTypeID() else {
            // Not a file-keychain item (e.g. data-protection keychain): we cannot
            // read its ACL, so we cannot claim it. Refuse rather than crash.
            return Found(existing: .foreign(owners: []), item: nil)
        }
        let item = refs[0] as! SecKeychainItem
        return Found(existing: try classify(item: item, service: service, account: account), item: item)
    }

    /// Decide ownership from the decrypt ACL, fail-closed:
    ///  1. every trusted application in every decrypt entry must be this binary
    ///     (real path); any other application → foreign (all of them reported).
    ///     Note `security -T a -T b` puts both apps in ONE entry, so "each list
    ///     contains us" would still pass — the rule is over applications.
    ///  2. no trusted-application list at all (only allow-all entries) → allowAll
    ///     (no owner identity; never claimed as ours)
    ///  3. an ACL entry that cannot be read or decoded → thrown OSStatus (the
    ///     caller refuses; nothing is written)
    private static func classify(item: SecKeychainItem, service: String, account: String) throws -> Existing {
        var access: SecAccess?
        let ast = SecKeychainItemCopyAccess(item, &access)
        guard ast == errSecSuccess, let acc = access else {
            throw KeychainError.osStatus(ast, operation: "set (read item ACL)")
        }
        let acls = (SecAccessCopyMatchingACLList(acc, kSecACLAuthorizationDecrypt) as? [SecACL]) ?? []
        var lists: [[String]] = []   // raw paths, compared unsanitized
        for acl in acls {
            var apps: CFArray?; var desc: CFString?; var sel = SecKeychainPromptSelector(rawValue: 0)
            let cst = SecACLCopyContents(acl, &apps, &desc, &sel)
            guard cst == errSecSuccess else { throw KeychainError.osStatus(cst, operation: "set (read decrypt ACL entry)") }
            guard let appsArray = apps else { continue }   // nil application list = any application
            guard let list = appsArray as? [SecTrustedApplication] else {
                throw KeychainError.osStatus(errSecDecode, operation: "set (decode trusted-application list)")
            }
            lists.append(list.compactMap(trustedApplicationPath))
        }
        if lists.isEmpty { return .allowAll }
        let me = selfPath()
        let apps = lists.flatMap { $0 }
        let onlyMe = !apps.isEmpty && apps.allSatisfy { realpath($0) == me }
        return onlyMe ? .own : .foreign(owners: apps.map(sanitize))
    }

    /// The ACL description we stamp on daemon items (display only — it is NOT
    /// an ownership fingerprint: any program can write the same string).
    private static func daemonLabel(service: String, account: String) -> String { "\(service)/\(account)" }

    /// SecTrustedApplicationCopyData returns the application's path as a
    /// NUL-terminated C string. Returned raw; sanitize only when displaying.
    private static func trustedApplicationPath(_ app: SecTrustedApplication) -> String? {
        var data: CFData?
        guard SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let d = data as Data? else { return nil }
        return String(decoding: d.prefix { $0 != 0 }, as: UTF8.self)
    }

    /// Strings read from the keychain are written by other programs: strip
    /// control characters before they reach a terminal, and cap the length.
    private static func sanitize(_ s: String) -> String {
        let cleaned = s.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7f }
        return String(String.UnicodeScalarView(cleaned).prefix(256))
    }

    /// The keychain records trusted applications by their real path, while
    /// Bundle.main.executablePath may be a symlink (e.g. Xcode's usr/bin/xctest
    /// → Agents/xctest). Compare both sides fully resolved. This is a path
    /// identity, stricter than the keychain's own code-signature trust: a copy
    /// of che-keychain at another path is treated as foreign (documented).
    private static func realpath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    private static func selfPath() -> String {
        realpath(Bundle.main.executablePath ?? CommandLine.arguments[0])
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
