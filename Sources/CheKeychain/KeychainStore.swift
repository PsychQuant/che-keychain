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

    var errorDescription: String? {
        switch self {
        case .osStatus(let status, let op):
            let text = (SecCopyErrorMessageString(status, nil) as String?) ?? ""
            var msg = "keychain \(op) failed (OSStatus \(status)\(text.isEmpty ? "" : ": \(text)"))"
            switch status {
            case errSecInvalidOwnerEdit:   // -25244
                msg += "\n  The item was created by another program, which SecItemDelete refuses to touch."
                msg += "\n  `che-keychain unset --service <service> --account <account>` deletes it by reference instead."
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
              Remove the stale one with:  security delete-generic-password -s \(shellQuote(svc)) -a \(shellQuote(acct))
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
        /// Not created by this binary: a trusted-application list exists that
        /// does not contain us, or an allow-all ACL that does not carry our
        /// fingerprint, or no readable ACL at all (`owners` empty).
        case foreign(owners: [String])
        /// Created by this binary. `daemonReadable` = the decrypt ACL also (or
        /// only) carries an allow-all entry — the shape `--daemon` writes.
        case own(daemonReadable: Bool)
    }

    /// Public view of `inspect` without the item reference.
    static func inspectExisting(service: String, account: String) throws -> Existing {
        try inspect(service: service, account: account).existing
    }

    /// Refuse-before-typing check: throws exactly what `save` would throw for a
    /// foreign or ambiguous item, without writing anything. `set-pair` runs it
    /// for both accounts before the dialog so a refusal can never follow a
    /// partial write (#5 verify R2).
    static func preflight(service: String, accounts: [String], daemon: Bool) throws {
        for account in accounts {
            if case .foreign(let owners) = try inspect(service: service, account: account).existing {
                throw KeychainError.foreignOwned(service: service, account: account, owners: owners, selfPath: selfPath())
            }
        }
    }

    /// Write a value. Policy (decided in #5 after verify round 1):
    ///
    ///   existing item                 set                     set --daemon
    ///   absent                        Add                     Add + allow-all ACL
    ///   foreign / unattributable      refuse + remedy         refuse + remedy
    ///   own, same mode                value-only update       value-only update
    ///   own, other mode               delete + Add (switch)   delete + Add (switch)
    ///
    /// Why refuse foreign items instead of updating them (user decision on #5
    /// after verify round 1): SecItemUpdate DOES succeed on an item another
    /// program created, but that leaves the new secret inside an item that
    /// program manages — and with --daemon it silently appended an allow-all
    /// ACL entry to that item (round 1). Replacing it is a destructive act on
    /// someone else's secret, so it must be an explicit `unset` by the user,
    /// not a side effect of `set`. Note: such items are prompt-on-read for
    /// other programs, not unreadable; the constraint is ownership.
    ///
    /// API facts (probed 2026-09-10): SecItemDelete — by query or by
    /// kSecMatchItemList — answers errSecInvalidOwnerEdit (-25244) on an item
    /// another program created (this is where the original -25299 came from);
    /// SecKeychainItemDelete(ref) deletes it. `unset` uses the latter.
    ///
    /// Why delete+add for a mode switch on our own item: SecItemUpdate with
    /// kSecAttrAccess unions ACL entries (5→7→9…), it never replaces them.
    /// Delete by reference and Add recreates the item with a clean ACL.
    static func save(service: String, account: String, value: String, daemon: Bool = false) throws {
        let found = try inspect(service: service, account: account)
        switch found.existing {
        case .foreign(let owners):
            throw KeychainError.foreignOwned(service: service, account: account, owners: owners, selfPath: selfPath())
        case .own(let daemonReadable) where daemonReadable == daemon:
            // Value-only update, bound to the very item we inspected. Never
            // touch kSecAttrAccess on an existing item (ACL union, see above).
            let q: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecMatchItemList as String: [found.item!]
            ]
            let st = SecItemUpdate(q as CFDictionary, [kSecValueData as String: Data(value.utf8)] as CFDictionary)
            guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "set (update value)") }
        case .own:
            let st = SecKeychainItemDelete(found.item!)
            guard st == errSecSuccess else {
                // We classified it as ours yet cannot delete it: report it as
                // foreign with the remedy rather than a bare status.
                if st == errSecInvalidOwnerEdit {
                    throw KeychainError.foreignOwned(service: service, account: account, owners: [], selfPath: selfPath())
                }
                throw KeychainError.osStatus(st, operation: "set (replace item to switch ACL mode)")
            }
            try add(service: service, account: account, value: value, daemon: daemon)
        case .none:
            try add(service: service, account: account, value: value, daemon: daemon)
        }
    }

    private static func add(service: String, account: String, value: String, daemon: Bool) throws {
        var add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(value.utf8)
        ]
        if daemon {
            // Daemon-readable: any process may read without a keychain prompt.
            // Use ONLY for low-sensitivity creds a headless launchd agent reads.
            // Fail loudly if the access can't be built — never silently store a
            // prompt-on-read item, which would hang the very daemon this serves.
            add[kSecAttrAccess as String] = try allowAllAccess(label: daemonLabel(service: service, account: account))
        }
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "set (add)") }
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
    /// query-based SecItemDelete the old loop used — also removes items created
    /// by other programs, so `unset` is the remedy `set` names for them. Should
    /// a delete still answer errSecInvalidOwnerEdit, the sweep continues and the
    /// first such item is reported afterwards instead of stopping silently.
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
        var firstForeign: (account: String, owners: [String])?
        for row in rows {
            guard let ref = row[kSecValueRef as String], CFGetTypeID(ref as CFTypeRef) == SecKeychainItemGetTypeID() else { continue }
            let item = ref as! SecKeychainItem
            let acct = row[kSecAttrAccount as String] as? String ?? account ?? "?"
            let del = SecKeychainItemDelete(item)
            switch del {
            case errSecSuccess: continue
            case errSecInvalidOwnerEdit:
                if firstForeign == nil {
                    let owners = (try? classify(item: item, service: service, account: acct)).flatMap { e -> [String]? in
                        if case .foreign(let o) = e { return o } else { return nil }
                    } ?? []
                    firstForeign = (acct, owners)
                }
            default: throw KeychainError.osStatus(del, operation: "unset (delete \(service)/\(acct))")
            }
        }
        if let f = firstForeign {
            throw KeychainError.foreignOwned(service: service, account: f.account, owners: f.owners, selfPath: selfPath())
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
    ///  1. any trusted-application list that does not contain this binary → foreign
    ///  2. a list containing this binary → own (daemonReadable if an allow-all entry coexists)
    ///  3. only allow-all entries → own only if one carries our label
    ///     "service/account" (what `--daemon` writes); otherwise foreign
    ///  4. no readable decrypt ACL → foreign with empty owners (unattributable)
    private static func classify(item: SecKeychainItem, service: String, account: String) throws -> Existing {
        var access: SecAccess?
        let ast = SecKeychainItemCopyAccess(item, &access)
        guard ast == errSecSuccess, let acc = access else {
            throw KeychainError.osStatus(ast, operation: "set (read item ACL)")
        }
        let acls = (SecAccessCopyMatchingACLList(acc, kSecACLAuthorizationDecrypt) as? [SecACL]) ?? []
        var lists: [[String]] = []
        var allowAllDescriptions: [String] = []
        for acl in acls {
            var apps: CFArray?; var desc: CFString?; var sel = SecKeychainPromptSelector(rawValue: 0)
            let cst = SecACLCopyContents(acl, &apps, &desc, &sel)
            guard cst == errSecSuccess else { throw KeychainError.osStatus(cst, operation: "set (read decrypt ACL entry)") }
            guard let appsArray = apps else {
                // nil application list = any application (allow-all).
                allowAllDescriptions.append(sanitize((desc as String?) ?? ""))
                continue
            }
            guard let list = appsArray as? [SecTrustedApplication] else {
                throw KeychainError.osStatus(errSecDecode, operation: "set (decode trusted-application list)")
            }
            lists.append(list.compactMap(trustedApplicationPath))
        }
        let me = selfPath()
        if !lists.isEmpty {
            let trustsMe = lists.contains { $0.contains { realpath($0) == me } }
            guard trustsMe else { return .foreign(owners: lists.flatMap { $0 }) }
            return .own(daemonReadable: !allowAllDescriptions.isEmpty)
        }
        if allowAllDescriptions.contains(daemonLabel(service: service, account: account)) {
            return .own(daemonReadable: true)
        }
        return .foreign(owners: allowAllDescriptions.map { "any application (allow-all ACL, description \"\($0)\")" })
    }

    /// The ACL description we stamp on daemon items; doubles as the ownership
    /// fingerprint for allow-all entries, which carry no application list.
    private static func daemonLabel(service: String, account: String) -> String { "\(service)/\(account)" }

    /// SecTrustedApplicationCopyData returns the application's path as a
    /// NUL-terminated C string. Anything else is rendered unreadable on purpose.
    private static func trustedApplicationPath(_ app: SecTrustedApplication) -> String? {
        var data: CFData?
        guard SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let d = data as Data? else { return nil }
        let bytes = d.prefix { $0 != 0 }
        return sanitize(String(decoding: bytes, as: UTF8.self))
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
