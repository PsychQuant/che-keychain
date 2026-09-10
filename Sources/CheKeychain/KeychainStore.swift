// Sources/CheKeychain/KeychainStore.swift
import Foundation
import Security

enum KeychainError: Error, LocalizedError {
    case osStatus(OSStatus, operation: String)
    case notFound
    /// The item exists but its decrypt ACL does not trust this binary — another
    /// program created it. We cannot delete it (errSecInvalidOwnerEdit) and we
    /// refuse to update it: a value written there would still be unreadable by
    /// this tool's consumers, and `--daemon` would silently widen the ACL of an
    /// item we do not own (#5 verify, finding #1/#2).
    case foreignOwned(service: String, account: String, owners: [String])
    /// The item exists and is ours, but its ACL does not match the requested
    /// mode. SecItemUpdate unions ACL entries instead of replacing them, so
    /// "fixing" the ACL in place is impossible; the only clean path is unset+set.
    case aclMismatch(service: String, account: String, existingDaemonReadable: Bool, requestedDaemon: Bool)

    var errorDescription: String? {
        switch self {
        case .osStatus(let status, let op):
            let text = (SecCopyErrorMessageString(status, nil) as String?) ?? ""
            var msg = "keychain \(op) failed (OSStatus \(status)\(text.isEmpty ? "" : ": \(text)"))"
            switch status {
            case errSecInvalidOwnerEdit:   // -25244
                msg += "\n  The item is owned by another program; only that program (or the user) may delete it."
                msg += "\n  Remove it with: security delete-generic-password -s <service> -a <account>"
            case errSecDuplicateItem:      // -25299
                msg += "\n  An item with this service/account already exists and could not be overwritten."
            default: break
            }
            return msg
        case .notFound: return "keychain item not found"
        case .foreignOwned(let svc, let acct, let owners):
            return """
            keychain item \(svc)/\(acct) already exists and is owned by another program \
            (trusted: \(owners.isEmpty ? "unknown" : owners.joined(separator: ", "))).
              Nothing was written. che-keychain cannot overwrite or delete it, and a value written \
            there would stay unreadable to anything but that program.
              Remove it first, then retry:
                security delete-generic-password -s \(svc) -a \(acct)
            """
        case .aclMismatch(let svc, let acct, let existing, let requested):
            let have = existing ? "daemon-readable (any process, no prompt)" : "prompt-on-read"
            let want = requested ? "--daemon" : "normal (prompt-on-read)"
            return """
            keychain item \(svc)/\(acct) already exists as \(have), but this call asked for \(want).
              Nothing was written. The ACL of an existing item cannot be changed in place \
            (SecItemUpdate appends ACL entries, it never replaces them).
              Remove it first, then retry:
                che-keychain unset --service \(svc) --account \(acct)
            """
        }
    }
}

/// Thin wrapper over SecItem* for generic-password items stored in the
/// default keychain (login.keychain-db on macOS). Mirrors the surface
/// che-transport-mcp's Auth.swift uses so other che-* projects can adopt
/// the same shape.
enum KeychainStore {
    /// What already lives at service/account, as seen through its decrypt ACL.
    enum Existing: Equatable {
        case none
        /// Trusted-app list does not contain this binary (and is not allow-all).
        case foreign(owners: [String])
        /// This binary is trusted (default prompt-on-read ACL) or the list is
        /// allow-all (daemon item). `daemonReadable` distinguishes the two.
        case own(daemonReadable: Bool)
    }

    /// Inspect the decrypt ACL of an existing item. Ownership is decided by
    /// whether this executable's path is in the trusted-application list; an
    /// empty (nil) list means "any application" — the shape `--daemon` writes.
    static func inspectExisting(service: String, account: String) throws -> Existing {
        var ref: CFTypeRef?
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnRef as String: true
        ]
        let st = SecItemCopyMatching(q as CFDictionary, &ref)
        if st == errSecItemNotFound { return .none }
        guard st == errSecSuccess, let item = ref else { throw KeychainError.osStatus(st, operation: "inspect") }
        var access: SecAccess?
        let ast = SecKeychainItemCopyAccess(item as! SecKeychainItem, &access)
        guard ast == errSecSuccess, let acc = access else { throw KeychainError.osStatus(ast, operation: "SecKeychainItemCopyAccess") }
        let acls = (SecAccessCopyMatchingACLList(acc, kSecACLAuthorizationDecrypt) as? [SecACL]) ?? []
        var owners: [String] = []
        var allowAll = false
        for acl in acls {
            var apps: CFArray?; var desc: CFString?; var sel = SecKeychainPromptSelector(rawValue: 0)
            guard SecACLCopyContents(acl, &apps, &desc, &sel) == errSecSuccess else { continue }
            guard let list = apps as? [SecTrustedApplication] else { allowAll = true; continue }
            for app in list {
                var data: CFData?
                if SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let d = data as Data? {
                    // The data is a C string: strip the trailing NUL before comparing paths.
                    let path = String(decoding: d.prefix { $0 != 0 }, as: UTF8.self)
                    owners.append(path.trimmingCharacters(in: .whitespacesAndNewlines))
                }
            }
        }
        if allowAll { return .own(daemonReadable: true) }
        let me = selfPath()
        return owners.contains { realpath($0) == me } ? .own(daemonReadable: false) : .foreign(owners: owners)
    }

    /// The keychain records trusted applications by their real path, while
    /// Bundle.main.executablePath may be a symlink (e.g. Xcode's usr/bin/xctest
    /// → Agents/xctest). Compare both sides fully resolved.
    private static func realpath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    private static func selfPath() -> String {
        realpath(Bundle.main.executablePath ?? CommandLine.arguments[0])
    }

    /// Write a value. New items are created; existing items are only updated
    /// when they are ours AND their ACL already matches the requested mode.
    ///
    /// Why not delete-then-add (#5): an item created by another binary has a
    /// different owner, and SecItemDelete on it returns errSecInvalidOwnerEdit
    /// (-25244); the old code discarded that and then hit errSecDuplicateItem.
    /// Why not blind upsert (#5 verify): SecItemUpdate DOES succeed on foreign
    /// items, but the decrypt ACL keeps trusting only the original program, so
    /// the "stored" value is unreadable to our consumers — and with `--daemon`
    /// it silently appends an allow-all ACL to an item we don't own. Refusing
    /// with the exact remedy is the only honest outcome.
    static func save(service: String, account: String, value: String, daemon: Bool = false) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        switch try inspectExisting(service: service, account: account) {
        case .foreign(let owners):
            throw KeychainError.foreignOwned(service: service, account: account, owners: owners)
        case .own(let daemonReadable):
            guard daemonReadable == daemon else {
                throw KeychainError.aclMismatch(service: service, account: account,
                                                existingDaemonReadable: daemonReadable, requestedDaemon: daemon)
            }
            // Value-only update. Never touch kSecAttrAccess on an existing item:
            // SecItemUpdate unions ACL entries (5→7→9→…), it does not replace them.
            let st = SecItemUpdate(query as CFDictionary, [kSecValueData as String: Data(value.utf8)] as CFDictionary)
            guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "update") }
        case .none:
            var add = query
            add[kSecValueData as String] = Data(value.utf8)
            if daemon {
                // Daemon-readable: any process may read without a keychain prompt.
                // Use ONLY for low-sensitivity creds a headless launchd agent reads.
                // Fail loudly if the access can't be built — never silently store a
                // prompt-on-read item, which would hang the very daemon this serves.
                add[kSecAttrAccess as String] = try allowAllAccess(label: "\(service)/\(account)")
            }
            let st = SecItemAdd(add as CFDictionary, nil)
            guard st == errSecSuccess else { throw KeychainError.osStatus(st, operation: "add") }
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

    static func unset(service: String, account: String? = nil) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        if let account = account {
            query[kSecAttrAccount as String] = account
        }
        // SecItemDelete on macOS removes one matching item per call even when
        // the query matches multiple (service-wide deletes). Loop until the
        // store reports nothing left to delete.
        var status: OSStatus
        repeat {
            status = SecItemDelete(query as CFDictionary)
        } while status == errSecSuccess
        guard status == errSecItemNotFound else {
            throw KeychainError.osStatus(status, operation: "delete")
        }
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
