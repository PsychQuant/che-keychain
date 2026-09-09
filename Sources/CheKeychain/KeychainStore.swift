// Sources/CheKeychain/KeychainStore.swift
import Foundation
import Security

enum KeychainError: Error, LocalizedError {
    case osStatus(OSStatus, operation: String)
    case notFound

    var errorDescription: String? {
        switch self {
        case .osStatus(let status, let op):
            let text = (SecCopyErrorMessageString(status, nil) as String?) ?? ""
            var msg = "keychain \(op) failed (OSStatus \(status)\(text.isEmpty ? "" : ": \(text)"))"
            switch status {
            case errSecInvalidOwnerEdit:   // -25244
                msg += "\n  The existing item was created by another program, so its ACL cannot be changed here."
                msg += "\n  Remove it first: che-keychain unset (if this tool owns it) or `security delete-generic-password`."
            case errSecDuplicateItem:      // -25299
                msg += "\n  An item with this service/account already exists and could not be overwritten."
            default: break
            }
            return msg
        case .notFound: return "keychain item not found"
        }
    }
}

/// Thin wrapper over SecItem* for generic-password items stored in the
/// default keychain (login.keychain-db on macOS). Mirrors the surface
/// che-transport-mcp's Auth.swift uses so other che-* projects can adopt
/// the same shape.
enum KeychainStore {
    /// Upsert: overwrite the value if the item exists, create it otherwise.
    ///
    /// Why not delete-then-add (#5): an item created by ANOTHER binary (the
    /// `security` CLI, an older build of this tool, …) has a different keychain
    /// owner, and SecItemDelete on it returns errSecInvalidOwnerEdit (-25244).
    /// The old code discarded that status and then hit errSecDuplicateItem
    /// (-25299) on SecItemAdd, with no path to ever overwrite. SecItemUpdate is
    /// permitted on foreign-owned items (it changes the value, not the owner),
    /// which is exactly the "overwrite" the caller asked for.
    static func save(service: String, account: String, value: String, daemon: Bool = false) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        var attrs: [String: Any] = [kSecValueData as String: Data(value.utf8)]
        if daemon {
            // Daemon-readable: any process may read without a keychain prompt.
            // Use ONLY for low-sensitivity creds a headless launchd agent reads.
            // Fail loudly if the access can't be built — never silently store a
            // prompt-on-read item, which would hang the very daemon this serves.
            attrs[kSecAttrAccess as String] = try allowAllAccess(label: "\(service)/\(account)")
        }

        let update = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        switch update {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var add = query
            add.merge(attrs) { _, new in new }
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw KeychainError.osStatus(status, operation: "add")
            }
        default:
            // Never swallow: -25244 here means the item exists but is owned by
            // another program and we tried to change its ACL (daemon mode).
            throw KeychainError.osStatus(update, operation: "update")
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
