// Sources/CheKeychain/KeychainStore.swift
import Foundation
import Security

enum KeychainError: Error, LocalizedError {
    case osStatus(OSStatus, operation: String)
    case notFound

    var errorDescription: String? {
        switch self {
        case .osStatus(let status, let op): return "keychain \(op) failed (OSStatus \(status))"
        case .notFound: return "keychain item not found"
        }
    }
}

/// Thin wrapper over SecItem* for generic-password items stored in the
/// default keychain (login.keychain-db on macOS). Mirrors the surface
/// che-transport-mcp's Auth.swift uses so other che-* projects can adopt
/// the same shape.
enum KeychainStore {
    static func save(service: String, account: String, value: String, daemon: Bool = false) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        // Always delete-then-add so a re-run cleanly overwrites stale ACLs / labels.
        SecItemDelete(query as CFDictionary)

        var add = query
        add[kSecValueData as String] = Data(value.utf8)
        if daemon, let access = allowAllAccess(label: "\(service)/\(account)") {
            // Daemon-readable: any process may read without a keychain prompt.
            // Use ONLY for low-sensitivity creds a headless launchd agent reads.
            add[kSecAttrAccess as String] = access
        }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status, operation: "add")
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
    private static func allowAllAccess(label: String) -> SecAccess? {
        var access: SecAccess?
        guard SecAccessCreate(label as CFString, nil, &access) == errSecSuccess,
              let acc = access else { return nil }
        var aclList: CFArray?
        guard SecAccessCopyACLList(acc, &aclList) == errSecSuccess,
              let acls = aclList as? [SecACL] else { return acc }
        for acl in acls {
            // nil trusted-application list = any application may use the item
            // without being prompted ("Allow all applications" in Keychain Access).
            SecACLSetContents(acl, nil, label as CFString, SecKeychainPromptSelector(rawValue: 0))
        }
        return acc
    }
}
