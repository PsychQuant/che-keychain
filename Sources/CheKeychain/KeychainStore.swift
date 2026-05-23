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
    static func save(service: String, account: String, value: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        // Always delete-then-add so a re-run cleanly overwrites stale ACLs / labels.
        SecItemDelete(query as CFDictionary)

        var add = query
        add[kSecValueData as String] = Data(value.utf8)
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
}
