import Foundation

/// Preserve the first account's evidence when the second store exits early.
func pairFirstStoreNote(service: String, account: String, firstError: KeychainError?) -> String {
    let destination = "\(sanitize(service))/\(sanitize(account))"
    if let firstError {
        return "\n  Note: the write to \(destination) was accepted but the value there could not be verified before this failure.\n"
            + (firstError.errorDescription ?? "The first account's state is unverified.")
    }
    return "\n  Note: \(destination) WAS stored and verified before this failure."
}

/// What `set --replace` reports it replaced: the class observed immediately
/// before the delete. An allow-all entry is listed first so the cap cannot hide
/// it, and a truncated list says so.
func replacementEvidence(_ previous: KeychainStore.Existing) -> String {
    switch previous {
    case .own: return "an item trusted only to this executable"
    case .allowAll(let scope):
        return "an allow-all item (owner not attributable; \(scope == .plaintext ? "plaintext open to every application" : "wrapped export only"))"
    case .foreign(let owners, let allowAll):
        let listed = (allowAll.map { [KeychainStore.allowAllOwnerLabel($0)] } ?? []) + owners
        return "a foreign item trusting: " + (listed.isEmpty ? "unattributed applications"
            : listed.prefix(8).joined(separator: ", ") + (listed.count > 8 ? ", … and \(listed.count - 8) more" : ""))
    case .none, .unsupported: return "the selected item"
    }
}
