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
