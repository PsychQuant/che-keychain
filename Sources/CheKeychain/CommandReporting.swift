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
/// before the delete. An allow-all entry is stated after the application list,
/// outside the cap, so it is never cut off; a truncated list says so.
func replacementEvidence(_ previous: KeychainStore.Existing) -> String {
    switch previous {
    case .own: return "an item trusted only to this executable"
    case .allowAll(let scope):
        let what: String
        switch scope {
        case .plaintext:   what = "plaintext open to every application at the application-ACL layer"
        case .wrappedOnly: what = "wrapped export only"
        case .promptGated: what = "an allow-all entry with a prompt selector"
        }
        return "an allow-all item (owner not attributable; \(what))"
    case .foreign(let owners, let allowAll):
        // Same shape as the refusal: the allow-all entry is stated apart, not
        // counted among the applications (round-11 verify).
        let apps = owners.isEmpty ? "no application named"
            : owners.prefix(8).joined(separator: ", ") + (owners.count > 8 ? ", … and \(owners.count - 8) more" : "")
        return "a foreign item trusting: " + apps + (allowAll.map { "; plus an allow-all entry — " + KeychainStore.allowAllOwnerLabel($0) } ?? "")
    case .none, .unsupported: return "the selected item"
    }
}

/// The `--from-clipboard` confirmation for an item this binary alone can read.
/// It must promise no more recovery than `replaceOwnItem` gives, so it quotes
/// the one restore rule (round-10/11 verify).
func ownItemOverwriteNotice(daemon: Bool) -> String {
    "An item ALREADY EXISTS at this destination: Store DELETES it and adds the new value. "
        + AppVersion.restoreRule + " " + AppVersion.copyRule
        + " A new value that is added but reads back wrong is left in place and reported, and the old one is gone."
        + (daemon ? " It is prompt-on-read today; Store CHANGES it to daemon-readable." : "")
}
