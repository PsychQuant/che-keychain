// Sources/CheKeychain/Version.swift
import Foundation

enum AppVersion {
    static let version = "0.1.0"
    static let versionString = "che-keychain \(version)"
    static let helpMessage = """
    \(versionString)
      A trust-isolated credential prompt for macOS keychain — the dialog runs in
      this signed binary, NOT in whatever caller invoked it. The caller (LLM,
      script, MCP) never sees the user's input; it only learns success / failure.

    USAGE
      che-keychain set       --service S --account A [--label L] [--explain E] [--secure]
      che-keychain set-pair  --service S --visible-account I --secure-account S \\
                             [--visible-label LI] [--secure-label LS] [--title T] [--explain E]
      che-keychain has       --service S --account A
      che-keychain unset     --service S [--account A]
      che-keychain --version
      che-keychain --help

    DETAILS
      `set` / `set-pair` pop a native NSAlert. The dialog shows the destination
      (service + account) so the user can verify a malicious caller isn't
      redirecting writes. Secure fields use NSSecureTextField (masked).
      Storage: login.keychain-db (local, NOT iCloud-synced).

      `has`  exits 0 if the entry exists, 1 if it does not.
      `unset` removes an account (or all accounts under a service if --account
      omitted).

    EXAMPLES
      # Single secret
      che-keychain set --service my-api --account token --secure \\
        --label "Enter your API token" --explain "Used for production deploys"

      # ID + secret pair in one dialog
      che-keychain set-pair --service che-transport-tdx \\
        --visible-account client_id --secure-account client_secret \\
        --title "che-transport-mcp setup"
    """
}
