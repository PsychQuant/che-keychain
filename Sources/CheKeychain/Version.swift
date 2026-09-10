// Sources/CheKeychain/Version.swift
import Foundation

enum AppVersion {
    static let version = "0.2.0"
    static let versionString = "che-keychain \(version)"
    static let helpMessage = """
    \(versionString)
      A trust-isolated credential prompt for macOS keychain — the dialog runs in
      this signed binary, NOT in whatever caller invoked it. The caller (LLM,
      script, MCP) never sees the user's input; it only learns success / failure.

    USAGE
      che-keychain set       --service S --account A [--label L] [--explain E] [--secure] [--daemon]
      che-keychain set-pair  --service S --visible-account I --secure-account S \\
                             [--visible-label LI] [--secure-label LS] [--title T] [--explain E]
      che-keychain has       --service S --account A
      che-keychain unset     --service S [--account A]
      che-keychain --version
      che-keychain --help

    DETAILS
      `set` / `set-pair` overwrite an existing item that THIS binary created:
      same ACL mode → the value is updated in place; switching between normal and
      --daemon → the item is deleted and re-added with the new ACL. An item created
      by another program (e.g. the `security` CLI, or another copy of che-keychain
      at a different path) is REFUSED before the dialog opens, with the exact
      `che-keychain unset` command to run first: che-keychain never silently
      replaces an item it did not create (an in-place update would leave the new
      secret under that program's ACL and only look like success). Ownership is
      judged by this binary's real path in the item's decrypt ACL (allow-all
      items: by the ACL label service/account). `unset` deletes by reference and
      therefore also removes items created by other programs.

      `set` / `set-pair` pop a native NSAlert. The dialog shows the destination
      (service + account) so the user can verify a malicious caller isn't
      redirecting writes. Secure fields use NSSecureTextField (masked).
      Storage: login.keychain-db (local, NOT iCloud-synced).

      `--daemon` stores the item with an "allow all applications" ACL so a
      headless launchd agent can read it without a keychain-access prompt. The
      value is still typed into THIS signed dialog (caller never sees it) — only
      the storage ACL is relaxed. Use ONLY for low-sensitivity creds.

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

      # Daemon-readable secret (launchd agent reads it without a prompt)
      che-keychain set --service bus-eta-logger --account tdx_secret --secure --daemon
    """
}
