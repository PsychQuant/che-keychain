// Sources/CheKeychain/Version.swift
import Foundation

enum AppVersion {
    static let version = "0.3.0"
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
      `set` / `set-pair` on an existing item: if its decrypt ACL trusts THIS
      binary and nothing else, the item is deleted by reference and re-created
      with the new value and the requested ACL (the old value is re-stored if
      that fails). Anything else is REFUSED before the dialog opens, with the
      exact `che-keychain unset` command to run first: an item whose ACL trusts
      any other application (the `security` CLI, another copy of che-keychain at
      a different path, an app you once clicked "Always Allow" for), or an item
      with an "allow all applications" entry — which carries no owner identity
      and is also what --daemon writes, so re-setting a daemon item is `unset`
      then `set --daemon`. che-keychain never overwrites an item whose ACL lets
      anything but this binary read it. "This binary alone" is a path identity,
      not provenance: an item another program pre-created for this binary only
      counts as ours and is replaced. Refusals are decided before the dialog;
      a write can still fail afterwards for other reasons (locked keychain…). `unset` deletes by reference, so it
      also removes items created by other programs, prints what it removed, and
      reports every item it could not remove.

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

      # Rotate a daemon-readable secret (0.3.0+: an existing allow-all item is
      # never overwritten in place — remove it explicitly first)
      che-keychain unset --service bus-eta-logger --account tdx_secret
      che-keychain set   --service bus-eta-logger --account tdx_secret --secure --daemon
    """
}
