// Sources/CheKeychain/Version.swift
import Foundation

enum AppVersion {
    static let version = "0.3.0"
    static let versionString = "che-keychain \(version)"
    static let helpMessage = """
    \(versionString)
      A trust-isolated credential prompt for macOS keychain — the dialog runs in
      this signed binary, NOT in whatever caller invoked it. With the dialog the
      caller (LLM, script, MCP) never sees the user's input; it only learns
      success / failure. --from-clipboard reads the pasteboard (which any process
      can read) behind a confirmation dialog; --stdin takes the value from the
      caller itself. See "Value sources" below.

    USAGE
      che-keychain set       --service S --account A [--label L] [--explain E] [--secure] [--daemon]
                             [--from-clipboard | --stdin]
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

      Value sources for `set` (0.3.0+): the dialog (default); `--from-clipboard`
      reads the clipboard's text, then shows a confirmation dialog with the
      destination and a fingerprint of the value (no input field — the paste
      problem lived there; Return cancels, Store needs a click or ⌘S); nothing is
      stored if the clipboard changed while the dialog was open. Once the value
      is stored and verified the clipboard is emptied (every type on it) if it
      still holds what was read — a clipboard manager or Universal Clipboard may
      keep a copy; on failure it is left as is. `--stdin` reads exactly one line
      from a pipe and stops at the line break without waiting for EOF; it shows
      NO dialog (the caller already holds the value — use it only from
      automation you trust) and prints the destination on stderr; with --daemon
      it refuses to replace an existing prompt-on-read item (no dialog may
      widen an ACL). Refused, never guessed: a terminal, invalid UTF-8, more
      than 64 KiB, no complete line within 30 s, a second line of content that
      arrived within 100 ms of the first, and — for both sources — a line break
      inside the value or leading/trailing whitespace (only LF/CR at the ends
      are removed; leading blank lines on stdin are skipped). --secure/--label/
      --explain are refused with both. Dialog values are stored as typed; an
      empty or whitespace-only value is refused everywhere, set-pair included.
      Every store is read back and compared: an empty or different value is
      removed again (a rotation gets its previous value re-stored and read
      back, or the report says exactly what state the slot is in) → exit 1; an
      unreadable or ambiguous read leaves the item in place and says whether it
      replaced a previous value → exit 3 ("written, unverified").

      `set` (dialog and --from-clipboard) / `set-pair` pop a native NSAlert;
      `--stdin` does not. The dialog shows the destination
      (service + account) so the user can verify a malicious caller isn't
      redirecting writes. Secure fields use NSSecureTextField (masked).
      Storage: login.keychain-db (local, NOT iCloud-synced).

      `--daemon` stores the item with an "allow all applications" ACL so a
      headless launchd agent can read it without a keychain-access prompt. The
      value comes from the chosen source (the dialog, the clipboard behind a
      confirmation, or — with --stdin — the caller itself); only the storage ACL
      is relaxed. Use ONLY for low-sensitivity creds.

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

      # Paste-free: copy the token, then run this and confirm the dialog (stored
      # prompt-on-read; add --daemon only for a headless launchd reader — any
      # process could then read it)
      che-keychain set --service ntu-cool-canvas --account default --from-clipboard

      # Automation: pipe exactly one line (never a terminal). Note `pbpaste` leaves
      # the token on the clipboard — prefer --from-clipboard, or clear it after.
      pbpaste | che-keychain set --service ntu-cool-canvas --account default --stdin

      # Rotate a daemon-readable secret (0.3.0+: an existing allow-all item is
      # never overwritten in place — remove it explicitly first)
      che-keychain unset --service bus-eta-logger --account tdx_secret
      che-keychain set   --service bus-eta-logger --account tdx_secret --secure --daemon
    """
}
