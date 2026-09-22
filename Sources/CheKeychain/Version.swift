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
      che-keychain set       --service S --account A [--label L] [--explain E] [--secure] [--daemon] [--replace]
      che-keychain set       --service S --account A [--daemon] [--replace] (--from-clipboard | --stdin)
      che-keychain set-pair  --service S --visible-account I --secure-account S \\
                             [--visible-label LI] [--secure-label LS] [--title T] [--explain E]
      che-keychain has       --service S --account A [--non-empty]
      che-keychain unset     --service S [--account A]
      che-keychain --version
      che-keychain --help

    DETAILS
      Dialog labels: `set --label` sets the dialog title and input field's
      label. For `set-pair`, --visible-label and --secure-label label the
      two input fields; --title sets the dialog title. These options do not
      set the stored item's label in Keychain Access.

      `set-pair` is dialog-only. It does not accept --stdin,
      --from-clipboard or --daemon. Automation should invoke `set --stdin`
      separately for each account and check each exit code. These two writes
      are not atomic: the first may be stored even if the second fails.
      Each write still uses read-back verification and the exit codes below.

      Plain `set` / `set-pair` on an existing item: if its decrypt ACL trusts THIS
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

      `set --replace` deliberately replaces an eligible foreign or allow-all
      item. It requires a noninteractive backup of the old bytes and access
      settings. A temporary nonsecret probe must confirm that the original
      policy can be recreated and be removed before the original is deleted.
      Unreadable or unreproducible backups are refused. Failed replacement
      attempts to restore and verify the old bytes and policy; the report
      distinguishes restored, unverified and failed recovery. This is not
      atomic and does not preserve label/comment/date metadata. No value is
      printed. --replace --stdin --daemon still cannot widen an existing
      non-allow-all ACL; it can rotate an existing allow-all item. set-pair
      does not accept --replace. Ambiguous/unsupported matches stay refused.

      Moving this executable to a different physical path makes its old
      items foreign to the new copy; a symlink resolves to the same path.
      Keep using the original copy, or explicitly use the new copy with
      --replace after establishing noninteractive read access. Failed backup
      or policy reproduction leaves the original untouched. A matching
      filename or signing team alone does not authorize replacement.

      Value sources for `set` (0.3.0+): the dialog (default); `--from-clipboard`
      reads the clipboard's text, then shows a confirmation dialog with the
      destination and a fingerprint of the value — its byte length and 8 hex
      digits of its SHA-256: enough to notice a wrong clipboard; useless
      against a long random token, but for a low-entropy secret (PIN, short
      passphrase) an observer of the screen could confirm a guess offline (no
      input field — the paste problem lived there; Return does nothing, Esc cancels, Store needs a click
      or ⌘S; it says whether an item already exists at the destination); nothing is
      stored if the clipboard changed while the dialog was open. Once the value
      is stored and verified the clipboard is emptied (every type on it) if it
      still holds what was read — a clipboard manager or Universal Clipboard may
      keep a copy; on failure it is left as is. `--stdin` reads exactly one line
      from a pipe and stops at the line break without waiting for EOF; it shows
      NO dialog (the caller already holds the value — use it only from
      automation you trust) and prints the destination on stderr; with --daemon
      it refuses, at write time, to replace an existing prompt-on-read item:
      no existing secret's ACL is widened without a dialog. A new allow-all
      item can still be created — including after an `unset`, which is also
      dialog-free; that destroys the old secret rather than exposing it.
      Refused, never guessed: a terminal, invalid UTF-8, more than 64 KiB, no
      complete line within 30 s of starting to read, a second line of content
      that arrived within 100 ms of the first, and — for both sources — a line
      break inside the value (any Unicode line separator), control or format
      characters, or leading/trailing whitespace (only LF/CR at the ends are
      removed; leading blank lines on stdin are skipped) — the same rule
      --service/--account have. --secure/--label/--explain are refused with
      both. Dialog values are stored as typed; an empty or whitespace-only
      value is refused everywhere, set-pair included.
      Every store (set, all sources, and set-pair) is read back and compared,
      and the exit code reports the observed outcome:
        1  an error: the new value is not proven to be at the destination, and
           nothing was removed. The report says which of these the destination is
           in: unchanged; holding a value that read back empty or different and
           was LEFT IN PLACE (a name lookup cannot show it is this write's, so it
           is not deleted); empty; holding the restored previous value (only after
           a failed add, and only into an empty destination); or unknown. Inspect
           the destination before deleting anything.
        3  the write was accepted but could not be verified (keychain locked, or
           the match was ambiguous); cleanup leaves the destination alone.
           Inspect ambiguous matches in Keychain Access; unlocking is not a remedy
           for multiple matches. The report says whether a previous item was deleted.
        4  a restore was accepted whose bytes or access settings do not match
           the backup: the destination holds an item that is not the one that
           was backed up. Inspect it in Keychain Access before retrying; do not
           remove it on this report alone.

      `set` (dialog and --from-clipboard) / `set-pair` pop a native NSAlert;
      `--stdin` does not. The dialog's first line warns when Store replaces
      an existing secret and/or makes it daemon-readable; then it shows the
      destination (service + account) so the user can verify a malicious
      caller isn't redirecting writes. Secure fields use NSSecureTextField
      (masked).
      Caller-provided explanations are shown separately from the fixed
      destination and warnings; long caller text is shortened. set-pair names
      the accounts being replaced and rechecks each account's observed
      existence state before its write. This is not a two-account transaction.
      Storage: login.keychain-db (local, NOT iCloud-synced).

      `--daemon` sets an "allow all applications" ACL. This alone does not
      guarantee that a different executable or a headless launchd agent can
      read it: partition-ID authorization and a locked keychain may still
      prevent access. Test the actual consuming executable before relying on
      background access. The
      value comes from the chosen source (the dialog, the clipboard behind a
      confirmation, or — with --stdin — the caller itself); only the storage ACL
      is relaxed. Use ONLY for low-sensitivity creds.

      Exit codes (set, set-pair): 0 stored and verified · 1 any other error,
      including "the new value did not land" — the slot is unchanged, holds
      the restored previous value, is empty, or has an unknown state;
      the message says which · 2
      cancelled · 3 write accepted but unverified · 4 restore does not match the
      backup (above). For
      set-pair, 3 and 4 refer to the account named in the message; the Note
      line says what happened to the other one. plain `has`: 0 present, 1 absent.
      `unset`: 0, or 1 when some match could not be removed.

      Keychain errors from set, set-pair and unset (including write-verification
      and restore failures) may include a numeric OSStatus and a description
      supplied by macOS. The description can vary with the system language;
      search by the numeric OSStatus, not the localized wording. OSStatus
      values are separate from the CLI exit codes above. Scripts should use
      the CLI exit code for the command's outcome, not exact stderr text.
      Plain `has` reports only 0 or 1 and does not print these error descriptions.

      `has` exits 0 if the entry exists, 1 if it does not.
      `has --non-empty` checks a single own item without interaction or writes:
        0 nonzero bytes; 1 absent; 2 present but empty; 3 check unavailable.
      Foreign, allow-all (--daemon), ambiguous and unreadable items return 3.
      No value is printed. Whitespace bytes count as non-empty; this does not
      validate a token or prove that another executable can read it.
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

      # Allow-all application ACL (verify access with the actual reader)
      che-keychain set --service bus-eta-logger --account tdx_secret --secure --daemon

      # Paste-free: copy the token, then run this and confirm the dialog (stored
      # prompt-on-read; --daemon widens the application ACL but does not
      # bypass other keychain authorization)
      che-keychain set --service ntu-cool-canvas --account default --from-clipboard

      # Automation: pipe exactly one line (never a terminal). Note `pbpaste` leaves
      # the token on the clipboard — prefer --from-clipboard, or clear it after.
      pbpaste | che-keychain set --service ntu-cool-canvas --account default --stdin

      # Explicit daemon rotation (requires a readable, restorable backup)
      che-keychain set --service bus-eta-logger --account tdx_secret --replace --secure --daemon
    """
}
