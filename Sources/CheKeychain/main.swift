// Sources/CheKeychain/main.swift
import Foundation

let argv = CommandLine.arguments

func emit(_ message: String, to stderr: Bool = false) {
    let data = Data((message + "\n").utf8)
    (stderr ? FileHandle.standardError : FileHandle.standardOutput).write(data)
}

func die(_ message: String, exitCode: Int32 = 1) -> Never {
    emit("✗ \(message)", to: true)
    exit(exitCode)
}

/// One store path for `set` and `set-pair`: the exit code follows the cleanup
/// outcome (1 = the new value is not in the slot; 3 = in the slot, unverified;
/// 4 = a bad item is stuck — see MismatchCleanup.exitCode). `note` is appended
/// to any failure (set-pair says what was already written).
/// Exit 3 ("stored, unverified") is NOT fatal here: the value IS in the slot,
/// so the caller may go on (set-pair stores its second half) and report 3 at
/// the end. Returns that error; dies for everything else.
@discardableResult
func storeOrDie(service: String, account: String, value: String, daemon: Bool = false, mayWidenExistingACL: Bool = true, expectingExisting: Bool? = nil, note: String = "") -> KeychainError? {
    do {
        try KeychainStore.save(service: service, account: account, value: value, daemon: daemon, mayWidenExistingACL: mayWidenExistingACL, expectingExisting: expectingExisting)
        return nil
    } catch let e as KeychainError where e.exitCode == 3 {
        return e
    } catch {
        dieWith(error, note: note)
    }
}

/// Every error path shares this so a KeychainError always reports its own exit code.
func dieWith(_ error: Error, note: String = "") -> Never {
    if let e = error as? KeychainError { die((e.errorDescription ?? "\(e)") + note, exitCode: e.exitCode) }
    die(((error as? LocalizedError)?.errorDescription ?? error.localizedDescription) + note)
}

guard argv.count >= 2 else {
    emit(AppVersion.helpMessage)
    exit(1)
}

switch argv[1] {
case "--version", "-v":
    emit(AppVersion.versionString)
    exit(0)
case "--help", "-h":
    emit(AppVersion.helpMessage)
    exit(0)
default:
    break
}

let subcommand = argv[1]
let rest = Array(argv.dropFirst(2))

let cmd: Command
do {
    cmd = try CommandParser.parse(subcommand, rest)
} catch let CommandError.unknownOption(opt) {
    die("unknown subcommand or option: \(opt)\n\nRun `che-keychain --help` for usage.")
} catch {
    die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
}

switch cmd {
case .set(let a):
    // Refuse before the user types anything: a foreign/ambiguous item cannot be
    // written to, so the dialog would only collect a secret to throw away.
    do {
        try KeychainStore.preflight(service: a.service, accounts: [a.account])
    } catch {
        dieWith(error)
    }
    // Take the value from the requested source (#6). The non-dialog sources
    // skip the "Storing to:" line the user would otherwise verify; the value
    // still never enters argv or stdout.
    let value: String
    var clipboardChangeCountAtRead: Int? = nil
    var existsAtDialog: Bool? = nil   // dialog / clipboard: what the dialog claimed; checked again at write time
    switch a.source {
    case .dialog:
        let title = a.label ?? "Enter credential"
        let field = PromptField(name: a.account, label: a.label ?? a.account, isSecure: a.secure)
        // Consent must be for what actually happens: say on the protected first
        // line whether Store replaces an existing secret and/or makes it
        // daemon-readable. The probe fails closed (preflight just passed).
        let existing: KeychainStore.Existing
        do { existing = try KeychainStore.inspectExisting(service: a.service, account: a.account) } catch { dieWith(error) }
        let replaces: Bool
        if case .none = existing { replaces = false } else { replaces = true }
        existsAtDialog = replaces
        let result = PromptDialog.run(
            title: title,
            destination: "service=\(sanitize(a.service)) account=\(sanitize(a.account))",
            explain: a.explain,
            fields: [field],
            warning: PromptDialog.warningText(daemon: a.daemon, replaces: replaces)
        )
        switch result {
        case .cancel:
            emit("Cancelled.", to: true)
            exit(2)
        case .accept(let values):
            // Stored as typed (0.2.x behaviour); only an empty / whitespace-only
            // field is refused.
            guard let v = InputSource.typedValue(values[a.account] ?? "") else {
                die("empty input — nothing stored.", exitCode: 1)
            }
            value = v
        }
    case .clipboard:
        // Read first, then confirm: the dialog shows the destination AND a
        // fingerprint of what will be stored; the clipboard must not change
        // between the read and the click, or nothing is stored.
        let before = InputSource.clipboardChangeCount()
        let read: String
        do {
            read = try InputSource.readClipboard()
        } catch {
            // Before any consent, one undifferentiated reason: the caller sees
            // stderr and the exit code, and must not learn the clipboard's shape.
            die("the clipboard does not hold exactly one clean line of text (it is empty, padded with whitespace, multi-line, or contains control characters) — copy exactly the value and retry. The clipboard was left as is.")
        }
        // Identifiers are validated by the parser, but cap them here too so a
        // long name cannot push the warning and the fingerprint out of view.
        let destination = "service=\(sanitize(a.service)) account=\(sanitize(a.account))"
        // Say whether Store overwrites: preflight just passed, so the slot is
        // either empty or an item this binary alone can read; a probe that fails
        // now is anomalous and fails CLOSED (no dialog whose claims could be wrong).
        let overwrite: String
        let existing: KeychainStore.Existing
        do { existing = try KeychainStore.inspectExisting(service: a.service, account: a.account) } catch { dieWith(error) }
        switch existing {
        case .none:
            overwrite = "New item: nothing is stored at this destination yet."
            existsAtDialog = false
        case .own:
            overwrite = "An item ALREADY EXISTS at this destination: Store REPLACES its value (the old value is put back only if the store fails)."
                + (a.daemon ? " It is prompt-on-read today; Store CHANGES it to daemon-readable." : "")
            existsAtDialog = true
        default:
            // Unreachable after a passed preflight unless the slot changed meanwhile;
            // say what save() will do (refuse), not what it would do for an own item.
            overwrite = "An item exists at this destination that che-keychain will NOT replace (its ACL is not this binary's alone); Store will be refused."
            existsAtDialog = true
        }
        let warning = PromptDialog.warningText(daemon: a.daemon, replaces: existsAtDialog == true)
        let explain = "\(overwrite)\nValue: \(InputSource.fingerprint(read)) (from the clipboard, line breaks at the ends removed).\nOnce stored and verified, the clipboard is emptied (every type on it) if it has not changed meanwhile. Return does nothing, Esc cancels; click Store or press ⌘S to confirm."
        guard PromptDialog.confirm(title: "Store the clipboard's contents?", destination: destination, explain: explain, warning: warning) else {
            emit("Cancelled. The clipboard was left as is.", to: true)
            exit(2)
        }
        guard InputSource.clipboardChangeCount() == before else {
            die("the clipboard changed while the dialog was open — nothing stored. Copy the value again and retry. The clipboard was left as is.")
        }
        value = read
        clipboardChangeCountAtRead = before
    case .stdin:
        // No dialog: the caller already holds the value, so there is nothing to
        // redirect that it does not already have. What it must NOT be able to do
        // silently is widen an existing item's ACL to allow-all — refused inside
        // save() (mayWidenExistingACL: false), at write time, on the same
        // inspection that decides the replace.
        emit("→ will store to service=\(sanitize(a.service)) account=\(sanitize(a.account)) (from stdin\(a.daemon ? ", daemon-readable" : ""))", to: true)
        do {
            value = try InputSource.readStdin()
        } catch {
            die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        }
    }
    // On failure the clipboard is left alone so the user can retry — and the
    // message says so, since the success line is where the clearing is reported.
    if let unverified = storeOrDie(service: a.service, account: a.account, value: value, daemon: a.daemon,
                                   mayWidenExistingACL: a.source != .stdin, expectingExisting: existsAtDialog,
                                   note: a.source == .clipboard ? "\n  The clipboard was left as is." : "") {
        dieWith(unverified, note: a.source == .clipboard ? "\n  The clipboard was left as is." : "")
    }
    // Only after the value is stored AND read back does the token leave the
    // clipboard — and only if the clipboard still holds what we read.
    var origin = a.source == .stdin ? " (from stdin)" : ""
    if a.source == .clipboard {
        origin = InputSource.clearClipboard(ifUnchangedSince: clipboardChangeCountAtRead)
            ? " (from clipboard; removed from this Mac's clipboard)"
            : " (from clipboard; clipboard changed meanwhile, left as is)"
    }
    // A --daemon store is the one implicit ACL widening left: say so.
    emit(a.daemon ? "✓ stored \(a.service)/\(a.account)\(origin) (allow-all application ACL; other keychain authorization may be required)"
                  : "✓ stored \(a.service)/\(a.account)\(origin)")

case .setPair(let a):
    // Both accounts are checked before the dialog so a *refusal* on the second
    // cannot follow a write of the first. A non-refusal failure on the second
    // write is still possible; it is reported together with what was written.
    do {
        try KeychainStore.preflight(service: a.service, accounts: [a.visibleAccount, a.secureAccount])
    } catch {
        dieWith(error)
    }
    let visibleLabel = a.visibleLabel ?? a.visibleAccount
    let secureLabel  = a.secureLabel  ?? a.secureAccount
    let title = a.title ?? "Enter credentials for \(a.service)"
    let fields = [
        PromptField(name: a.visibleAccount, label: visibleLabel, isSecure: false),
        PromptField(name: a.secureAccount,  label: secureLabel,  isSecure: true)
    ]
    let pairReplaces = (try? KeychainStore.inspectExisting(service: a.service, account: a.visibleAccount)).map { if case .none = $0 { return false } else { return true } } ?? true
        || (try? KeychainStore.inspectExisting(service: a.service, account: a.secureAccount)).map { if case .none = $0 { return false } else { return true } } ?? true
    let result = PromptDialog.run(
        title: title,
        destination: "service=\(sanitize(a.service))  accounts={\(sanitize(a.visibleAccount)), \(sanitize(a.secureAccount))}",
        explain: a.explain,
        fields: fields,
        warning: PromptDialog.warningText(daemon: false, replaces: pairReplaces)
    )
    switch result {
    case .cancel:
        emit("Cancelled.", to: true)
        exit(2)
    case .accept(let values):
        guard let v = InputSource.typedValue(values[a.visibleAccount] ?? "") else {
            die("\(a.visibleAccount) is empty — nothing stored.", exitCode: 1)
        }
        guard let s = InputSource.typedValue(values[a.secureAccount] ?? "") else {
            die("\(a.secureAccount) is empty — nothing stored.", exitCode: 1)
        }
        // A "stored, unverified" first half (exit 3) is in the slot, so the second
        // half is still stored; both outcomes are reported at the end with exit 3.
        let first = storeOrDie(service: a.service, account: a.visibleAccount, value: v,
                               note: "\n  Note: \(sanitize(a.service))/\(sanitize(a.secureAccount)) was NOT stored (set-pair stops at a failure that leaves nothing usable); the pair is incomplete until you re-run set-pair.")
        let second = storeOrDie(service: a.service, account: a.secureAccount, value: s,
                                note: "\n  Note: \(sanitize(a.service))/\(sanitize(a.visibleAccount)) \(first == nil ? "WAS stored and verified" : "was stored but could not be verified") before this failure; the pair is inconsistent until you re-run set-pair.")
        if first != nil || second != nil {
            let parts = [first, second].compactMap { $0?.errorDescription }
            die(parts.joined(separator: "\n") + "\n  Both halves of the pair are in place; the one(s) above could not be verified.", exitCode: 3)
        }
        emit("✓ stored \(a.service)/{\(a.visibleAccount), \(a.secureAccount)}")
    }

case .has(let service, let account):
    if KeychainStore.has(service: service, account: account) {
        exit(0)
    } else {
        exit(1)
    }

case .unset(let service, let account):
    let removed: [String]
    do {
        removed = try KeychainStore.unset(service: service, account: account)
    } catch {
        dieWith(error)
    }
    if removed.isEmpty {
        emit("nothing to remove under \(sanitize(service))\(account.map { "/\(sanitize($0))" } ?? "")")
    } else {
        // Removed items may have been created by other programs (that is what
        // `set`'s refusal sends the user here for), so say exactly what went.
        emit("✓ removed \(removed.count) account(s) under \(sanitize(service)): \(removed.map(sanitize).joined(separator: ", "))")
    }
}
