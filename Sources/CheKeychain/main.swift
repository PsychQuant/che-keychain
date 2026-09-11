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
func storeOrDie(service: String, account: String, value: String, daemon: Bool = false, mayWidenExistingACL: Bool = true, note: String = "") {
    do {
        try KeychainStore.save(service: service, account: account, value: value, daemon: daemon, mayWidenExistingACL: mayWidenExistingACL)
    } catch let e as KeychainError {
        if case .storedValueMismatch(_, _, _, let cleanup) = e {
            die((e.errorDescription ?? "\(e)") + note, exitCode: cleanup.exitCode)
        }
        die((e.errorDescription ?? "\(e)") + note)
    } catch {
        die(((error as? LocalizedError)?.errorDescription ?? error.localizedDescription) + note)
    }
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
        die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
    }
    // Take the value from the requested source (#6). The non-dialog sources
    // skip the "Storing to:" line the user would otherwise verify; the value
    // still never enters argv or stdout.
    let value: String
    var clipboardChangeCountAtRead: Int? = nil
    switch a.source {
    case .dialog:
        let title = a.label ?? "Enter credential"
        let field = PromptField(name: a.account, label: a.label ?? a.account, isSecure: a.secure)
        let result = PromptDialog.run(
            title: title,
            destination: "service=\(a.service) account=\(a.account)",
            explain: a.explain,
            fields: [field]
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
            die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        }
        // Identifiers are validated by the parser, but cap them here too so a
        // long name cannot push the warning and the fingerprint out of view.
        let destination = "service=\(sanitize(a.service)) account=\(sanitize(a.account))\(a.daemon ? "  ⚠ daemon-readable: any process can read it without a prompt" : "")"
        // Say whether Store overwrites: preflight passed, so the slot is either
        // empty or an item this binary alone can read (a probe error is said, not hidden).
        let overwrite: String
        if let existing = try? KeychainStore.inspectExisting(service: a.service, account: a.account) {
            switch existing {
            case .none: overwrite = "New item: nothing is stored at this destination yet."
            default:    overwrite = "⚠ An item ALREADY EXISTS at this destination: Store REPLACES its value (the old value is put back only if the store fails)."
            }
        } else {
            overwrite = "⚠ Could not determine whether an item already exists here; Store would replace one that does."
        }
        let explain = "\(overwrite)\nValue: \(InputSource.fingerprint(read)) (from the clipboard, line breaks at the ends removed).\nOnce stored and verified, the clipboard is emptied (every type on it) if it has not changed meanwhile. Return does nothing, Esc cancels; click Store or press ⌘S to confirm."
        guard PromptDialog.confirm(title: "Store the clipboard's contents?", destination: destination, explain: explain) else {
            emit("Cancelled.", to: true)
            exit(2)
        }
        guard InputSource.clipboardChangeCount() == before else {
            die("the clipboard changed while the dialog was open — nothing stored. Copy the value again and retry.")
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
    // On failure the clipboard is left alone so the user can retry.
    storeOrDie(service: a.service, account: a.account, value: value, daemon: a.daemon, mayWidenExistingACL: a.source != .stdin)
    // Only after the value is stored AND read back does the token leave the
    // clipboard — and only if the clipboard still holds what we read.
    var origin = a.source == .stdin ? " (from stdin)" : ""
    if a.source == .clipboard {
        origin = InputSource.clearClipboard(ifUnchangedSince: clipboardChangeCountAtRead)
            ? " (from clipboard; removed from this Mac's clipboard)"
            : " (from clipboard; clipboard changed meanwhile, left as is)"
    }
    // A --daemon store is the one implicit ACL widening left: say so.
    emit(a.daemon ? "✓ stored \(a.service)/\(a.account)\(origin) (daemon-readable: any process can read it without a prompt)"
                  : "✓ stored \(a.service)/\(a.account)\(origin)")

case .setPair(let a):
    // Both accounts are checked before the dialog so a *refusal* on the second
    // cannot follow a write of the first. A non-refusal failure on the second
    // write is still possible; it is reported together with what was written.
    do {
        try KeychainStore.preflight(service: a.service, accounts: [a.visibleAccount, a.secureAccount])
    } catch {
        die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
    }
    let visibleLabel = a.visibleLabel ?? a.visibleAccount
    let secureLabel  = a.secureLabel  ?? a.secureAccount
    let title = a.title ?? "Enter credentials for \(a.service)"
    let fields = [
        PromptField(name: a.visibleAccount, label: visibleLabel, isSecure: false),
        PromptField(name: a.secureAccount,  label: secureLabel,  isSecure: true)
    ]
    let result = PromptDialog.run(
        title: title,
        destination: "service=\(a.service)  accounts={\(a.visibleAccount), \(a.secureAccount)}",
        explain: a.explain,
        fields: fields
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
        storeOrDie(service: a.service, account: a.visibleAccount, value: v)
        storeOrDie(service: a.service, account: a.secureAccount, value: s,
                   note: "\n  Note: \(a.service)/\(a.visibleAccount) WAS stored before this failure; the pair is now inconsistent until you re-run set-pair.")
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
        die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
    }
    if removed.isEmpty {
        emit("nothing to remove under \(sanitize(service))\(account.map { "/\(sanitize($0))" } ?? "")")
    } else {
        // Removed items may have been created by other programs (that is what
        // `set`'s refusal sends the user here for), so say exactly what went.
        emit("✓ removed \(removed.count) account(s) under \(sanitize(service)): \(removed.map(sanitize).joined(separator: ", "))")
    }
}
