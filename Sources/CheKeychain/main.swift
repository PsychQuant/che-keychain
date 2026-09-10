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
        guard let value = values[a.account], !value.isEmpty else {
            die("empty input — nothing stored.", exitCode: 1)
        }
        do {
            try KeychainStore.save(service: a.service, account: a.account, value: value, daemon: a.daemon)
        } catch {
            die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        }
        // A --daemon store is the one implicit ACL widening left: say so.
        emit(a.daemon ? "✓ stored \(a.service)/\(a.account) (daemon-readable: any process can read it without a prompt)"
                      : "✓ stored \(a.service)/\(a.account)")
    }

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
        guard let v = values[a.visibleAccount], !v.isEmpty else {
            die("\(a.visibleAccount) is empty — nothing stored.", exitCode: 1)
        }
        guard let s = values[a.secureAccount], !s.isEmpty else {
            die("\(a.secureAccount) is empty — nothing stored.", exitCode: 1)
        }
        do {
            try KeychainStore.save(service: a.service, account: a.visibleAccount, value: v)
        } catch {
            die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        }
        do {
            try KeychainStore.save(service: a.service, account: a.secureAccount,  value: s)
        } catch {
            let msg = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            die(msg + "\n  Note: \(a.service)/\(a.visibleAccount) WAS stored before this failure; the pair is now inconsistent until you re-run set-pair.")
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
        die((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
    }
    if removed.isEmpty {
        emit("nothing to remove under \(service)\(account.map { "/\($0)" } ?? "")")
    } else {
        // Removed items may have been created by other programs (that is what
        // `set`'s refusal sends the user here for), so say exactly what went.
        emit("✓ removed \(removed.count) account(s) under \(service): \(removed.map(sanitize).joined(separator: ", "))")
    }
}
