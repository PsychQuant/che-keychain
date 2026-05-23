// Sources/CheKeychain/Commands.swift
import Foundation

enum CommandError: Error, LocalizedError {
    case missingArgument(String)
    case unknownOption(String)
    case invalidValue(field: String, reason: String)

    var errorDescription: String? {
        switch self {
        case .missingArgument(let arg): return "missing required argument: \(arg)"
        case .unknownOption(let opt):   return "unknown option: \(opt)"
        case .invalidValue(let f, let r): return "invalid value for \(f): \(r)"
        }
    }
}

/// Pure parser for `che-keychain` subcommand arguments. Returns a typed
/// command representation that the runner consumes. Kept separate from main
/// + the AppKit-dependent PromptDialog so it can be exhaustively unit-tested.
enum Command {
    case set(SetArgs)
    case setPair(SetPairArgs)
    case has(service: String, account: String)
    case unset(service: String, account: String?)
}

struct SetArgs: Equatable {
    var service: String
    var account: String
    var label: String?
    var explain: String?
    var secure: Bool
}

struct SetPairArgs: Equatable {
    var service: String
    var visibleAccount: String
    var secureAccount: String
    var visibleLabel: String?
    var secureLabel: String?
    var title: String?
    var explain: String?
}

enum CommandParser {
    /// Parses an argv slice (excluding the program name and subcommand name).
    static func parse(_ subcommand: String, _ args: [String]) throws -> Command {
        switch subcommand {
        case "set":       return .set(try parseSet(args))
        case "set-pair":  return .setPair(try parseSetPair(args))
        case "has":       return try parseHas(args)
        case "unset":     return try parseUnset(args)
        default:
            throw CommandError.unknownOption(subcommand)
        }
    }

    // MARK: - set

    static func parseSet(_ args: [String]) throws -> SetArgs {
        var service: String?
        var account: String?
        var label: String?
        var explain: String?
        var secure = false

        var i = 0
        while i < args.count {
            switch args[i] {
            case "--service": service = try valueAfter(&i, args)
            case "--account": account = try valueAfter(&i, args)
            case "--label":   label   = try valueAfter(&i, args)
            case "--explain": explain = try valueAfter(&i, args)
            case "--secure":  secure  = true; i += 1
            default: throw CommandError.unknownOption(args[i])
            }
        }
        guard let s = service else { throw CommandError.missingArgument("--service") }
        guard let a = account else { throw CommandError.missingArgument("--account") }
        try validateIdentifier(s, field: "service")
        try validateIdentifier(a, field: "account")
        return SetArgs(service: s, account: a, label: label, explain: explain, secure: secure)
    }

    // MARK: - set-pair

    static func parseSetPair(_ args: [String]) throws -> SetPairArgs {
        var service: String?
        var visibleAccount: String?
        var secureAccount: String?
        var visibleLabel: String?
        var secureLabel: String?
        var title: String?
        var explain: String?

        var i = 0
        while i < args.count {
            switch args[i] {
            case "--service":         service = try valueAfter(&i, args)
            case "--visible-account": visibleAccount = try valueAfter(&i, args)
            case "--secure-account":  secureAccount  = try valueAfter(&i, args)
            case "--visible-label":   visibleLabel   = try valueAfter(&i, args)
            case "--secure-label":    secureLabel    = try valueAfter(&i, args)
            case "--title":           title = try valueAfter(&i, args)
            case "--explain":         explain = try valueAfter(&i, args)
            default: throw CommandError.unknownOption(args[i])
            }
        }
        guard let s = service else { throw CommandError.missingArgument("--service") }
        guard let v = visibleAccount else { throw CommandError.missingArgument("--visible-account") }
        guard let sa = secureAccount else { throw CommandError.missingArgument("--secure-account") }
        try validateIdentifier(s, field: "service")
        try validateIdentifier(v, field: "visible-account")
        try validateIdentifier(sa, field: "secure-account")
        if v == sa {
            throw CommandError.invalidValue(field: "secure-account", reason: "must differ from visible-account")
        }
        return SetPairArgs(service: s,
                           visibleAccount: v, secureAccount: sa,
                           visibleLabel: visibleLabel, secureLabel: secureLabel,
                           title: title, explain: explain)
    }

    // MARK: - has

    static func parseHas(_ args: [String]) throws -> Command {
        var service: String?
        var account: String?

        var i = 0
        while i < args.count {
            switch args[i] {
            case "--service": service = try valueAfter(&i, args)
            case "--account": account = try valueAfter(&i, args)
            default: throw CommandError.unknownOption(args[i])
            }
        }
        guard let s = service else { throw CommandError.missingArgument("--service") }
        guard let a = account else { throw CommandError.missingArgument("--account") }
        return .has(service: s, account: a)
    }

    // MARK: - unset

    static func parseUnset(_ args: [String]) throws -> Command {
        var service: String?
        var account: String?

        var i = 0
        while i < args.count {
            switch args[i] {
            case "--service": service = try valueAfter(&i, args)
            case "--account": account = try valueAfter(&i, args)
            default: throw CommandError.unknownOption(args[i])
            }
        }
        guard let s = service else { throw CommandError.missingArgument("--service") }
        return .unset(service: s, account: account)
    }

    // MARK: - Helpers

    /// Reads args[i+1] then advances i by 2.
    private static func valueAfter(_ i: inout Int, _ args: [String]) throws -> String {
        guard i + 1 < args.count else {
            throw CommandError.missingArgument(args[i])
        }
        let value = args[i + 1]
        i += 2
        return value
    }

    /// service / account identifiers go into URL-like keychain query keys; keep
    /// them sanity-checked to catch obvious mistakes (empty string, control chars).
    static func validateIdentifier(_ s: String, field: String) throws {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw CommandError.invalidValue(field: field, reason: "must not be empty")
        }
        if trimmed.contains(where: { $0.isNewline || $0.unicodeScalars.contains(where: { $0.value < 0x20 }) }) {
            throw CommandError.invalidValue(field: field, reason: "contains control characters")
        }
    }
}
