// Sources/CheKeychain/InputSource.swift
import AppKit
import Foundation

/// Where `set` takes its value from (#6). `.dialog` is the trust-isolated
/// NSAlert; the other two skip the dialog — and with it the "Storing to:"
/// line the user verifies — for automation and for pastes the dialog cannot
/// take. The value still never enters argv or stdout.
enum InputSourceKind: Equatable {
    case dialog
    case clipboard
    case stdin
}

enum InputSourceError: Error, LocalizedError {
    case emptyClipboard
    case stdinIsTerminal
    case emptyStdin
    case stdinTooLong(limit: Int)
    case stdinMultiline
    case stdinNotUTF8

    var errorDescription: String? {
        switch self {
        case .emptyClipboard:
            return "the clipboard holds no text (or only whitespace) — copy the value first, then retry with --from-clipboard."
        case .stdinIsTerminal:
            return "--stdin needs a pipe, not a terminal (e.g. `pbpaste | che-keychain set … --stdin`); an interactive paste would be mangled by bracketed-paste control sequences."
        case .emptyStdin:
            return "nothing (or only whitespace) was read from stdin — nothing stored."
        case .stdinTooLong(let limit):
            return "the first line of stdin exceeds \(limit) bytes without a line break — refusing to store a truncated value."
        case .stdinMultiline:
            return "stdin carried more than one line of content — refusing to store only the first line. Pipe exactly one line (a multi-line secret is not supported)."
        case .stdinNotUTF8:
            return "stdin is not valid UTF-8 — refusing to store a value that would be altered on decoding."
        }
    }
}

enum InputSource {
    /// The one normalization rule every `set` / `set-pair` value goes through,
    /// whatever its source: surrounding whitespace and line breaks are dropped
    /// (pastes usually carry a trailing newline), nothing inside is touched.
    /// Returns nil when nothing is left — whitespace-only counts as empty.
    static func normalize(_ raw: String) -> String? {
        let v = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return v.isEmpty ? nil : v
    }

    /// Read the clipboard's plain-text string, normalized.
    static func readClipboard(pasteboard: NSPasteboard = .general) throws -> String {
        guard let raw = pasteboard.string(forType: .string), let value = normalize(raw) else {
            throw InputSourceError.emptyClipboard
        }
        return value
    }

    /// The pasteboard's change counter at read time; pass it to
    /// `clearClipboard(ifUnchangedSince:)` so a value the user copied *after*
    /// we read is never destroyed.
    static func clipboardChangeCount(pasteboard: NSPasteboard = .general) -> Int {
        pasteboard.changeCount
    }

    /// Remove the value from this Mac's clipboard after a successful store.
    /// Clears every type on the board (that is what "clear" means on macOS),
    /// but only if the board still holds what we read. Returns whether it
    /// cleared. A clipboard manager or Universal Clipboard may keep a copy —
    /// this cannot reach those.
    @discardableResult
    static func clearClipboard(pasteboard: NSPasteboard = .general, ifUnchangedSince changeCount: Int) -> Bool {
        guard pasteboard.changeCount == changeCount else { return false }
        pasteboard.clearContents()
        return true
    }

    static let stdinLimit = 64 * 1024

    /// Read exactly one line of content from stdin. Reads incrementally and
    /// stops at the first line break (LF or CR) — it does NOT wait for EOF, so
    /// a writer that keeps the pipe open cannot hang us. Refused rather than
    /// guessed: a terminal (interactive paste is what bracketed-paste mangles),
    /// more than `stdinLimit` bytes without a line break, invalid UTF-8, and
    /// any further non-blank content that had already arrived after the line.
    static func readStdin(handle: FileHandle = .standardInput, isTTY: Bool = isatty(0) != 0) throws -> String {
        guard !isTTY else { throw InputSourceError.stdinIsTerminal }
        let blank: (UInt8) -> Bool = { $0 == 0x0a || $0 == 0x0d || $0 == 0x20 || $0 == 0x09 }
        let isBreak: (UInt8) -> Bool = { $0 == 0x0a || $0 == 0x0d }
        var buffer = Data()
        while true {
            let chunk = handle.availableData          // blocks until some bytes or EOF
            if chunk.isEmpty { break }                // EOF
            buffer.append(chunk)
            let stripped = buffer.drop(while: blank)  // leading blank lines do not count
            if stripped.contains(where: isBreak) { break }
            if stripped.count > stdinLimit { throw InputSourceError.stdinTooLong(limit: stdinLimit) }
        }
        let stripped = buffer.drop(while: blank)
        let firstLine = stripped.prefix { !isBreak($0) }
        guard firstLine.count <= stdinLimit else { throw InputSourceError.stdinTooLong(limit: stdinLimit) }
        let rest = stripped.dropFirst(firstLine.count)
        guard !rest.contains(where: { !blank($0) }) else { throw InputSourceError.stdinMultiline }
        guard let decoded = String(bytes: firstLine, encoding: .utf8) else { throw InputSourceError.stdinNotUTF8 }
        guard let value = normalize(decoded) else { throw InputSourceError.emptyStdin }
        return value
    }
}
