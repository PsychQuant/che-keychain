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
        }
    }
}

enum InputSource {
    /// Read the clipboard's plain-text string, trimmed of surrounding
    /// whitespace and line breaks (pastes usually carry a trailing newline).
    static func readClipboard(pasteboard: NSPasteboard = .general) throws -> String {
        guard let raw = pasteboard.string(forType: .string) else { throw InputSourceError.emptyClipboard }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw InputSourceError.emptyClipboard }
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
    static func clearClipboard(pasteboard: NSPasteboard = .general, ifUnchangedSince changeCount: Int? = nil) -> Bool {
        if let cc = changeCount, pasteboard.changeCount != cc { return false }
        pasteboard.clearContents()
        return true
    }

    static let stdinLimit = 64 * 1024

    /// Read the first non-blank line of stdin, trimmed. Reads incrementally and
    /// stops at the first line break — it does NOT wait for EOF, so a writer
    /// that keeps the pipe open (ssh session, a wrapper, a FIFO) cannot hang
    /// us. More than `stdinLimit` bytes without a line break is refused rather
    /// than truncated. A terminal is refused: the whole point is to bypass
    /// interactive paste.
    static func readStdin(handle: FileHandle = .standardInput, isTTY: Bool = isatty(0) != 0) throws -> String {
        guard !isTTY else { throw InputSourceError.stdinIsTerminal }
        var buffer = Data()
        while true {
            let chunk = handle.availableData          // blocks until some bytes or EOF
            if chunk.isEmpty { break }                // EOF
            buffer.append(chunk)
            // Skip leading blank lines: the first line that has content counts.
            let stripped = buffer.drop { $0 == 0x0a || $0 == 0x0d || $0 == 0x20 || $0 == 0x09 }
            if stripped.contains(0x0a) { break }
            if buffer.count > stdinLimit { throw InputSourceError.stdinTooLong(limit: stdinLimit) }
        }
        let stripped = buffer.drop { $0 == 0x0a || $0 == 0x0d || $0 == 0x20 || $0 == 0x09 }
        let firstLine = stripped.prefix { $0 != 0x0a }
        guard firstLine.count <= stdinLimit else { throw InputSourceError.stdinTooLong(limit: stdinLimit) }
        let value = String(decoding: firstLine, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw InputSourceError.emptyStdin }
        return value
    }
}
