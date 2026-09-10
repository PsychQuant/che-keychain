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

    var errorDescription: String? {
        switch self {
        case .emptyClipboard:
            return "the clipboard holds no text (or only whitespace) — copy the value first, then retry with --from-clipboard."
        case .stdinIsTerminal:
            return "--stdin needs a pipe, not a terminal (e.g. `pbpaste | che-keychain set … --stdin`); an interactive paste would be mangled by bracketed-paste control sequences."
        case .emptyStdin:
            return "nothing (or only whitespace) was read from stdin — nothing stored."
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

    /// Wipe the pasteboard after a successful store: a token must not stay on
    /// the clipboard. Clears every type on the board, not only our string.
    static func clearClipboard(pasteboard: NSPasteboard = .general) {
        pasteboard.clearContents()
    }

    /// Read the first line of stdin (up to 64 KiB), trimmed. A terminal is
    /// refused: the whole point is to bypass interactive paste.
    static func readStdin(handle: FileHandle = .standardInput, isTTY: Bool = isatty(0) != 0) throws -> String {
        guard !isTTY else { throw InputSourceError.stdinIsTerminal }
        let data = handle.readData(ofLength: 64 * 1024)
        let firstLine = data.prefix { $0 != 0x0a }
        let value = String(decoding: firstLine, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw InputSourceError.emptyStdin }
        return value
    }
}
