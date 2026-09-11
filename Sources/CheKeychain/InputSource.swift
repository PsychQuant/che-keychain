// Sources/CheKeychain/InputSource.swift
import AppKit
import CryptoKit
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
    case stdinTimeout(seconds: Int)
    case surroundingWhitespace(source: String)
    case embeddedLineBreak(source: String)

    var errorDescription: String? {
        switch self {
        case .emptyClipboard:
            return "the clipboard holds no text (or only whitespace) — copy the value first, then retry with --from-clipboard."
        case .stdinIsTerminal:
            return "--stdin needs a pipe, not a terminal (e.g. `pbpaste | che-keychain set … --stdin`); an interactive paste would be mangled by bracketed-paste control sequences."
        case .emptyStdin:
            return "nothing (or only whitespace) was read from stdin — nothing stored."
        case .stdinTooLong(let limit):
            return "the first line of stdin exceeds \(limit) bytes — refusing to store a truncated value."
        case .surroundingWhitespace(let source):
            return "the value from \(source) has leading or trailing whitespace (only line breaks at the ends are stripped) — refusing to store it altered; remove the whitespace and retry."
        case .embeddedLineBreak(let source):
            return "the value from \(source) contains a line break — a multi-line secret is not supported; copy or pipe exactly one line."
        case .stdinTimeout(let seconds):
            return "no complete line arrived on stdin within \(seconds) s — nothing stored."
        case .stdinMultiline:
            return "stdin carried more than one line of content — refusing to store only the first line. Pipe exactly one line (a multi-line secret is not supported)."
        case .stdinNotUTF8:
            return "stdin is not valid UTF-8 — refusing to store a value that would be altered on decoding."
        }
    }
}

enum InputSource {
    /// Rule for the two non-dialog sources (#6): LF/CR at the ends are dropped
    /// (a paste usually carries a trailing newline); nothing else is altered —
    /// a value with leading/trailing whitespace, or a line break inside, is
    /// refused rather than trimmed or truncated, matching the identifier
    /// policy ("it would be stored as typed"). Returns nil when nothing but
    /// blanks is left.
    static func normalizeLine(_ raw: String, source: String) throws -> String? {
        let breaks = CharacterSet(charactersIn: "\n\r")
        let noBreaks = raw.trimmingCharacters(in: breaks)
        if noBreaks.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return nil }
        guard noBreaks.rangeOfCharacter(from: breaks) == nil else {
            throw InputSourceError.embeddedLineBreak(source: source)
        }
        guard noBreaks == noBreaks.trimmingCharacters(in: .whitespaces) else {
            throw InputSourceError.surroundingWhitespace(source: source)
        }
        return noBreaks
    }

    /// Dialog / set-pair rule: stored as typed; only an empty or whitespace-only
    /// field is refused (nil).
    static func typedValue(_ raw: String) -> String? {
        raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : raw
    }

    /// Read the clipboard's plain-text string (line breaks at the ends dropped).
    static func readClipboard(pasteboard: NSPasteboard = .general) throws -> String {
        guard let raw = pasteboard.string(forType: .string), let value = try normalizeLine(raw, source: "the clipboard") else {
            throw InputSourceError.emptyClipboard
        }
        return value
    }

    /// Short, non-reversible description of a value for the confirmation
    /// dialog: length and the first 8 hex digits of its SHA-256. Enough to
    /// notice the clipboard does not hold what you meant; useless to an observer.
    static func fingerprint(_ value: String) -> String {
        let digest = SHA256.hash(data: Data(value.utf8)).prefix(4).map { String(format: "%02x", $0) }.joined()
        // Useless to an observer for a high-entropy token; a low-entropy secret
        // (PIN, passphrase) could be confirmed offline from length + prefix.
        return "\(value.utf8.count) bytes, sha256 \(digest)…"
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
    static func clearClipboard(pasteboard: NSPasteboard = .general, ifUnchangedSince changeCount: Int?) -> Bool {
        guard let cc = changeCount, pasteboard.changeCount == cc else { return false }
        pasteboard.clearContents()
        return true
    }

    static let stdinLimit = 64 * 1024
    /// After the first line break, how long to wait for a slow writer's next
    /// bytes before concluding the input was one line. Best-effort by nature:
    /// a writer that pauses longer than this and then sends a second line is
    /// not detected (documented).
    static let stdinGraceMilliseconds: Int32 = 100
    /// How long to wait for the next bytes at all before giving up: a writer
    /// that keeps the pipe open and sends nothing must not hang us forever.
    static var stdinIdleSeconds: Int32 = 30

    /// Read exactly one line of content from stdin. Reads incrementally and
    /// stops at the first line break (LF or CR) — it does NOT wait for EOF, so
    /// a writer that keeps the pipe open cannot hang us; an idle writer is
    /// given `stdinIdleSeconds` per read. Leading BLANK LINES are skipped; the
    /// value's own line is handed over as is. Refused rather than guessed: a
    /// terminal (interactive paste is what bracketed-paste mangles), more than
    /// `stdinLimit` bytes consumed, invalid UTF-8, leading/trailing whitespace
    /// on the line, and any further non-blank content that arrived by the end
    /// of a short grace period.
    static func readStdin(handle: FileHandle = .standardInput, isTTY: Bool = isatty(0) != 0) throws -> String {
        guard !isTTY else { throw InputSourceError.stdinIsTerminal }
        let isBreak: (UInt8) -> Bool = { $0 == 0x0a || $0 == 0x0d }
        let isBlank: (UInt8) -> Bool = { isBreak($0) || $0 == 0x20 || $0 == 0x09 }
        func waitReadable(_ ms: Int32) -> Bool {
            var pfd = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
            return poll(&pfd, 1, ms) > 0 && (pfd.revents & Int16(POLLIN | POLLHUP)) != 0
        }
        var buffer = Data()
        var scanned = 0            // bytes already scanned (incremental, O(n))
        var lineStart = 0          // start of the current line
        var contentSeen = false    // the current line has a non-blank byte
        var breakAt: Int? = nil
        var sawEOF = false
        while breakAt == nil {
            guard waitReadable(stdinIdleSeconds * 1000) else { throw InputSourceError.stdinTimeout(seconds: Int(stdinIdleSeconds)) }
            let chunk = handle.availableData
            if chunk.isEmpty { sawEOF = true; break }                // EOF
            buffer.append(chunk)
            if buffer.count > stdinLimit { throw InputSourceError.stdinTooLong(limit: stdinLimit) }
            var i = scanned
            while i < buffer.count {
                let b = buffer[i]
                if isBreak(b) {
                    if contentSeen { breakAt = i; break }
                    lineStart = i + 1                                 // a blank line: skip it whole
                } else if !isBlank(b) {
                    contentSeen = true
                }
                i += 1
            }
            scanned = buffer.count
        }
        // Give a slow writer a moment to deliver a second line, so a multi-line
        // value is refused instead of silently truncated (best-effort).
        if breakAt != nil && !sawEOF && waitReadable(stdinGraceMilliseconds) {
            buffer.append(handle.availableData)
            if buffer.count > stdinLimit { throw InputSourceError.stdinTooLong(limit: stdinLimit) }
        }
        guard contentSeen else { throw InputSourceError.emptyStdin }
        let lineEnd = breakAt ?? buffer.count
        let line = buffer[lineStart..<lineEnd]
        let rest = buffer[lineEnd...]
        guard !rest.contains(where: { !isBlank($0) }) else { throw InputSourceError.stdinMultiline }
        guard let decoded = String(bytes: line, encoding: .utf8) else { throw InputSourceError.stdinNotUTF8 }
        guard let value = try normalizeLine(decoded, source: "stdin") else { throw InputSourceError.emptyStdin }
        return value
    }
}
