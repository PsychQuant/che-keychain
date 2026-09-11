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
    case stdinReadFailed(errno: Int32)
    case surroundingWhitespace(source: String)
    case embeddedLineBreak(source: String)
    case controlCharacters(source: String)

    var errorDescription: String? {
        switch self {
        case .emptyClipboard:
            return "the clipboard holds no text (or only whitespace) — copy the value first, then retry with --from-clipboard."
        case .stdinIsTerminal:
            return "--stdin needs a pipe, not a terminal (e.g. `pbpaste | che-keychain set … --stdin`); an interactive paste would be mangled by bracketed-paste control sequences."
        case .emptyStdin:
            return "nothing (or only whitespace) was read from stdin — nothing stored."
        case .stdinTooLong(let limit):
            return "stdin delivered more than \(limit) bytes before a complete line — refusing to store a truncated value."
        case .surroundingWhitespace(let source):
            return "the value from \(source) has leading or trailing whitespace (only line breaks at the ends are stripped) — refusing to store it altered; remove the whitespace and retry."
        case .embeddedLineBreak(let source):
            return "the value from \(source) contains a line break (LF, CR, or another Unicode line separator) — a multi-line secret is not supported; copy or pipe exactly one line."
        case .controlCharacters(let source):
            return "the value from \(source) contains control or format characters — refusing to store it (the same rule --service / --account have)."
        case .stdinTimeout(let seconds):
            return "no complete line arrived on stdin within \(seconds) s of starting to read — nothing stored."
        case .stdinReadFailed(let e):
            return "reading stdin failed (errno \(e): \(String(cString: strerror(e)))) — nothing stored."
        case .stdinMultiline:
            return "stdin carried more than one line of content — refusing to store only the first line. Pipe exactly one line (a multi-line secret is not supported)."
        case .stdinNotUTF8:
            return "stdin is not valid UTF-8 — refusing to store a value that would be altered on decoding."
        }
    }
}

enum InputSource {
    /// Rule for the two non-dialog sources (#6): LF/CR at the ends are dropped
    /// (a paste usually carries a trailing newline); nothing else is altered.
    /// Refused rather than trimmed or truncated: leading/trailing whitespace,
    /// any line break left (LF/CR inside, or any other Unicode line separator
    /// anywhere), and control/format characters — the same predicate
    /// `--service` / `--account` use (`CommandParser.containsControlOrFormat`).
    /// Returns nil when nothing but blanks is left.
    static func normalizeLine(_ raw: String, source: String) throws -> String? {
        let noBreaks = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\n\r"))
        if noBreaks.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return nil }
        guard !noBreaks.contains(where: { $0.isNewline }) else {
            throw InputSourceError.embeddedLineBreak(source: source)
        }
        // Surrounding whitespace (a tab is also a control character) is named
        // first, as the identifier check does: it is the likelier paste accident.
        guard noBreaks == noBreaks.trimmingCharacters(in: .whitespaces) else {
            throw InputSourceError.surroundingWhitespace(source: source)
        }
        guard !CommandParser.containsControlOrFormat(noBreaks) else {
            throw InputSourceError.controlCharacters(source: source)
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
    /// Total time allowed from the start of the read until a complete line has
    /// arrived — a deadline, not an idle timeout, so a drip-feeding writer is
    /// bounded too. A writer that keeps the pipe open must not hang us forever.
    #if DEBUG
    static var stdinDeadlineSeconds: Int32 = 30      // tests shorten it
    #else
    static let stdinDeadlineSeconds: Int32 = 30
    #endif

    /// Read exactly one line of content from stdin. Reads incrementally and
    /// stops at the first line break (LF or CR) — it does NOT wait for EOF, so
    /// a writer that keeps the pipe open cannot hang us; the whole read must
    /// complete within `stdinDeadlineSeconds`. Leading BLANK LINES are skipped;
    /// the value's own line is handed over as is. Refused rather than guessed:
    /// a terminal (interactive paste is what bracketed-paste mangles), more
    /// than `stdinLimit` bytes consumed, invalid UTF-8, leading/trailing
    /// whitespace on the line, and any further non-blank content that arrived
    /// by the end of a short grace period. `isTTY` defaults to a check of the
    /// handle actually read.
    static func readStdin(handle: FileHandle = .standardInput, isTTY: Bool? = nil) throws -> String {
        guard !(isTTY ?? (isatty(handle.fileDescriptor) != 0)) else { throw InputSourceError.stdinIsTerminal }
        let isBreak: (UInt8) -> Bool = { $0 == 0x0a || $0 == 0x0d }
        let isBlank: (UInt8) -> Bool = { isBreak($0) || $0 == 0x20 || $0 == 0x09 }
        let deadline = DispatchTime.now() + .seconds(Int(stdinDeadlineSeconds))
        /// Wait up to `ms` (clamped to the deadline) for readable data or EOF.
        func waitReadable(_ ms: Int32) throws -> Bool {
            let remaining = Int64(deadline.uptimeNanoseconds) - Int64(DispatchTime.now().uptimeNanoseconds)
            let budget = Int32(max(0, min(Int64(ms), remaining / 1_000_000)))
            var pfd = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
            var n: Int32
            repeat { n = poll(&pfd, 1, budget) } while n < 0 && errno == EINTR
            if n < 0 { throw InputSourceError.stdinReadFailed(errno: errno) }
            if n == 0 { return false }
            if (pfd.revents & Int16(POLLERR | POLLNVAL)) != 0 { throw InputSourceError.stdinReadFailed(errno: EIO) }
            return (pfd.revents & Int16(POLLIN | POLLHUP)) != 0
        }
        var buffer = Data()
        var scanned = 0            // bytes already scanned (incremental, O(n))
        var lineStart = 0          // start of the current line
        var contentSeen = false    // the current line has a non-blank byte
        var breakAt: Int? = nil
        var sawEOF = false
        while breakAt == nil {
            guard try waitReadable(stdinDeadlineSeconds * 1000) else { throw InputSourceError.stdinTimeout(seconds: Int(stdinDeadlineSeconds)) }
            let chunk = handle.availableData
            if chunk.isEmpty { sawEOF = true; break }                // EOF
            buffer.append(chunk)
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
            // The cap is about a line that never completes; a completed line
            // followed by more content is the multi-line refusal below.
            if breakAt == nil && buffer.count > stdinLimit { throw InputSourceError.stdinTooLong(limit: stdinLimit) }
        }
        // Give a slow writer a moment to deliver a second line, so a multi-line
        // value is refused instead of silently truncated (best-effort).
        // Keep looking for the WHOLE grace period, not just the first readable
        // event: a lone blank byte followed by a second line inside the window
        // must still be seen. A poll error here must not discard the valid line.
        if breakAt != nil {   // (EOF cannot have been seen: the loop broke on a line break)
            let graceEnd = DispatchTime.now() + .milliseconds(Int(stdinGraceMilliseconds))
            while true {
                let left = Int64(graceEnd.uptimeNanoseconds) - Int64(DispatchTime.now().uptimeNanoseconds)
                if left <= 0 { break }
                guard (try? waitReadable(Int32(min(Int64(stdinGraceMilliseconds), left / 1_000_000 + 1)))) ?? false else { break }
                let more = handle.availableData
                if more.isEmpty { break }                                    // EOF
                buffer.append(more)
                if more.contains(where: { !isBlank($0) }) { break }          // enough to refuse
            }
        }
        // Best-effort: the buffer held the secret; wipe it once the String copy exists.
        defer { buffer.resetBytes(in: 0..<buffer.count) }
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
