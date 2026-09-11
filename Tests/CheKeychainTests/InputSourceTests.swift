import XCTest
import AppKit
@testable import CheKeychain

final class InputSourceTests: XCTestCase {
    // MARK: stdin

    private func pipe(with text: String) -> FileHandle {
        let p = Pipe()
        p.fileHandleForWriting.write(Data(text.utf8))
        p.fileHandleForWriting.closeFile()
        return p.fileHandleForReading
    }

    func testStdinReadsOneLineAndDropsLineBreaks() throws {
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "tok3n\r\n"), isTTY: false), "tok3n")
        // Leading/trailing whitespace is refused, not trimmed (stored-as-typed policy).
        XCTAssertThrowsError(try InputSource.readStdin(handle: pipe(with: "  tok3n \n"), isTTY: false)) { err in
            guard case InputSourceError.surroundingWhitespace = err else { return XCTFail("got \(err)") }
        }
        // No trailing newline at all is fine too; CR-only line endings count as breaks.
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "bare"), isTTY: false), "bare")
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "cr\r"), isTTY: false), "cr")
        // Trailing blank lines after the value are fine.
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "one\n\n  \n"), isTTY: false), "one")
    }

    func testStdinRefusesMoreThanOneLineOfContent() {
        XCTAssertThrowsError(try InputSource.readStdin(handle: pipe(with: "first\nsecond\n"), isTTY: false)) { err in
            guard case InputSourceError.stdinMultiline = err else { return XCTFail("got \(err)") }
        }
    }

    func testStdinRefusesASecondLineThatArrivesShortlyAfterTheFirst() throws {
        // The lines arrive in separate writes; the grace period must catch the second.
        let p = Pipe()
        p.fileHandleForWriting.write(Data("first\n".utf8))
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.02) { p.fileHandleForWriting.write(Data("second\n".utf8)) }
        XCTAssertThrowsError(try InputSource.readStdin(handle: p.fileHandleForReading, isTTY: false)) { err in
            guard case InputSourceError.stdinMultiline = err else { return XCTFail("got \(err)") }
        }
        p.fileHandleForWriting.closeFile()
    }

    func testStdinAllBlankStreamIsBoundedByTheLimit() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("che-keychain-blank-\(UUID().uuidString)")
        try Data(repeating: 0x20, count: InputSource.stdinLimit + 100).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        XCTAssertThrowsError(try InputSource.readStdin(handle: try FileHandle(forReadingFrom: url), isTTY: false)) { err in
            guard case InputSourceError.stdinTooLong = err else { return XCTFail("got \(err)") }
        }
    }

    func testStdinRefusesInvalidUTF8() throws {
        let p = Pipe(); p.fileHandleForWriting.write(Data([0x74, 0x6f, 0x6b, 0xff, 0x0a])); p.fileHandleForWriting.closeFile()
        XCTAssertThrowsError(try InputSource.readStdin(handle: p.fileHandleForReading, isTTY: false)) { err in
            guard case InputSourceError.stdinNotUTF8 = err else { return XCTFail("got \(err)") }
        }
    }

    func testValuePolicies() throws {
        XCTAssertEqual(try InputSource.normalizeLine("a b\n", source: "x"), "a b")
        XCTAssertNil(try InputSource.normalizeLine(" \n\t", source: "x"))
        XCTAssertThrowsError(try InputSource.normalizeLine(" a", source: "x"))
        XCTAssertEqual(InputSource.typedValue(" a "), " a ", "dialog values are stored as typed")
        XCTAssertNil(InputSource.typedValue("   "))
        XCTAssertTrue(InputSource.fingerprint("abc").hasPrefix("3 bytes, sha256 ba7816bf"))
    }

    func testStdinReturnsAtTheLineBreakWithoutWaitingForEOF() throws {
        // A writer that keeps the pipe open (ssh session, wrapper, FIFO) must not hang us.
        let p = Pipe()
        p.fileHandleForWriting.write(Data("tok\n".utf8))
        let done = expectation(description: "readStdin returned")
        var result: String?
        DispatchQueue.global().async {
            result = try? InputSource.readStdin(handle: p.fileHandleForReading, isTTY: false)
            done.fulfill()
        }
        wait(for: [done], timeout: 3)
        XCTAssertEqual(result, "tok")
        p.fileHandleForWriting.closeFile()
    }

    func testStdinSkipsLeadingBlankLines() throws {
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "\n  \ntok\n"), isTTY: false), "tok")
    }

    func testStdinRefusesOverlongLine() throws {
        // A Pipe would block the writer at 64 KiB; use a file as the stdin stand-in.
        let big = String(repeating: "x", count: InputSource.stdinLimit + 10)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("che-keychain-stdin-\(UUID().uuidString)")
        try Data(big.utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let handle = try FileHandle(forReadingFrom: url)
        XCTAssertThrowsError(try InputSource.readStdin(handle: handle, isTTY: false)) { err in
            guard case InputSourceError.stdinTooLong = err else { return XCTFail("got \(err)") }
        }
    }

    func testStdinRefusesTTY() {
        XCTAssertThrowsError(try InputSource.readStdin(handle: pipe(with: "x\n"), isTTY: true)) { err in
            guard case InputSourceError.stdinIsTerminal = err else { return XCTFail("got \(err)") }
        }
    }

    func testStdinEmptyIsError() {
        for text in ["", "\n", "   \n"] {
            XCTAssertThrowsError(try InputSource.readStdin(handle: pipe(with: text), isTTY: false)) { err in
                guard case InputSourceError.emptyStdin = err else { return XCTFail("\(text.debugDescription): got \(err)") }
            }
        }
    }

    // MARK: clipboard (private pasteboard, never the user's general one)

    func testClipboardRoundTripAndClear() throws {
        let pb = NSPasteboard(name: NSPasteboard.Name("che-keychain-test-\(UUID().uuidString)"))
        defer { pb.releaseGlobally() }
        pb.clearContents()
        pb.setString("\nsecret-value\n", forType: .string)
        XCTAssertEqual(try InputSource.readClipboard(pasteboard: pb), "secret-value")
        pb.clearContents(); pb.setString(" padded ", forType: .string)
        XCTAssertThrowsError(try InputSource.readClipboard(pasteboard: pb)) { err in
            guard case InputSourceError.surroundingWhitespace = err else { return XCTFail("got \(err)") }
        }
        pb.clearContents(); pb.setString("\nsecret-value\n", forType: .string)
        let cc = InputSource.clipboardChangeCount(pasteboard: pb)
        pb.clearContents(); pb.setString("something the user copied meanwhile", forType: .string)
        XCTAssertFalse(InputSource.clearClipboard(pasteboard: pb, ifUnchangedSince: cc), "a changed clipboard is left alone")
        XCTAssertEqual(pb.string(forType: .string), "something the user copied meanwhile")
        let cc2 = InputSource.clipboardChangeCount(pasteboard: pb)
        XCTAssertTrue(InputSource.clearClipboard(pasteboard: pb, ifUnchangedSince: cc2))
        XCTAssertNil(pb.string(forType: .string), "clearClipboard must remove the value")
    }

    func testClipboardEmptyIsError() {
        let pb = NSPasteboard(name: NSPasteboard.Name("che-keychain-test-\(UUID().uuidString)"))
        defer { pb.releaseGlobally() }
        pb.clearContents()
        XCTAssertThrowsError(try InputSource.readClipboard(pasteboard: pb)) { err in
            guard case InputSourceError.emptyClipboard = err else { return XCTFail("got \(err)") }
        }
        pb.setString("   \n", forType: .string)
        XCTAssertThrowsError(try InputSource.readClipboard(pasteboard: pb))
    }
}
