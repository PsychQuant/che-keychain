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

    func testStdinReadsOneLineAndTrims() throws {
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "  tok3n \r\n"), isTTY: false), "tok3n")
        // Only the first line counts; a second line is not part of the value.
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "first\nsecond\n"), isTTY: false), "first")
        // No trailing newline at all is fine too.
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "bare"), isTTY: false), "bare")
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
        XCTAssertEqual(try InputSource.readStdin(handle: pipe(with: "\n  \ntok\nnext\n"), isTTY: false), "tok")
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
        pb.setString("\n  secret-value \n", forType: .string)
        XCTAssertEqual(try InputSource.readClipboard(pasteboard: pb), "secret-value")
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
