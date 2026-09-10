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
        InputSource.clearClipboard(pasteboard: pb)
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
