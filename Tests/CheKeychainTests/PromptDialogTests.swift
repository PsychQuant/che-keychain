import XCTest
@testable import CheKeychain

final class PromptDialogTests: XCTestCase {
    // The AppKit dialog itself is exercised manually (it requires a real GUI
    // session). We test only the pure-string helpers here.

    func testInformativeTextIncludesDestination() {
        let text = PromptDialog.buildInformativeText(destination: "service=foo account=bar", explain: nil)
        XCTAssertTrue(text.contains("service=foo account=bar"))
        XCTAssertTrue(text.contains("login.keychain"), "user should see where it's being stored")
    }

    func testInformativeTextIncludesExplainWhenProvided() {
        let text = PromptDialog.buildInformativeText(
            destination: "service=x account=y",
            explain: "Used in production."
        )
        XCTAssertTrue(text.contains("Used in production."))
    }

    func testInformativeTextOmitsExplainBlockWhenNilOrEmpty() {
        let nilText = PromptDialog.buildInformativeText(destination: "x", explain: nil)
        let emptyText = PromptDialog.buildInformativeText(destination: "x", explain: "")
        // Both should still mention destination + keychain location; just no
        // double blank lines from an empty explain block.
        XCTAssertFalse(nilText.contains("\n\n\n"))
        XCTAssertFalse(emptyText.contains("\n\n\n"))
    }
}
