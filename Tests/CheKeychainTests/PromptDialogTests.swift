import XCTest
import AppKit
@testable import CheKeychain

final class PromptDialogTests: XCTestCase {
    // The AppKit dialog itself is exercised manually (it requires a real GUI
    // session). We test only the pure helpers here.

    func testInformativeTextPutsAWarningOnItsOwnFirstLine() {
        // The caller controls service/account (up to 256 scalars each): a warning
        // appended after them could be pushed out of view or contradicted.
        let text = PromptDialog.buildInformativeText(destination: "service=x account=y", explain: "e", warning: "daemon-readable ACL: other keychain authorization may still be required")
        let lines = text.components(separatedBy: "\n")
        XCTAssertEqual(lines.first, "⚠ daemon-readable ACL: other keychain authorization may still be required")
        XCTAssertEqual(lines[1], "Storing to: service=x account=y")
        XCTAssertFalse(PromptDialog.buildInformativeText(destination: "d", explain: nil).contains("⚠"))
    }

    func testWarningTextCombinesReplaceAndDaemonInsteadOfChoosing() {
        // Both facts must survive on the protected first line — the worst combination
        // (an existing secret destroyed AND made world-readable) must not lose one of them.
        XCTAssertNil(PromptDialog.warningText(daemon: false, replaces: false))
        XCTAssertEqual(PromptDialog.warningText(daemon: true, replaces: false), "daemon-readable ACL: other keychain authorization may still be required")
        XCTAssertEqual(PromptDialog.warningText(daemon: false, replaces: true), "replaces an existing secret")
        XCTAssertEqual(PromptDialog.warningText(daemon: true, replaces: true), "replaces an existing secret AND sets a daemon-readable ACL: other keychain authorization may still be required")
    }

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

    // MARK: - Edit menu (issue #1: dialog could not paste)

    // Without a main menu carrying a standard Edit menu, NSAlert.runModal()
    // has no key-equivalent binding for Cmd+V, so the modal text fields cannot
    // paste. These tests pin the structure of the Edit menu we install.

    func testMainMenuHasEditSubmenu() {
        let mainMenu = PromptDialog.makeMainMenuWithEditMenu()
        XCTAssertEqual(mainMenu.items.count, 1, "expected a single top-level item hosting the Edit submenu")
        guard let editMenu = mainMenu.items.first?.submenu else {
            return XCTFail("expected an Edit submenu on the main menu")
        }
        XCTAssertEqual(editMenu.title, "Edit")
    }

    func testEditMenuHasPasteBoundToCmdV() {
        let mainMenu = PromptDialog.makeMainMenuWithEditMenu()
        guard let editMenu = mainMenu.items.first?.submenu else {
            return XCTFail("expected an Edit submenu")
        }
        guard let paste = editMenu.items.first(where: { $0.action == #selector(NSText.paste(_:)) }) else {
            return XCTFail("expected a Paste item bound to NSText.paste(_:)")
        }
        XCTAssertEqual(paste.keyEquivalent, "v", "Paste must be Cmd+V — the whole point of issue #1")
    }

    func testEditMenuHasCutCopySelectAll() {
        let mainMenu = PromptDialog.makeMainMenuWithEditMenu()
        guard let editMenu = mainMenu.items.first?.submenu else {
            return XCTFail("expected an Edit submenu")
        }
        XCTAssertTrue(editMenu.items.contains { $0.action == #selector(NSText.cut(_:)) && $0.keyEquivalent == "x" })
        XCTAssertTrue(editMenu.items.contains { $0.action == #selector(NSText.copy(_:)) && $0.keyEquivalent == "c" })
        XCTAssertTrue(editMenu.items.contains { $0.action == #selector(NSText.selectAll(_:)) && $0.keyEquivalent == "a" })
    }
}
