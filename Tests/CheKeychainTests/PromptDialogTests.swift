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
        XCTAssertNil(PromptDialog.warningText(daemon: false, replacing: KeychainStore.Existing.none))
        let fresh = PromptDialog.warningText(daemon: true, replacing: KeychainStore.Existing.none) ?? ""
        XCTAssertTrue(fresh.contains("ALL applications") && fresh.contains("other keychain authorization may still be required"),
                      "a new --daemon item must say its scope, not only its caveat (J5): \(fresh)")
        let replaceOnly = PromptDialog.warningText(daemon: false, replacing: .own) ?? ""
        XCTAssertTrue(replaceOnly.contains("replaces"), replaceOnly)
        let both = PromptDialog.warningText(daemon: true, replacing: .own) ?? ""
        XCTAssertTrue(both.contains("replaces") && both.contains("any application"), both)
    }

    func testWarningTextSaysWhichAccessClassIsBeingReplacedAndWhatChanges() {
        // The dialog is the only place the user can still stop this, so it has to
        // say what is there now and what the replacement turns it into (#7 L1).
        let worldReadable = PromptDialog.warningText(daemon: false, replacing: .allowAll(.plaintext)) ?? ""
        XCTAssertTrue(worldReadable.contains("ANY application can read"), worldReadable)
        XCTAssertTrue(worldReadable.contains("only this binary"), worldReadable)

        let foreign = PromptDialog.warningText(daemon: false, replacing: .foreign(owners: ["/usr/bin/security"], allowAll: nil)) ?? ""
        XCTAssertTrue(foreign.contains("other") && foreign.contains("access to the OLD value ends"), foreign)
        XCTAssertTrue(foreign.contains("only this binary"), "must also say what it becomes: \(foreign)")

        // Widening is the worst case and must name both halves.
        let widening = PromptDialog.warningText(daemon: true, replacing: .own) ?? ""
        XCTAssertTrue(widening.contains("only this binary can read") && widening.contains("any application"), widening)
    }

    func testAnExportWrappedOnlyAllowAllItemIsNotDescribedAsReadableByEveryone() {
        // Round-7 verify K1: all applications may export such an item only in
        // wrapped (encrypted) form; the plaintext is not theirs. Replacing it with
        // a --daemon item hands every application the plaintext, and the dialog
        // is the one place that consent is asked for, so it must say so.
        let wrapped = PromptDialog.warningText(daemon: true, replacing: .allowAll(.wrappedOnly)) ?? ""
        XCTAssertFalse(wrapped.contains("ANY application can read"), wrapped)
        XCTAssertTrue(wrapped.contains("WIDENS"), "the widening is named: \(wrapped)")
        XCTAssertTrue(wrapped.contains("wrapped"), wrapped)
        // Without --daemon the replacement is readable by this binary only: no widening claimed.
        let narrowing = PromptDialog.warningText(daemon: false, replacing: .allowAll(.wrappedOnly)) ?? ""
        XCTAssertFalse(narrowing.contains("WIDENS"), narrowing)
        // A plaintext allow-all item replaced by another --daemon item widens nothing.
        let same = PromptDialog.warningText(daemon: true, replacing: .allowAll(.plaintext)) ?? ""
        XCTAssertFalse(same.contains("WIDENS"), same)

        // Foreign: the count is of applications only; the allow-all entry is described, not counted.
        let foreignWrapped = PromptDialog.warningText(daemon: true, replacing: .foreign(owners: ["/usr/bin/security"], allowAll: .wrappedOnly)) ?? ""
        XCTAssertTrue(foreignWrapped.contains("trusts 1 application other than this binary"), foreignWrapped)
        XCTAssertFalse(foreignWrapped.contains("2 other"), foreignWrapped)
        XCTAssertTrue(foreignWrapped.contains("WIDENS"), foreignWrapped)
        let foreignOpen = PromptDialog.warningText(daemon: false, replacing: .foreign(owners: ["/usr/bin/security"], allowAll: .plaintext)) ?? ""
        XCTAssertTrue(foreignOpen.contains("ANY application"), foreignOpen)
    }

    func testAPromptGatedItemIsNotDescribedAsOpenAndItsDaemonReplacementWidens() {
        let gated = PromptDialog.warningText(daemon: true, replacing: .allowAll(.promptGated)) ?? ""
        XCTAssertTrue(gated.contains("WIDENS") && gated.contains("confirmation prompt"), gated)
        XCTAssertFalse(gated.contains("ANY application can read"), gated)
    }

    func testPairWarningNamesOnlyAccountsThatWillBeReplaced() {
        XCTAssertNil(PromptDialog.pairWarningText(replacing: []))
        let one = PromptDialog.pairWarningText(replacing: ["client_secret"]) ?? ""
        XCTAssertTrue(one.contains("client_secret")); XCTAssertFalse(one.contains("client_id"))
        let both = PromptDialog.pairWarningText(replacing: ["client_id", "client_secret"]) ?? ""
        XCTAssertTrue(both.contains("client_id") && both.contains("client_secret"))
    }

    func testInputDialogSeparatesCallerExplanationFromTrustedDestination() {
        let explanation = "Caller says: store somewhere else"
        let built = PromptDialog.makeInputAlert(title: "Request", destination: "service=real account=real", explain: explanation,
            fields: [PromptField(name: "real", label: "Account", isSecure: true)], warning: "replaces an existing secret")
        XCTAssertTrue(built.alert.informativeText.contains("service=real account=real"))
        XCTAssertTrue(built.alert.informativeText.contains("replaces an existing secret"))
        XCTAssertFalse(built.alert.informativeText.contains(explanation))
        func labels(_ view: NSView) -> [String] {
            (view as? NSTextField).map { [$0.stringValue] } ?? view.subviews.flatMap(labels)
        }
        let shown = labels(built.alert.accessoryView!)
        XCTAssertTrue(shown.contains("Caller-provided explanation"))
        XCTAssertTrue(shown.contains(explanation))
        XCTAssertTrue(built.fieldViews.first is NSSecureTextField)
    }

    func testLongCallerExplanationCannotGrowTheInputDialogWithoutBound() {
        let built = PromptDialog.makeInputAlert(title: "Request", destination: "service=real account=real", explain: String(repeating: "caller text ", count: 2000),
            fields: [PromptField(name: "a", label: "Account", isSecure: true)], warning: "replaces an existing secret")
        built.alert.layout()
        XCTAssertLessThan(built.alert.window.frame.height, 700)
        XCTAssertTrue(built.alert.informativeText.hasPrefix("⚠ replaces an existing secret"))
        XCTAssertFalse(built.alert.informativeText.contains("caller text"))
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
