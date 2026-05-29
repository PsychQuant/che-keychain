// Sources/CheKeychain/PromptDialog.swift
import AppKit

struct PromptField {
    let name: String        // keychain account name — the storage key
    let label: String       // what to display next to the input
    let isSecure: Bool      // true → NSSecureTextField (masked)
}

enum PromptResult {
    case accept(values: [String: String])
    case cancel
}

/// One-shot native macOS dialog for capturing one or more credentials and
/// echoing them back to the caller in-memory (NOT into the LLM context — the
/// caller of this binary doesn't see anything the user types here). The
/// destination string is rendered in the dialog so the user can verify the
/// caller isn't redirecting writes to a misleading service/account.
enum PromptDialog {
    static func run(title: String, destination: String, explain: String?, fields: [PromptField]) -> PromptResult {
        // NSApp must be a regular app for its window to come forward on a
        // CLI invocation. Without this, an .runModal() either no-ops or hides
        // behind whatever terminal/app is in front.
        let app = NSApplication.shared
        if app.activationPolicy() != .regular {
            app.setActivationPolicy(.regular)
        }
        app.activate(ignoringOtherApps: true)

        // A CLI-launched NSApplication has no main menu, so NSAlert.runModal()
        // has no key-equivalent binding for Cmd+C/V/X/A and the modal text
        // fields silently fail to paste (issue #1). Install a standard Edit menu.
        installEditMenuIfNeeded(app)

        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = buildInformativeText(destination: destination, explain: explain)
        alert.addButton(withTitle: "Store")
        alert.addButton(withTitle: "Cancel")
        alert.alertStyle = .informational

        let inputs = buildAccessoryView(for: fields)
        alert.accessoryView = inputs.container
        // Focus the first field so the user can start typing immediately.
        if let first = inputs.fieldViews.first {
            alert.window.initialFirstResponder = first
        }

        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else {
            return .cancel
        }

        var values: [String: String] = [:]
        for (field, view) in zip(fields, inputs.fieldViews) {
            values[field.name] = view.stringValue
        }
        return .accept(values: values)
    }

    // MARK: - Building blocks (factored out for testability)

    static func buildInformativeText(destination: String, explain: String?) -> String {
        var lines = ["Storing to: \(destination)"]
        if let e = explain, !e.isEmpty {
            lines.append("")
            lines.append(e)
        }
        lines.append("")
        lines.append("Values are written to your macOS keychain (login.keychain-db, not iCloud-synced).")
        return lines.joined(separator: "\n")
    }

    // MARK: - Edit menu (issue #1: dialog could not paste)

    /// Builds a minimal main menu carrying a standard Edit menu (Cut/Copy/Paste/
    /// Select All). macOS binds Cmd+C/V/X/A to these menu items' key equivalents;
    /// without a main menu, NSAlert.runModal() can't dispatch Cmd+V to the focused
    /// text field's `paste:` action. `target = nil` routes each action up the
    /// responder chain to the active field editor. Factored out (not private) so
    /// the structure is unit-testable without a GUI session.
    static func makeMainMenuWithEditMenu() -> NSMenu {
        let mainMenu = NSMenu()
        let editItem = NSMenuItem()
        mainMenu.addItem(editItem)

        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu

        return mainMenu
    }

    /// Installs the Edit menu onto the app once. Idempotent — the dialog may run
    /// multiple times per process; an existing main menu is left intact.
    private static func installEditMenuIfNeeded(_ app: NSApplication) {
        guard app.mainMenu == nil else { return }
        app.mainMenu = makeMainMenuWithEditMenu()
    }

    private static func buildAccessoryView(for fields: [PromptField]) -> (container: NSView, fieldViews: [NSTextField]) {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false

        var fieldViews: [NSTextField] = []
        for field in fields {
            let row = NSStackView()
            row.orientation = .vertical
            row.alignment = .leading
            row.spacing = 2

            let label = NSTextField(labelWithString: field.label)
            label.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)

            let input: NSTextField = field.isSecure ? NSSecureTextField() : NSTextField()
            input.frame = NSRect(x: 0, y: 0, width: 360, height: 22)
            input.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                input.widthAnchor.constraint(equalToConstant: 360)
            ])
            fieldViews.append(input)

            row.addArrangedSubview(label)
            row.addArrangedSubview(input)
            stack.addArrangedSubview(row)
        }

        // Wrap in a container view so NSAlert sizes the accessory correctly.
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 360, height: CGFloat(fields.count) * 56))
        container.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            stack.topAnchor.constraint(equalTo: container.topAnchor),
            stack.bottomAnchor.constraint(equalTo: container.bottomAnchor)
        ])
        return (container, fieldViews)
    }
}
