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
    /// The one sentence that must survive on the dialog's protected first line.
    /// Both facts are kept when both hold — the worst combination (an existing
    /// secret destroyed AND made world-readable) must not lose one of them.
    ///
    /// `replacing` is the destination's current access class, so the line can say
    /// what is there now and what the replacement turns it into. "Replaces an
    /// existing secret" alone does not let anyone judge the change: replacing a
    /// world-readable item with a binary-only one narrows access, and the reverse
    /// widens it, and the dialog is the last place either can be stopped (#7 L1).
    static func warningText(daemon: Bool, replacing existing: KeychainStore.Existing) -> String? {
        let becomes = daemon
            ? "one any application can read (other keychain authorization may still be required)"
            : "one only this binary can read"
        let now: String
        switch existing {
        case .none:
            return daemon ? "daemon-readable ACL: other keychain authorization may still be required" : nil
        case .own:
            now = "a secret only this binary can read"
        case .allowAll:
            now = "a secret ANY application can read"
        case .foreign(let owners):
            now = owners.isEmpty
                ? "a secret nothing ties to this binary"
                : "a secret \(owners.count) other application\(owners.count == 1 ? "" : "s") can read — that access ends"
        case .unsupported:
            now = "an existing secret whose access this binary cannot inspect"
        }
        return "replaces \(now) with \(becomes)"
    }

    static func run(title: String, destination: String, explain: String?, fields: [PromptField], warning: String? = nil) -> PromptResult {
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

        let built = makeInputAlert(title: title, destination: destination, explain: explain, fields: fields, warning: warning)
        let alert = built.alert
        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else {
            return .cancel
        }

        var values: [String: String] = [:]
        for (field, view) in zip(fields, built.fieldViews) {
            values[field.name] = view.stringValue
        }
        return .accept(values: values)
    }

    static func pairWarningText(replacing accounts: [String]) -> String? {
        guard !accounts.isEmpty else { return nil }
        return "replaces existing secrets for accounts: " + accounts.map(sanitize).joined(separator: ", ")
    }

    /// Build the input alert without presenting it. Trusted destination text
    /// remains in informativeText; caller explanation lives in the accessory.
    static func makeInputAlert(title: String, destination: String, explain: String?, fields: [PromptField], warning: String? = nil) -> (alert: NSAlert, fieldViews: [NSTextField]) {
        let alert = NSAlert()
        alert.messageText = sanitize(title)
        alert.informativeText = buildInformativeText(destination: destination, explain: nil, warning: warning)
        alert.addButton(withTitle: "Store")
        alert.addButton(withTitle: "Cancel")
        alert.alertStyle = .informational
        let inputs = buildAccessoryView(for: fields, explain: explain)
        alert.accessoryView = inputs.container
        alert.window.initialFirstResponder = inputs.fieldViews.first
        return (alert, inputs.fieldViews)
    }

    /// Confirmation-only alert (no input field) for `--from-clipboard` (#6): the
    /// user still sees the destination before anything is read or stored —
    /// the paste problem was in the input field, not in the dialog itself.
    static func confirm(title: String, destination: String, explain: String?, warning: String? = nil) -> Bool {
        let app = NSApplication.shared
        if app.activationPolicy() != .regular { app.setActivationPolicy(.regular) }
        app.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = buildInformativeText(destination: destination, explain: explain, warning: warning)
        alert.addButton(withTitle: "Store")
        alert.addButton(withTitle: "Cancel")
        alert.alertStyle = .warning
        // With no input field a stray Return must not store: Store needs a
        // deliberate click (or ⌘S); Return does nothing; Cancel keeps Escape.
        alert.buttons[0].keyEquivalent = "s"
        alert.buttons[0].keyEquivalentModifierMask = [.command]
        return alert.runModal() == .alertFirstButtonReturn
    }

    // MARK: - Building blocks (factored out for testability)

    /// `warning` (if any) is the FIRST line, before the caller-controlled
    /// destination, so a long service/account cannot push it out of view.
    static func buildInformativeText(destination: String, explain: String?, warning: String? = nil) -> String {
        var lines: [String] = []
        if let w = warning, !w.isEmpty { lines.append("⚠ \(w)") }
        lines.append("Storing to: \(destination)")
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

    private static func buildAccessoryView(for fields: [PromptField], explain: String?) -> (container: NSView, fieldViews: [NSTextField]) {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false

        if let explain, !explain.isEmpty {
            let heading = NSTextField(labelWithString: "Caller-provided explanation")
            heading.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize, weight: .semibold)
            stack.addArrangedSubview(heading)
            let shown = String(explain.prefix(512)) + (explain.count > 512 ? "…" : "")
            let text = NSTextField(wrappingLabelWithString: shown)
            text.preferredMaxLayoutWidth = 360
            text.maximumNumberOfLines = 6
            text.lineBreakMode = .byTruncatingTail
            text.setAccessibilityLabel("Caller-provided explanation")
            text.widthAnchor.constraint(equalToConstant: 360).isActive = true
            stack.addArrangedSubview(text)
        }

        var fieldViews: [NSTextField] = []
        for field in fields {
            let row = NSStackView()
            row.orientation = .vertical
            row.alignment = .leading
            row.spacing = 2

            let label = NSTextField(labelWithString: sanitize(field.label))
            label.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
            label.lineBreakMode = .byTruncatingTail
            label.widthAnchor.constraint(equalToConstant: 360).isActive = true

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
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 360, height: max(CGFloat(fields.count) * 56, stack.fittingSize.height)))
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
