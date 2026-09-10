import XCTest
import Security
@testable import CheKeychain

final class KeychainStoreTests: XCTestCase {
    // Use a UUID-suffixed service so test runs never collide with real entries
    // or leave permanent residue if a test fails partway through.
    private var service: String { "che-keychain-test-\(testRunID!)" }
    private var testRunID: String!

    override func setUp() {
        super.setUp()
        testRunID = UUID().uuidString
    }

    override func tearDown() {
        try? KeychainStore.unset(service: service)
        // Foreign-owned items (seeded via `security`, see #5) can't be deleted by this
        // binary — errSecInvalidOwnerEdit. Sweep them with the CLI that owns them.
        // `security` deletes one matching item per call — loop until it reports none left.
        for _ in 0..<64 {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
            p.arguments = ["delete-generic-password", "-s", service]
            p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
            try? p.run(); p.waitUntilExit()
            if p.terminationStatus != 0 { break }
        }
        super.tearDown()
    }

    func testSaveAndHas() throws {
        try KeychainStore.save(service: service, account: "a", value: "v")
        XCTAssertTrue(KeychainStore.has(service: service, account: "a"))
        XCTAssertFalse(KeychainStore.has(service: service, account: "missing"))
    }

    func testSaveOverwritesExisting() throws {
        try KeychainStore.save(service: service, account: "a", value: "first")
        try KeychainStore.save(service: service, account: "a", value: "second")
        XCTAssertEqual(try readOwn(account: "a"), "second", "the headline requirement: the value really changed")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "a"), .own)
    }

    func testUnsetSpecificAccount() throws {
        try KeychainStore.save(service: service, account: "keep", value: "x")
        try KeychainStore.save(service: service, account: "drop", value: "y")
        try KeychainStore.unset(service: service, account: "drop")
        XCTAssertTrue(KeychainStore.has(service: service, account: "keep"))
        XCTAssertFalse(KeychainStore.has(service: service, account: "drop"))
    }

    func testUnsetAllAccountsUnderService() throws {
        try KeychainStore.save(service: service, account: "a", value: "1")
        try KeychainStore.save(service: service, account: "b", value: "2")
        try KeychainStore.unset(service: service)
        XCTAssertFalse(KeychainStore.has(service: service, account: "a"))
        XCTAssertFalse(KeychainStore.has(service: service, account: "b"))
    }

    func testUnsetMissingIsNotError() throws {
        XCTAssertEqual(try KeychainStore.unset(service: service, account: "never-existed"), [])
    }

    // MARK: - Foreign-owned items (#5)
    //
    // An item created by another binary (here: the `security` CLI) has a different
    // keychain owner. The old delete-then-add used SecItemDelete, which answers
    // errSecInvalidOwnerEdit (-25244) on such items (hence the -25299 that opened
    // #5). SecItemUpdate would "succeed" but leave the value under that program's
    // ACL. Policy (user decision after verify round 1): `save` refuses and names
    // the explicit remedy; `unset` (SecKeychainItemDelete by reference) can delete it.

    /// Creates an item owned by the `security` CLI, not by this test binary.
    /// `-A` = allow-all decrypt ACL (the shape that fooled the round-2 build).
    private func seedForeignItem(account: String, value: String, allowAll: Bool = false, label: String? = nil) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        // Value is a non-secret test literal; argv visibility is acceptable here.
        p.arguments = ["add-generic-password", "-s", service, "-a", account, "-w", value]
            + (allowAll ? ["-A"] : []) + (label.map { ["-l", $0] } ?? [])
        try p.run(); p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0, "security add-generic-password failed")
    }

    /// Reads back an item THIS test binary created, through SecItemCopyMatching.
    /// The store deliberately has no read API; the test binary is in the item's
    /// trusted-application list, so no SecurityAgent prompt fires. Do NOT use
    /// the `security` CLI for our own items: even allow-all (--daemon) items make
    /// `security` ask for the login-keychain password (partition-ID ACL), which
    /// hangs a headless run.
    private func readOwn(account: String) throws -> String {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        guard st == errSecSuccess, let d = out as? Data else { throw KeychainError.osStatus(st, operation: "test read") }
        return String(decoding: d, as: UTF8.self)
    }

    /// Reads a value back through the `security` CLI — only for items `security`
    /// itself created (it is their trusted application, so no prompt).
    private func readForeign(account: String) throws -> String {
        let p = Process(); let out = Pipe()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["find-generic-password", "-s", service, "-a", account, "-w"]
        p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        return String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func testSaveRefusesForeignOwnedItemAndNamesTheDeleteCommand() throws {
        try seedForeignItem(account: "foreign", value: "stale")
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "foreign", value: "fresh")) { err in
            guard case KeychainError.foreignOwned(let svc, let acct, let owners, _) = err else {
                return XCTFail("expected .foreignOwned, got \(err)")
            }
            XCTAssertEqual(svc, service); XCTAssertEqual(acct, "foreign")
            XCTAssertTrue(owners.contains("/usr/bin/security"), "owners=\(owners)")
            let msg = (err as? LocalizedError)?.errorDescription ?? ""
            XCTAssertTrue(msg.contains("che-keychain unset --service '\(service)' --account 'foreign'"), msg)
        }
        // Nothing was written: the foreign value is untouched.
        XCTAssertEqual(try readForeign(account: "foreign"), "stale")
    }

    func testSaveDaemonRefusesForeignItemAndLeavesItsACLAlone() throws {
        // Round-1 regression: `set --daemon` on a foreign item appended an allow-all ACL.
        try seedForeignItem(account: "foreign", value: "stale")
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "foreign", value: "fresh", daemon: true)) { err in
            guard case KeychainError.foreignOwned = err else { return XCTFail("expected .foreignOwned, got \(err)") }
        }
        XCTAssertEqual(try readForeign(account: "foreign"), "stale")
        guard case .foreign = try KeychainStore.inspectExisting(service: service, account: "foreign") else {
            return XCTFail("foreign item must still be classified foreign after the refusal")
        }
    }

    func testAllowAllItemsAreRefusedInBothModes() throws {
        // `security add-generic-password -A` — allow-all decrypt ACL. Such items
        // carry no owner identity and any label can be forged (`-l 'S/A'` was the
        // round-3 bypass), so both `set` and `set --daemon` refuse and name `unset`.
        try seedForeignItem(account: "open", value: "stale", allowAll: true)
        try seedForeignItem(account: "forged", value: "stale", allowAll: true, label: "\(service)/forged")
        for acct in ["open", "forged"] {
            XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: acct), .allowAll)
            for daemon in [false, true] {
                XCTAssertThrowsError(try KeychainStore.save(service: service, account: acct, value: "fresh", daemon: daemon)) { err in
                    guard case KeychainError.unattributable = err else { return XCTFail("\(acct) daemon=\(daemon): expected .unattributable, got \(err)") }
                    let msg = (err as? LocalizedError)?.errorDescription ?? ""
                    XCTAssertTrue(msg.contains("che-keychain unset --service '\(service)' --account '\(acct)'"), msg)
                }
                XCTAssertThrowsError(try KeychainStore.preflight(service: service, accounts: [acct], daemon: daemon))
            }
            XCTAssertEqual(try readForeign(account: acct), "stale", "nothing may touch \(acct)")
        }
    }

    func testMixedACLWithAllowAllEntryIsNotOwn() throws {
        // Our own item whose decrypt ACL later gained an allow-all entry (what the
        // round-1 build did via SecItemUpdate + kSecAttrAccess union). Round 4
        // dropped such entries and judged the item .own; it must be .allowAll.
        try KeychainStore.save(service: service, account: "mixed", value: "v1")
        var access: SecAccess?
        XCTAssertEqual(SecAccessCreate("x" as CFString, nil, &access), errSecSuccess)
        var acls: CFArray?
        XCTAssertEqual(SecAccessCopyACLList(access!, &acls), errSecSuccess)
        for acl in acls as! [SecACL] { _ = SecACLSetContents(acl, nil, "x" as CFString, SecKeychainPromptSelector(rawValue: 0)) }
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "mixed"]
        XCTAssertEqual(SecItemUpdate(q as CFDictionary, [kSecAttrAccess as String: access!] as CFDictionary), errSecSuccess)
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "mixed"), .allowAll)
        for daemon in [false, true] {
            XCTAssertThrowsError(try KeychainStore.save(service: service, account: "mixed", value: "v2", daemon: daemon)) { err in
                guard case KeychainError.unattributable = err else { return XCTFail("daemon=\(daemon): got \(err)") }
            }
        }
        XCTAssertEqual(try readOwn(account: "mixed"), "v1")
    }

    func testPrePlantedItemTrustingOnlyUsIsReplacedNotUpdated() throws {
        // Another program can create an item whose decrypt list names only this
        // binary while keeping the owner (ChangeACL) entry for itself. Updating
        // it in place would hand that program the new secret later; `set` must
        // re-create the item so the ACL is ours from scratch.
        let me = URL(fileURLWithPath: Bundle.main.executablePath!).resolvingSymlinksInPath().path
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["add-generic-password", "-s", service, "-a", "planted", "-w", "stale", "-T", me]
        try p.run(); p.waitUntilExit(); XCTAssertEqual(p.terminationStatus, 0)
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "planted"), .own)
        try KeychainStore.save(service: service, account: "planted", value: "fresh")
        XCTAssertEqual(try readOwn(account: "planted"), "fresh")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "planted"), .own)
        // The re-created item is deletable by our own delete path (fresh ACL).
        XCTAssertEqual(try KeychainStore.unset(service: service, account: "planted"), ["planted"])
    }

    func testCoTrustedItemIsForeign() throws {
        // Decrypt ACL trusts `security` AND this binary → not ours (every list must contain us).
        let me = URL(fileURLWithPath: Bundle.main.executablePath!).resolvingSymlinksInPath().path
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["add-generic-password", "-s", service, "-a", "shared", "-w", "stale", "-T", "/usr/bin/security", "-T", me]
        try p.run(); p.waitUntilExit(); XCTAssertEqual(p.terminationStatus, 0)
        guard case .foreign(let owners) = try KeychainStore.inspectExisting(service: service, account: "shared") else {
            return XCTFail("co-trusted item must be foreign")
        }
        XCTAssertTrue(owners.contains("/usr/bin/security"), "owners=\(owners)")
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "shared", value: "fresh"))
        XCTAssertEqual(try readForeign(account: "shared"), "stale")
    }

    func testSaveDaemonSwitchesOwnItemToDaemonReadable() throws {
        // Own prompt-on-read item + --daemon → delete by reference + re-add allow-all.
        try KeychainStore.save(service: service, account: "d", value: "v1")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "d"), .own)
        try KeychainStore.save(service: service, account: "d", value: "v2", daemon: true)
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "d"), .allowAll)
        XCTAssertEqual(try readOwn(account: "d"), "v2")
    }

    func testPlainSetRefusesDaemonItemAndNamesUnset() throws {
        // A daemon item is allow-all and therefore unattributable: switching it back
        // to prompt-on-read is an explicit `unset` then `set`, never a side effect.
        try KeychainStore.save(service: service, account: "d", value: "low", daemon: true)
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "high")) { err in
            guard case KeychainError.unattributable = err else { return XCTFail("expected .unattributable, got \(err)") }
            let msg = (err as? LocalizedError)?.errorDescription ?? ""
            XCTAssertTrue(msg.contains("che-keychain unset --service '\(service)' --account 'd'"), msg)
        }
        XCTAssertEqual(try readOwn(account: "d"), "low")
        try KeychainStore.unset(service: service, account: "d")
        try KeychainStore.save(service: service, account: "d", value: "high")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "d"), .own)
        XCTAssertEqual(try readOwn(account: "d"), "high")
    }

    func testSaveDaemonRefusesExistingDaemonItemAndNamesUnset() throws {
        // Our own daemon item is allow-all and therefore indistinguishable from
        // anyone else's: re-setting it is `unset` then `set --daemon`.
        try KeychainStore.save(service: service, account: "d", value: "v1", daemon: true)
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "v2", daemon: true)) { err in
            guard case KeychainError.unattributable = err else { return XCTFail("expected .unattributable, got \(err)") }
        }
        XCTAssertEqual(try readOwn(account: "d"), "v1")
        XCTAssertEqual(try KeychainStore.unset(service: service, account: "d"), ["d"])
        try KeychainStore.save(service: service, account: "d", value: "v2", daemon: true)
        XCTAssertEqual(try readOwn(account: "d"), "v2", "the headline requirement: the value really changed")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "d"), .allowAll)
    }

    func testPreflightRefusesBeforeAnythingIsWritten() throws {
        // set-pair must refuse up front, not after the first account has landed.
        try seedForeignItem(account: "pass", value: "stale")
        XCTAssertThrowsError(try KeychainStore.preflight(service: service, accounts: ["user", "pass"], daemon: false)) { err in
            guard case KeychainError.foreignOwned(_, let acct, _, _) = err else { return XCTFail("expected .foreignOwned, got \(err)") }
            XCTAssertEqual(acct, "pass")
        }
        XCTAssertFalse(KeychainStore.has(service: service, account: "user"), "preflight must not write")
        XCTAssertNoThrow(try KeychainStore.preflight(service: service, accounts: ["user", "other"], daemon: false))
    }

    func testUnsetRemovesItemsCreatedByOtherProgramsToo() throws {
        // SecItemDelete(query) answers -25244 on a `security`-created item (the
        // old loop stopped there); SecKeychainItemDelete(ref) removes it. `unset`
        // is therefore the remedy `set` names for a foreign item.
        try KeychainStore.save(service: service, account: "mine", value: "x")
        try seedForeignItem(account: "theirs", value: "y")
        XCTAssertEqual(Set(try KeychainStore.unset(service: service)), ["mine", "theirs"])
        XCTAssertFalse(KeychainStore.has(service: service, account: "mine"))
        XCTAssertFalse(KeychainStore.has(service: service, account: "theirs"))
        // and the single-account form on a foreign item alone
        try seedForeignItem(account: "theirs2", value: "z")
        try KeychainStore.unset(service: service, account: "theirs2")
        XCTAssertFalse(KeychainStore.has(service: service, account: "theirs2"))
    }

    func testSaveDaemonRoundTrips() throws {
        // Proves the allow-all SecAccess attaches without SecItemAdd rejecting it
        // at runtime — the legacy-API (kSecAttrAccess) compatibility risk.
        try KeychainStore.save(service: service, account: "daemon", value: "v", daemon: true)
        XCTAssertTrue(KeychainStore.has(service: service, account: "daemon"))
    }
}
