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

    func testNonEmptyProbeDistinguishesMissingEmptyAndPresentWithoutWriting() throws {
        XCTAssertEqual(KeychainStore.nonEmptyStatus(service: service, account: "missing").exitCode, 1)
        for (account, value, expected) in [("empty", "", Int32(2)), ("value", "value", Int32(0)), ("spaces", "   ", Int32(0))] {
            let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                kSecAttrAccount as String: account, kSecValueData as String: Data(value.utf8)]
            XCTAssertEqual(SecItemAdd(q as CFDictionary, nil), errSecSuccess)
            XCTAssertEqual(KeychainStore.nonEmptyStatus(service: service, account: account).exitCode, expected)
            XCTAssertTrue(KeychainStore.has(service: service, account: account), "probe must not remove an empty item")
        }
    }

    func testNonEmptyProbeRefusesForeignAndAllowAllWithoutChangingThem() throws {
        try seedForeignItem(account: "foreign", value: "value")
        XCTAssertEqual(KeychainStore.nonEmptyStatus(service: service, account: "foreign").exitCode, 3)
        XCTAssertEqual(try readForeign(account: "foreign"), "value")
        try KeychainStore.save(service: service, account: "daemon", value: "value", daemon: true)
        XCTAssertEqual(KeychainStore.nonEmptyStatus(service: service, account: "daemon").exitCode, 3)
        XCTAssertEqual(try readOwn(account: "daemon"), "value")
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
            }
            XCTAssertThrowsError(try KeychainStore.preflight(service: service, accounts: [acct]))
            XCTAssertEqual(try readForeign(account: acct), "stale", "nothing may touch \(acct)")
        }
    }

    func testMixedACLWithAllowAllEntryIsNotOwn() throws {
        // Our own item whose decrypt ACL later gained an allow-all entry (what the
        // round-1 build did via SecItemUpdate + kSecAttrAccess union). Round 4
        // dropped such entries and judged the item .own; it must be .allowAll.
        // Construct the mixed ACL directly. Mutating an existing default
        // owner ACL through SecItemUpdate can wait for SecurityAgent input.
        var me: SecTrustedApplication?
        XCTAssertEqual(SecTrustedApplicationCreateFromPath(nil, &me), errSecSuccess)
        var access: SecAccess?
        XCTAssertEqual(SecAccessCreate("mixed fixture" as CFString, [me!] as CFArray, &access), errSecSuccess)
        var extra: SecACL?
        XCTAssertEqual(SecACLCreateWithSimpleContents(access!, nil, "allow-all entry" as CFString, SecKeychainPromptSelector(rawValue: 0), &extra), errSecSuccess)
        XCTAssertEqual(SecACLUpdateAuthorizations(extra!, [kSecACLAuthorizationDecrypt] as CFArray), errSecSuccess)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: "mixed", kSecValueData as String: Data("v1".utf8), kSecAttrAccess as String: access!]
        XCTAssertEqual(SecItemAdd(q as CFDictionary, nil), errSecSuccess)
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

    func testPreflightReturnsEachAccountsExistenceWithoutShortCircuiting() throws {
        for first in [false, true] {
            for second in [false, true] {
                try KeychainStore.unset(service: service)
                if first { try KeychainStore.save(service: service, account: "id", value: "first") }
                if second { try KeychainStore.save(service: service, account: "secret", value: "second") }
                let states = try KeychainStore.preflight(service: service, accounts: ["id", "secret"])
                XCTAssertEqual(states, ["id": first, "secret": second])
            }
        }
    }

    func testPreflightRefusesBeforeAnythingIsWritten() throws {
        // set-pair must refuse up front, not after the first account has landed.
        try seedForeignItem(account: "pass", value: "stale")
        XCTAssertThrowsError(try KeychainStore.preflight(service: service, accounts: ["user", "pass"])) { err in
            guard case KeychainError.foreignOwned(_, let acct, _, _) = err else { return XCTFail("expected .foreignOwned, got \(err)") }
            XCTAssertEqual(acct, "pass")
        }
        XCTAssertFalse(KeychainStore.has(service: service, account: "user"), "preflight must not write")
        XCTAssertNoThrow(try KeychainStore.preflight(service: service, accounts: ["user", "other"]))
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

    func testARefusalToCleanUpNeverTellsTheUserToDeleteAnything() {
        // The destination may hold another writer's credential, so the report
        // must not hand out an `unset` for it, and must not pretend a deletion
        // was attempted and failed.
        let outcome = MismatchCleanup.removalNotAttempted(.writeNotAttributable, previousReplaced: false)
        XCTAssertEqual(outcome.exitCode, 1, "not attempting a delete is not proof of a stuck bad item")
        let report = KeychainError.storedValueMismatch(service: "s", account: "a", reason: .differs, cleanup: outcome).errorDescription ?? ""
        XCTAssertFalse(report.contains("che-keychain unset"), report)
        XCTAssertFalse(report.contains("OSStatus"), report)
        XCTAssertTrue(report.contains("cannot be proven to be this write"), report)
    }

    func testAmbiguousReadBackDoesNotSuggestUnlockingTheKeychain() {
        let error = KeychainError.storedValueMismatch(service: "s", account: "a", reason: .ambiguous, cleanup: .leftInPlace(previousReplaced: false))
        let message = error.errorDescription ?? ""
        XCTAssertFalse(message.lowercased().contains("unlock"), message)
        XCTAssertTrue(message.contains("Keychain Access"), message)
    }

    func testAFailedReaddDoesNotClaimAnEmptySlot() {
        let msg = KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: .lost(.readdFailed(-25299))).errorDescription ?? ""
        XCTAssertFalse(msg.contains("now absent"), msg)
        XCTAssertTrue(msg.contains("state is unknown") && msg.contains("-25299"), msg)
        let missing = KeychainError.storedValueMismatch(service: "s", account: "a", reason: .missing, cleanup: .nothingStored(previousReplaced: false)).errorDescription ?? ""
        XCTAssertTrue(missing.contains("outside the search list"), missing)
    }

    func testAnAmbiguousRestoreIsNotAnsweredByUnlockingTheKeychain() {
        // Two items match: unlocking cannot resolve that, so it must not be the
        // advice. The same outcome with `.unreadable` is answered by unlocking.
        let ambiguous = KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308,
                                                    restore: .restoredUnverified(.ambiguous)).errorDescription ?? ""
        XCTAssertFalse(ambiguous.lowercased().contains("unlock"), ambiguous)
        XCTAssertTrue(ambiguous.contains("Keychain Access"), ambiguous)
        let locked = KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308,
                                                 restore: .restoredUnverified(.unreadable)).errorDescription ?? ""
        XCTAssertTrue(locked.lowercased().contains("unlock"), locked)
    }

    // MARK: - Read-back verification (#6)

    func testSaveRejectsEmptyValue() throws {
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "e", value: " \n\t")) { err in
            guard case KeychainError.emptyValue = err else { return XCTFail("whitespace-only: expected .emptyValue, got \(err)") }
        }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "e", value: "")) { err in
            guard case KeychainError.emptyValue = err else { return XCTFail("expected .emptyValue, got \(err)") }
        }
        XCTAssertFalse(KeychainStore.has(service: service, account: "e"), "an empty value must never create an item")
        // The same guard protects the daemon path.
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "e", value: "", daemon: true))
        XCTAssertFalse(KeychainStore.has(service: service, account: "e"))
    }

    private func resetSeams() {
        KeychainStore.readBackOverride = nil
        KeychainStore.readBackReasonOverride = nil
        KeychainStore.addRawStatusOverride = nil
        KeychainStore.afterInspectHook = nil
        KeychainStore.afterAddHook = nil
    }

    /// The item reference currently carrying this service/account, or nil.
    private func currentItem(account: String) -> SecKeychainItem? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitOne, kSecReturnRef as String: true
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let ref = out, CFGetTypeID(ref) == SecKeychainItemGetTypeID() else { return nil }
        return (ref as! SecKeychainItem)
    }

    /// Stands in for another process writing the same service/account: the
    /// destination is deleted and recreated, so a name lookup finds an item that
    /// this binary could also have written.
    private func competitorReplaces(account: String, with value: String) {
        if let item = currentItem(account: account) { XCTAssertEqual(SecKeychainItemDelete(item), errSecSuccess) }
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: account, kSecValueData as String: Data(value.utf8)
        ]
        XCTAssertEqual(SecItemAdd(q as CFDictionary, nil), errSecSuccess)
    }

    // MARK: - #7 H2: nothing at the destination is deleted once the add succeeded

    func testProvenBadValueIsLeftInPlaceBecauseItCannotBeAttributedToThisWrite() throws {
        defer { resetSeams() }
        for (name, fake) in [("empty", Data()), ("differs", Data("other".utf8))] {
            KeychainStore.readBackOverride = { _, _ in fake }
            XCTAssertThrowsError(try KeychainStore.save(service: service, account: name, value: "v")) { err in
                guard case KeychainError.storedValueMismatch(_, _, let reason, let cleanup) = err else {
                    return XCTFail("\(name): got \(err)")
                }
                XCTAssertEqual(reason.rawValue, name)
                XCTAssertEqual(cleanup, .removalNotAttempted(.writeNotAttributable, previousReplaced: false))
                XCTAssertEqual(cleanup.exitCode, 1, "a refusal to clean up is not a proven stuck item")
            }
            XCTAssertTrue(KeychainStore.has(service: service, account: name),
                          "\(name): the destination must be left alone — it cannot be proven to be our write")
        }
    }

    func testAnItemAnotherWriterRecreatedSurvivesAndTheBackupIsNotPutBackOverIt() throws {
        defer { resetSeams() }
        try KeychainStore.save(service: service, account: "own", value: "v1")
        // Between our add and our read-back, another writer replaces the
        // destination. The old cleanup compared two name lookups and required
        // `.own` — both of which this interleaving satisfies.
        KeychainStore.afterAddHook = { [weak self] _, account in
            self?.competitorReplaces(account: account, with: "competitor")
            self?.resetSeams()          // fire once
        }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "own", value: "v2")) { err in
            guard case KeychainError.storedValueMismatch(_, _, .differs, let cleanup) = err else {
                return XCTFail("got \(err)")
            }
            XCTAssertEqual(cleanup, .removalNotAttempted(.writeNotAttributable, previousReplaced: true))
        }
        resetSeams()
        XCTAssertEqual(try readOwn(account: "own"), "competitor",
                       "the other writer's credential must survive, and our older backup must not be written over it")
    }

    // MARK: - #7 H1: the widening decision comes from the backup, not the first inspection

    func testWideningIsRefusedWhenTheAccessIsTightenedAfterTheFirstInspection() throws {
        defer { resetSeams() }
        // An allow-all item this binary owns, so the interleaving below can change
        // its access without needing anyone else's authorization.
        try KeychainStore.save(service: service, account: "rot", value: "v1", daemon: true)
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "rot"), .allowAll)
        // After the classification and before the backup, another writer tightens
        // the ACL in place: the reference and the bytes do not change, so every
        // later equality check still passes and only the captured access differs.
        KeychainStore.afterInspectHook = { [weak self] _, account in
            guard let self, let item = self.currentItem(account: account) else { return XCTFail("no item") }
            var me: SecTrustedApplication?
            XCTAssertEqual(SecTrustedApplicationCreateFromPath(nil, &me), errSecSuccess)
            // `SecKeychainItemSetAccess` merges: handing it a fresh access leaves
            // the existing allow-all entry in place, so the item would still be
            // readable by everything. Narrow the entry that is already there.
            var access: SecAccess?
            XCTAssertEqual(SecKeychainItemCopyAccess(item, &access), errSecSuccess)
            var list: CFArray?
            XCTAssertEqual(SecAccessCopyACLList(access!, &list), errSecSuccess)
            for acl in (list as! [SecACL]) {
                let auths = (SecACLCopyAuthorizations(acl) as? [String]) ?? []
                guard auths.contains(kSecACLAuthorizationDecrypt as String) else { continue }
                XCTAssertEqual(SecACLSetContents(acl, [me!] as CFArray, "tightened" as CFString,
                                                 SecKeychainPromptSelector(rawValue: 0)), errSecSuccess)
            }
            XCTAssertEqual(SecKeychainItemSetAccess(item, access!), errSecSuccess)
            XCTAssertEqual(try? KeychainStore.inspectExisting(service: self.service, account: account), .own,
                           "the fixture must really have tightened the ACL")
            KeychainStore.afterInspectHook = nil
        }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "rot", value: "v2",
                                                   daemon: true, mayWidenExistingACL: false,
                                                   allowReplacement: true)) { err in
            guard case KeychainError.aclWideningRefused = err else {
                return XCTFail("a stdin --daemon replacement must not widen an ACL that is no longer allow-all; got \(err)")
            }
        }
        XCTAssertEqual(try readOwn(account: "rot"), "v1", "and the original item is untouched")
    }

    func testAnAllowAllEntryMixedWithNamedApplicationsStillRotates() throws {
        // allow-all + another application in one ACL classifies foreign, but the
        // item is already readable by everything: rotating it widens nothing.
        var me: SecTrustedApplication?; var other: SecTrustedApplication?
        XCTAssertEqual(SecTrustedApplicationCreateFromPath(nil, &me), errSecSuccess)
        XCTAssertEqual(SecTrustedApplicationCreateFromPath("/usr/bin/security", &other), errSecSuccess)
        var access: SecAccess?
        XCTAssertEqual(SecAccessCreate("mixed allow-all" as CFString, [me!, other!] as CFArray, &access), errSecSuccess)
        var extra: SecACL?
        XCTAssertEqual(SecACLCreateWithSimpleContents(access!, nil, "allow-all entry" as CFString,
                                                      SecKeychainPromptSelector(rawValue: 0), &extra), errSecSuccess)
        XCTAssertEqual(SecACLUpdateAuthorizations(extra!, [kSecACLAuthorizationDecrypt] as CFArray), errSecSuccess)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: "mixed", kSecValueData as String: Data("old".utf8), kSecAttrAccess as String: access!]
        XCTAssertEqual(SecItemAdd(q as CFDictionary, nil), errSecSuccess)
        guard case .foreign = try KeychainStore.inspectExisting(service: service, account: "mixed") else {
            return XCTFail("fixture should classify foreign — that is the point")
        }
        try KeychainStore.save(service: service, account: "mixed", value: "new",
                               daemon: true, mayWidenExistingACL: false, allowReplacement: true)
        XCTAssertEqual(try readOwn(account: "mixed"), "new")
    }

    func testSaveReportsWhatWasEstablishedWithoutTouchingTheDestination() throws {
        defer { resetSeams() }
        // A proven bad value is still left alone: a name lookup cannot show the
        // item is this write, so removing it could destroy someone else's.
        for (name, fake) in [("empty", Data()), ("differs", Data("other".utf8))] {
            KeychainStore.readBackOverride = { _, _ in fake }
            XCTAssertThrowsError(try KeychainStore.save(service: service, account: name, value: "v")) { err in
                guard case KeychainError.storedValueMismatch(_, let acct, let reason, let cleanup) = err else {
                    return XCTFail("\(name): expected .storedValueMismatch, got \(err)")
                }
                XCTAssertEqual(acct, name)
                XCTAssertEqual(reason.rawValue, name)
                XCTAssertEqual(cleanup, .removalNotAttempted(.writeNotAttributable, previousReplaced: false))
            }
            XCTAssertTrue(KeychainStore.has(service: service, account: name), "\(name): the destination is left alone")
        }
        // An unreadable read-back proves nothing about the item: it stays, and the message says so.
        KeychainStore.readBackOverride = nil
        KeychainStore.readBackReasonOverride = { _, _ in .unreadable }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "locked", value: "v")) { err in
            guard case KeychainError.storedValueMismatch(_, _, let reason, let cleanup) = err else { return XCTFail("got \(err)") }
            XCTAssertEqual(reason, .unreadable)
            XCTAssertEqual(cleanup, .leftInPlace(previousReplaced: false))
        }
        XCTAssertTrue(KeychainStore.has(service: service, account: "locked"), "an unreadable item is not deleted")
        resetSeams()
        XCTAssertEqual(try readOwn(account: "locked"), "v", "and it was in fact stored correctly")
        // Missing after a successful write: reported as nothing stored.
        KeychainStore.readBackOverride = { _, _ in nil }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "gone", value: "v")) { err in
            guard case KeychainError.storedValueMismatch(_, _, let reason, let cleanup) = err else { return XCTFail("got \(err)") }
            XCTAssertEqual(reason, .missing); XCTAssertEqual(cleanup, .nothingStored(previousReplaced: false))
        }
        resetSeams(); KeychainStore.readBackReasonOverride = { _, _ in .ambiguous }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "amb", value: "v")) { err in
            guard case KeychainError.storedValueMismatch(_, _, .ambiguous, .leftInPlace(previousReplaced: false)) = err else { return XCTFail("got \(err)") }
        }
    }

    func testARotationWhoseNewValueReadsBackWrongLeavesTheDestinationAlone() throws {
        defer { resetSeams() }
        try KeychainStore.save(service: service, account: "own", value: "v1")
        KeychainStore.readBackOverride = { _, _ in Data("garbage".utf8) }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "own", value: "v2")) { err in
            guard case KeychainError.storedValueMismatch(_, _, .differs, let cleanup) = err else { return XCTFail("got \(err)") }
            XCTAssertEqual(cleanup, .removalNotAttempted(.writeNotAttributable, previousReplaced: true))
            XCTAssertEqual(cleanup.exitCode, 1, "the new value is NOT proven to be in the slot — not exit 3")
            let msg = (err as? LocalizedError)?.errorDescription ?? ""
            XCTAssertTrue(msg.contains("has not been restored"), msg)
        }
        resetSeams()
        XCTAssertEqual(try readOwn(account: "own"), "v2",
                       "what the keychain accepted stays; the older backup is not written over it")
    }

    func testAFailedAddRestoresThePreviousValueIntoTheEmptiedSlot() throws {
        defer { resetSeams() }
        try KeychainStore.save(service: service, account: "own", value: "v1")
        // The new add fails outright — the one case where a backup may still go back.
        var calls = 0
        KeychainStore.addRawStatusOverride = { _, _, _ in calls += 1; return calls == 1 ? errSecDuplicateItem : nil }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "own", value: "v2")) { err in
            guard case KeychainError.replaceFailed(_, _, _, let restore) = err else { return XCTFail("got \(err)") }
            XCTAssertEqual(restore, .restored)
        }
        resetSeams()
        XCTAssertEqual(try readOwn(account: "own"), "v1", "the previous secret survives a failed add")
    }

    func testAFailedAddDoesNotWriteTheBackupOverSomethingElse() throws {
        defer { resetSeams() }
        try KeychainStore.save(service: service, account: "own", value: "v1")
        // The new add fails, and by the time the restore runs another writer has
        // taken the destination. The backup must not be written over it.
        var calls = 0
        KeychainStore.addRawStatusOverride = { [weak self] _, account, _ in
            calls += 1
            guard calls == 1 else { return nil }
            self?.competitorReplaces(account: account, with: "theirs")
            return errSecDuplicateItem
        }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "own", value: "v2")) { err in
            guard case KeychainError.replaceFailed(_, _, _, let restore) = err else { return XCTFail("got \(err)") }
            XCTAssertEqual(restore, .lost(.destinationOccupied))
            let msg = (err as? LocalizedError)?.errorDescription ?? ""
            XCTAssertTrue(msg.contains("left untouched"), msg)
        }
        resetSeams()
        XCTAssertEqual(try readOwn(account: "own"), "theirs", "the other writer's item is intact")
    }

    func testRotationUnreadableReadBackSaysThePreviousValueWasReplaced() throws {
        defer { resetSeams() }
        try KeychainStore.save(service: service, account: "own", value: "v1")
        KeychainStore.readBackReasonOverride = { _, _ in .unreadable }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "own", value: "v2")) { err in
            guard case KeychainError.storedValueMismatch(_, _, .unreadable, .leftInPlace(previousReplaced: true)) = err else { return XCTFail("got \(err)") }
            let msg = (err as? LocalizedError)?.errorDescription ?? ""
            XCTAssertTrue(msg.contains("previous value is GONE"), msg)
        }
        resetSeams()
        XCTAssertEqual(try readOwn(account: "own"), "v2", "the new value is in place (unverified at the time)")
    }

    func testSaveReadsBackWhatItWroteInBothModes() throws {
        // No override: the real read-back must agree, for prompt-on-read and allow-all items.
        try KeychainStore.save(service: service, account: "p", value: "plain-value")
        XCTAssertEqual(try readOwn(account: "p"), "plain-value")
        try KeychainStore.save(service: service, account: "d", value: "daemon-value", daemon: true)
        XCTAssertEqual(try readOwn(account: "d"), "daemon-value")
    }

    // MARK: - Failure-path messages (pure string logic, no keychain)

    func testUndeletableMessageNamesEveryRefusedItemHonestly() {
        let err = KeychainError.undeletable(service: "svc", deleted: ["a"], refused: [
            ("b", "OSStatus -25244 (owner edit)", true),
            ("", "OSStatus -25244", true),
            ("c\u{1b}[2J", "OSStatus -25244", true),
            ("d", "iCloud-synchronized item; SecItemDelete answered OSStatus -25308", false)
        ])
        let msg = err.errorDescription ?? ""
        XCTAssertTrue(msg.contains("removed 1 account(s): a"), msg)
        XCTAssertTrue(msg.contains("security delete-generic-password -s 'svc' -a 'b'"), msg)
        XCTAssertTrue(msg.contains("(account attribute missing)") && msg.contains("security delete-generic-password -s 'svc'   #"), msg)
        XCTAssertFalse(msg.contains("\u{1b}"), "control characters must not reach the terminal")
        XCTAssertTrue(msg.contains("contains control characters; remove it in Keychain Access"), msg)
        XCTAssertFalse(msg.contains("-a 'c"), "no copy-paste command for a name we cannot show faithfully")
        XCTAssertTrue(msg.contains("d: iCloud-synchronized item") && msg.contains("Keychain Access"), msg)
    }

    func testReplaceFailedMessageSaysWhatHappenedToTheOldValue() {
        func msg(_ r: RestoreOutcome) -> String { KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: r).errorDescription ?? "" }
        let ok = msg(.restored)
        XCTAssertTrue(ok.contains("re-stored as a prompt-on-read item") && ok.contains("and read back") && ok.contains("-25308"), ok)
        let unverified = msg(.restoredUnverified(.unreadable))
        XCTAssertTrue(unverified.contains("could not be read back to prove it") && !unverified.contains("now absent"), unverified)
        let lost = msg(.lost(.readdFailed(-25293)))
        XCTAssertTrue(lost.contains("could NOT be restored") && lost.contains("state is unknown") && !lost.contains("now absent") && lost.contains("-25293"), lost)
        let wrong = msg(.mismatch(.differs))
        XCTAssertTrue(wrong.contains("reads back differs") && wrong.contains("unset"), wrong)
    }

    func testEveryKeychainErrorCarriesItsExitCode() {
        // One accessor for the CLI, so a future error case cannot silently miss the mapping.
        XCTAssertEqual(KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: .mismatch(.differs)).exitCode, 4)
        XCTAssertEqual(KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: .restored).exitCode, 1)
        XCTAssertEqual(KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: .restoredUnverified(.unreadable)).exitCode, 1)
        XCTAssertEqual(KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: .lost(.readdVanished)).exitCode, 1)
        XCTAssertEqual(KeychainError.storedValueMismatch(service: "s", account: "a", reason: .unreadable, cleanup: .leftInPlace(previousReplaced: false)).exitCode, 3)
        XCTAssertEqual(KeychainError.storedValueMismatch(service: "s", account: "a", reason: .differs, cleanup: .removalNotAttempted(.writeNotAttributable, previousReplaced: false)).exitCode, 1)
        XCTAssertEqual(KeychainError.explicitReplacementFailed(service: "s", account: "a", detail: "d", recovery: .mismatch).exitCode, 4)
        XCTAssertEqual(KeychainError.aclWideningRefused(service: "s", account: "a").exitCode, 1)
        XCTAssertEqual(KeychainError.notFound.exitCode, 1)
    }

    func testSaveRefusesWhenTheDestinationChangedSinceTheDialog() throws {
        // The clipboard dialog says "New item" / "ALREADY EXISTS" from a pre-write
        // probe; the write must refuse if reality differs at write time.
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "v", expectingExisting: true)) { err in
            guard case KeychainError.destinationChanged(_, _, true) = err else { return XCTFail("got \(err)") }
        }
        XCTAssertFalse(KeychainStore.has(service: service, account: "d"))
        try KeychainStore.save(service: service, account: "d", value: "v", expectingExisting: false)
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "v2", expectingExisting: false)) { err in
            guard case KeychainError.destinationChanged(_, _, false) = err else { return XCTFail("got \(err)") }
        }
        XCTAssertEqual(try readOwn(account: "d"), "v", "untouched")
        try KeychainStore.save(service: service, account: "d", value: "v3", expectingExisting: true)
        XCTAssertEqual(try readOwn(account: "d"), "v3")
    }

    func testCleanupOutcomesMapToExitCodesByWhetherTheNewValueLanded() {
        // 1: the new value is NOT proven to be in the slot. 3: it is, unverified.
        for c in [MismatchCleanup.nothingStored(previousReplaced: false), .nothingStored(previousReplaced: true),
                  .removalNotAttempted(.writeNotAttributable, previousReplaced: false),
                  .removalNotAttempted(.writeNotAttributable, previousReplaced: true)] {
            XCTAssertEqual(c.exitCode, 1, "\(c)")
        }
        XCTAssertEqual(MismatchCleanup.leftInPlace(previousReplaced: false).exitCode, 3)
        XCTAssertEqual(MismatchCleanup.leftInPlace(previousReplaced: true).exitCode, 3)
    }

    func testExitFourHasOneMeaningAcrossEveryPathThatCanProduceIt() {
        // 4 says one thing: a restore was accepted whose bytes or access settings
        // do not match the backup. Nothing else returns it, so the help text and
        // the documentation can state it without qualification (#7 M2 / #15).
        XCTAssertEqual(KeychainError.explicitReplacementFailed(service: "s", account: "a", detail: "d", recovery: .mismatch).exitCode, 4)
        XCTAssertEqual(KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: .mismatch(.differs)).exitCode, 4)
        for recovery: ExplicitRestoreOutcome in [.restored, .unverified, .preparationFailed, .failed(-25308), .destinationOccupied, .notAttempted] {
            XCTAssertEqual(KeychainError.explicitReplacementFailed(service: "s", account: "a", detail: "d", recovery: recovery).exitCode, 1, "\(recovery)")
        }
    }

    func testLeftInPlaceAfterRotationSaysThePreviousValueIsGone() {
        // This arm never restores anything: the new (unverified) item occupies the slot.
        let msg = KeychainError.storedValueMismatch(service: "s", account: "a", reason: .unreadable, cleanup: .leftInPlace(previousReplaced: true)).errorDescription ?? ""
        XCTAssertTrue(msg.contains("previous value is GONE") && msg.contains("nothing was put back"), msg)
        XCTAssertFalse(msg.contains("re-stored"), msg)
    }

    func testAFailedAddThatRestoredSaysAttributesWereNotPreserved() {
        // The one path that still puts a backup back: the add failed outright.
        let msg = KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: .restored).errorDescription ?? ""
        XCTAssertTrue(msg.contains("not preserved"), msg)
    }

    func testAFailedRestoreNamesTheActualLoss() {
        func msg(_ l: RestoreLoss) -> String { KeychainError.replaceFailed(service: "s", account: "a", addStatus: -25308, restore: .lost(l)).errorDescription ?? "" }
        XCTAssertTrue(msg(.previousUnreadable).contains("could not be read before the replace"))
        XCTAssertTrue(msg(.previousEmpty).contains("was itself empty"))
        XCTAssertTrue(msg(.readdFailed(-25293)).contains("re-add") && msg(.readdFailed(-25293)).contains("-25293"))
        XCTAssertTrue(msg(.readdVanished).contains("accepted the re-add") && msg(.readdVanished).contains("no item exists"))
        XCTAssertTrue(msg(.destinationOccupied).contains("never write over it") && msg(.destinationOccupied).contains("left untouched"))
    }

    func testSaveWithoutACLWideningRefusesToTurnAnOwnItemDaemonReadable() throws {
        // The --stdin path: no dialog, so an existing prompt-on-read item must not
        // be re-created allow-all. Decided in save() itself, at write time.
        try KeychainStore.save(service: service, account: "own", value: "v1")
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "own", value: "v2", daemon: true, mayWidenExistingACL: false)) { err in
            guard case KeychainError.aclWideningRefused(let s, let a) = err else { return XCTFail("got \(err)") }
            XCTAssertEqual(s, service); XCTAssertEqual(a, "own")
            let msg = (err as? LocalizedError)?.errorDescription ?? ""
            XCTAssertTrue(msg.contains("without any dialog") && msg.contains("che-keychain unset"), msg)
        }
        XCTAssertEqual(try readOwn(account: "own"), "v1", "the item is untouched")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "own"), .own, "and still prompt-on-read")
        // A NEW item may still be created allow-all from stdin (documented decision).
        try KeychainStore.save(service: service, account: "fresh", value: "v", daemon: true, mayWidenExistingACL: false)
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "fresh"), .allowAll)
        // Same-mode rotation of an own item stays allowed without widening.
        try KeychainStore.save(service: service, account: "own", value: "v3", daemon: false, mayWidenExistingACL: false)
        XCTAssertEqual(try readOwn(account: "own"), "v3")
    }

    func testForeignOwnedMessageQuotesTheRemedyAndCapsOwners() {
        let owners = (1...12).map { "/Applications/App\($0).app" }
        let msg = KeychainError.foreignOwned(service: "my svc", account: "a'b", owners: owners, selfPath: "/me").errorDescription ?? ""
        XCTAssertTrue(msg.contains("che-keychain unset --service 'my svc' --account 'a'\\''b'"), msg)
        XCTAssertTrue(msg.contains("… and 4 more"), msg)
    }

    func testExplicitReplaceHandlesReadableForeignACLWithFreshAccess() throws {
        var me: SecTrustedApplication?; var other: SecTrustedApplication?
        XCTAssertEqual(SecTrustedApplicationCreateFromPath(nil, &me), errSecSuccess)
        XCTAssertEqual(SecTrustedApplicationCreateFromPath("/usr/bin/security", &other), errSecSuccess)
        var access: SecAccess?
        XCTAssertEqual(SecAccessCreate("foreign fixture" as CFString, [me!, other!] as CFArray, &access), errSecSuccess)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: "shared", kSecValueData as String: Data("old".utf8), kSecAttrAccess as String: access!]
        XCTAssertEqual(SecItemAdd(q as CFDictionary, nil), errSecSuccess)
        guard case .foreign = try KeychainStore.inspectExisting(service: service, account: "shared") else { return XCTFail() }
        try KeychainStore.save(service: service, account: "shared", value: "new", allowReplacement: true)
        XCTAssertEqual(try readOwn(account: "shared"), "new")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "shared"), .own)
    }

    func testExplicitReplaceRejectsUnrepresentableOwnerACLBeforeDeletion() throws {
        try KeychainStore.save(service: service, account: "d", value: "old", daemon: true)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: "d", kSecReturnRef as String: true]
        var out: CFTypeRef?; XCTAssertEqual(SecItemCopyMatching(q as CFDictionary, &out), errSecSuccess)
        let item = out as! SecKeychainItem
        var access: SecAccess?; XCTAssertEqual(SecKeychainItemCopyAccess(item, &access), errSecSuccess)
        var extra: SecACL?
        XCTAssertEqual(SecACLCreateWithSimpleContents(access!, nil, "additional control" as CFString, SecKeychainPromptSelector(rawValue: 0), &extra), errSecSuccess)
        XCTAssertEqual(SecACLUpdateAuthorizations(extra!, [kSecACLAuthorizationChangeACL] as CFArray), errSecSuccess)
        XCTAssertEqual(SecKeychainItemSetAccess(item, access!), errSecSuccess)
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "new", daemon: true, allowReplacement: true)) { error in
            XCTAssertTrue(error.localizedDescription.contains("no deletion was attempted"), error.localizedDescription)
        }
        XCTAssertEqual(try readOwn(account: "d"), "old")
    }

    func testExplicitReplaceRotatesAllowAllWithoutWideningFromStdin() throws {
        try KeychainStore.save(service: service, account: "d", value: "old", daemon: true)
        try KeychainStore.save(service: service, account: "d", value: "new", daemon: true, mayWidenExistingACL: false, allowReplacement: true)
        XCTAssertEqual(try readOwn(account: "d"), "new")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "d"), .allowAll)
    }

    func testExplicitReplaceRequiresReadableBackupBeforeDeletingForeignItem() throws {
        try seedForeignItem(account: "foreign", value: "old")
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "foreign", value: "new", allowReplacement: true)) { error in
            XCTAssertTrue(error.localizedDescription.contains("backup"), error.localizedDescription)
        }
        XCTAssertEqual(try readForeign(account: "foreign"), "old")
    }

    func testExplicitReplaceLeavesTheDestinationAloneAfterABadReadBack() throws {
        // The keychain accepted the write, so the item now at the destination
        // cannot be shown to be ours: it is neither removed nor overwritten with
        // the backup, and the report says which of those did not happen (#7 H2).
        try KeychainStore.save(service: service, account: "d", value: "old", daemon: true)
        defer { resetSeams() }
        KeychainStore.readBackOverride = { _, _ in Data("bad".utf8) }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "new", daemon: true, allowReplacement: true)) { error in
            guard case KeychainError.storedValueMismatch(_, _, .differs, let cleanup) = error else { return XCTFail("got \(error)") }
            XCTAssertEqual(cleanup, .removalNotAttempted(.writeNotAttributable, previousReplaced: true))
            let msg = error.localizedDescription
            XCTAssertTrue(msg.contains("cannot be proven to be this write"), msg)
            XCTAssertFalse(msg.contains("were restored and verified"), msg)
        }
        resetSeams()
        XCTAssertEqual(try readOwn(account: "d"), "new", "what the keychain accepted stays where it is")
    }

    func testExplicitReplaceRestoresOriginalAfterNewAddFails() throws {
        try KeychainStore.save(service: service, account: "d", value: "old", daemon: true)
        defer { resetSeams() }
        KeychainStore.addRawStatusOverride = { _, _, data in data == Data("new".utf8) ? errSecNotAvailable : nil }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "new", daemon: true, allowReplacement: true)) { error in
            XCTAssertTrue(error.localizedDescription.contains("restored and verified"), error.localizedDescription)
        }
        resetSeams()
        XCTAssertEqual(try readOwn(account: "d"), "old")
        XCTAssertEqual(try KeychainStore.inspectExisting(service: service, account: "d"), .allowAll)
    }

    func testExplicitReplaceDoesNotClaimRecoveryWhenRestoringAlsoFails() throws {
        try KeychainStore.save(service: service, account: "d", value: "old", daemon: true)
        defer { resetSeams() }
        KeychainStore.addRawStatusOverride = { _, _, _ in errSecNotAvailable }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "new", daemon: true, allowReplacement: true)) { error in
            XCTAssertTrue(error.localizedDescription.contains("could NOT be restored"), error.localizedDescription)
            XCTAssertFalse(error.localizedDescription.contains("restored and verified"), error.localizedDescription)
        }
        XCTAssertFalse(KeychainStore.has(service: service, account: "d"))
    }

    func testExplicitReplaceLeavesUnverifiableNewItemUntouched() throws {
        try KeychainStore.save(service: service, account: "d", value: "old", daemon: true)
        defer { resetSeams() }
        KeychainStore.readBackReasonOverride = { _, _ in .unreadable }
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "d", value: "new", daemon: true, allowReplacement: true)) { error in
            XCTAssertEqual((error as? KeychainError)?.exitCode, 3)
        }
        resetSeams()
        XCTAssertEqual(try readOwn(account: "d"), "new")
    }

    func testExplicitReplaceDoesNotBypassStdinWideningGuard() throws {
        try KeychainStore.save(service: service, account: "own", value: "old")
        XCTAssertThrowsError(try KeychainStore.save(service: service, account: "own", value: "new", daemon: true, mayWidenExistingACL: false, allowReplacement: true)) { error in
            guard case KeychainError.aclWideningRefused = error else { return XCTFail("unexpected error: \(error)") }
        }
        XCTAssertEqual(try readOwn(account: "own"), "old")
    }

    func testSaveDaemonRoundTrips() throws {
        // Proves the allow-all SecAccess attaches without SecItemAdd rejecting it
        // at runtime — the legacy-API (kSecAttrAccess) compatibility risk.
        try KeychainStore.save(service: service, account: "daemon", value: "v", daemon: true)
        XCTAssertTrue(KeychainStore.has(service: service, account: "daemon"))
    }
}
