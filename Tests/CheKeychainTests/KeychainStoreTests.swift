import XCTest
@testable import CheKeychain

final class KeychainStoreTests: XCTestCase {
    // Use a UUID-suffixed service so test runs never collide with real entries
    // or leave permanent residue if a test fails partway through.
    private var service: String { "che-keychain-test-\(testRunID)" }
    private var testRunID: String!

    override func setUp() {
        super.setUp()
        testRunID = UUID().uuidString
    }

    override func tearDown() {
        try? KeychainStore.unset(service: service)
        // Foreign-owned items (seeded via `security`, see #5) can't be deleted by this
        // binary — errSecInvalidOwnerEdit. Sweep them with the CLI that owns them.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["delete-generic-password", "-s", service]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try? p.run(); p.waitUntilExit()
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
        // We don't expose read in this API (intentional — caller shouldn't), so verify
        // overwrite by re-checking that the entry still exists after both writes.
        XCTAssertTrue(KeychainStore.has(service: service, account: "a"))
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

    func testUnsetMissingIsNotError() {
        XCTAssertNoThrow(try KeychainStore.unset(service: service, account: "never-existed"))
    }

    // MARK: - Foreign-owned items (#5)
    //
    // An item created by another binary (here: the `security` CLI) has a different
    // keychain owner. SecItemDelete on it returns errSecInvalidOwnerEdit (-25244),
    // so the old delete-then-add strategy could never overwrite it — SecItemAdd
    // then failed with errSecDuplicateItem (-25299). SecItemUpdate is allowed.

    /// Creates an item owned by the `security` CLI, not by this test binary.
    private func seedForeignItem(account: String, value: String) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["add-generic-password", "-s", service, "-a", account, "-w", value]
        try p.run(); p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0, "security add-generic-password failed")
    }

    /// Reads a value back through the `security` CLI — the store deliberately has no read API.
    private func readForeign(account: String) throws -> String {
        let p = Process(); let out = Pipe()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["find-generic-password", "-s", service, "-a", account, "-w"]
        p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        return String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func testSaveOverwritesForeignOwnedItem() throws {
        try seedForeignItem(account: "foreign", value: "stale")
        try KeychainStore.save(service: service, account: "foreign", value: "fresh")
        XCTAssertEqual(try readForeign(account: "foreign"), "fresh")
    }

    func testSaveDaemonRoundTrips() throws {
        // Proves the allow-all SecAccess attaches without SecItemAdd rejecting it
        // at runtime — the legacy-API (kSecAttrAccess) compatibility risk.
        try KeychainStore.save(service: service, account: "daemon", value: "v", daemon: true)
        XCTAssertTrue(KeychainStore.has(service: service, account: "daemon"))
    }
}
