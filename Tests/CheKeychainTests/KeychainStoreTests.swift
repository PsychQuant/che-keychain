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
}
