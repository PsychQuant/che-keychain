import XCTest
@testable import CheKeychain

final class CommandReportingTests: XCTestCase {
    func testPairSecondFailureRetainsTheFirstAccountsFullDiagnosis() {
        let first = KeychainError.storedValueMismatch(service: "service", account: "id", reason: .ambiguous, cleanup: .leftInPlace(previousReplaced: true))
        let note = pairFirstStoreNote(service: "service", account: "id", firstError: first)
        XCTAssertTrue(note.contains(first.errorDescription!), note)
        XCTAssertTrue(note.contains("service/id"), note)
        XCTAssertFalse(note.contains("WAS stored and verified"), note)
    }

    func testPairSecondFailureIdentifiesAnAlreadyVerifiedFirstAccount() {
        let note = pairFirstStoreNote(service: "service", account: "id", firstError: nil)
        XCTAssertTrue(note.contains("service/id WAS stored and verified"), note)
    }
}
