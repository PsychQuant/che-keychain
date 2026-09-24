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

    func testReplacementEvidenceListsTheAllowAllEntryFirstAndMarksTruncation() {
        // Round-9 verify (LOW): the success line after `set --replace` was untested.
        let owners = (1...9).map { "/Applications/App\($0).app" }
        let line = replacementEvidence(.foreign(owners: owners, allowAll: .plaintext))
        XCTAssertTrue(line.contains(KeychainStore.allowAllOwnerLabel(.plaintext)), line)
        XCTAssertTrue(line.contains("… and 1 more"), "only applications count toward the cap: \(line)")
        XCTAssertTrue(line.contains("plus an allow-all entry"), line)
        XCTAssertTrue(replacementEvidence(.allowAll(.wrappedOnly)).contains("wrapped export only"))
        XCTAssertEqual(replacementEvidence(.own), "an item trusted only to this executable")
    }
}
