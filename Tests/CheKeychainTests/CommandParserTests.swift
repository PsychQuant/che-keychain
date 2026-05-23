import XCTest
@testable import CheKeychain

final class CommandParserTests: XCTestCase {

    // MARK: - set

    func testSetParsesMinimal() throws {
        let cmd = try CommandParser.parse("set", ["--service", "S", "--account", "A"])
        guard case .set(let args) = cmd else { return XCTFail("expected .set, got \(cmd)") }
        XCTAssertEqual(args.service, "S")
        XCTAssertEqual(args.account, "A")
        XCTAssertFalse(args.secure)
        XCTAssertNil(args.label)
    }

    func testSetParsesAllOptions() throws {
        let cmd = try CommandParser.parse("set", [
            "--service", "my-api",
            "--account", "token",
            "--label", "API token",
            "--explain", "Used in prod",
            "--secure"
        ])
        guard case .set(let args) = cmd else { return XCTFail() }
        XCTAssertEqual(args, SetArgs(
            service: "my-api", account: "token",
            label: "API token", explain: "Used in prod",
            secure: true
        ))
    }

    func testSetRejectsMissingService() {
        XCTAssertThrowsError(try CommandParser.parse("set", ["--account", "A"])) { error in
            guard case CommandError.missingArgument(let arg) = error else {
                return XCTFail("expected .missingArgument, got \(error)")
            }
            XCTAssertEqual(arg, "--service")
        }
    }

    func testSetRejectsUnknownOption(){
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", "S", "--bogus"])) { error in
            guard case CommandError.unknownOption = error else { return XCTFail() }
        }
    }

    // MARK: - set-pair

    func testSetPairParses() throws {
        let cmd = try CommandParser.parse("set-pair", [
            "--service", "che-transport-tdx",
            "--visible-account", "client_id",
            "--secure-account", "client_secret",
            "--title", "TDX setup",
            "--explain", "Stored locally only."
        ])
        guard case .setPair(let args) = cmd else { return XCTFail() }
        XCTAssertEqual(args.service, "che-transport-tdx")
        XCTAssertEqual(args.visibleAccount, "client_id")
        XCTAssertEqual(args.secureAccount, "client_secret")
        XCTAssertEqual(args.title, "TDX setup")
    }

    func testSetPairRejectsSameAccountNames() {
        XCTAssertThrowsError(try CommandParser.parse("set-pair", [
            "--service", "S",
            "--visible-account", "x",
            "--secure-account", "x"
        ])) { error in
            guard case CommandError.invalidValue(let f, _) = error else { return XCTFail() }
            XCTAssertEqual(f, "secure-account")
        }
    }

    // MARK: - validation

    func testValidateIdentifierRejectsEmpty() {
        XCTAssertThrowsError(try CommandParser.validateIdentifier("", field: "service"))
        XCTAssertThrowsError(try CommandParser.validateIdentifier("   ", field: "service"))
    }

    func testValidateIdentifierRejectsControlChars() {
        XCTAssertThrowsError(try CommandParser.validateIdentifier("ab\nc", field: "account"))
        XCTAssertThrowsError(try CommandParser.validateIdentifier("a\u{0}b", field: "account"))
    }

    func testValidateIdentifierAcceptsTypical() {
        XCTAssertNoThrow(try CommandParser.validateIdentifier("che-transport-tdx", field: "service"))
        XCTAssertNoThrow(try CommandParser.validateIdentifier("client_secret", field: "account"))
    }

    // MARK: - has / unset

    func testHasRequiresBoth() throws {
        let cmd = try CommandParser.parse("has", ["--service", "S", "--account", "A"])
        guard case .has(let s, let a) = cmd else { return XCTFail() }
        XCTAssertEqual(s, "S")
        XCTAssertEqual(a, "A")
        XCTAssertThrowsError(try CommandParser.parse("has", ["--service", "S"]))
    }

    func testUnsetAccountOptional() throws {
        let withAccount = try CommandParser.parse("unset", ["--service", "S", "--account", "A"])
        guard case .unset(_, let a1) = withAccount else { return XCTFail() }
        XCTAssertEqual(a1, "A")

        let serviceOnly = try CommandParser.parse("unset", ["--service", "S"])
        guard case .unset(_, let a2) = serviceOnly else { return XCTFail() }
        XCTAssertNil(a2, "unset without --account removes all accounts under service")
    }

    func testUnknownSubcommandRejected() {
        XCTAssertThrowsError(try CommandParser.parse("nope", []))
    }
}
