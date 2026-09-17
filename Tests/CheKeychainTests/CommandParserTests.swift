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

    func testSetParsesDaemonFlag() throws {
        let cmd = try CommandParser.parse("set", ["--service", "S", "--account", "A", "--daemon"])
        guard case .set(let args) = cmd else { return XCTFail("expected .set, got \(cmd)") }
        XCTAssertTrue(args.daemon)
        XCTAssertFalse(args.secure)
    }

    func testSetDaemonDefaultsFalse() throws {
        let cmd = try CommandParser.parse("set", ["--service", "S", "--account", "A"])
        guard case .set(let args) = cmd else { return XCTFail() }
        XCTAssertFalse(args.daemon)
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

    func testValidateIdentifierChecksTheStringAsTyped() {
        // 0.3.0: a value wrapped in newlines used to trim clean and be stored raw.
        XCTAssertThrowsError(try CommandParser.validateIdentifier("svc\n", field: "service"))
        XCTAssertThrowsError(try CommandParser.validateIdentifier("\nsvc", field: "service"))
        XCTAssertThrowsError(try CommandParser.validateIdentifier("svc\u{7f}", field: "service"))
        XCTAssertThrowsError(try CommandParser.validateIdentifier(" svc", field: "service"))
        XCTAssertThrowsError(try CommandParser.validateIdentifier("svc\t", field: "service"))
    }

    func testDialogTextCannotForgeALine() throws {
        // --explain is rendered under "Storing to: …"; a line break would let a
        // caller print a second, fake destination line.
        XCTAssertNoThrow(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--explain", "line one\nline two"]), "explain may span lines")
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--explain", "x\u{1b}[2J"]))
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--label", "x\u{1b}[2J"]))
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--label", "ab\u{202e}c"]), "bidi override")
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--label", "one\ntwo"]), "label is single-line")
        XCTAssertThrowsError(try CommandParser.parse("set-pair", ["--service", "s", "--visible-account", "u", "--secure-account", "p", "--title", "t\n"]))
        XCTAssertNoThrow(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--explain", "Used for production deploys"]))
    }

    // MARK: - Input sources (#6)

    func testSetDefaultsToDialogSource() throws {
        guard case .set(let a) = try CommandParser.parse("set", ["--service", "s", "--account", "a"]) else { return XCTFail() }
        XCTAssertEqual(a.source, .dialog)
    }

    func testSetParsesInputSourceFlags() throws {
        guard case .set(let c) = try CommandParser.parse("set", ["--service", "s", "--account", "a", "--from-clipboard"]) else { return XCTFail() }
        XCTAssertEqual(c.source, .clipboard)
        guard case .set(let i) = try CommandParser.parse("set", ["--service", "s", "--account", "a", "--stdin", "--daemon"]) else { return XCTFail() }
        XCTAssertEqual(i.source, .stdin)
        XCTAssertTrue(i.daemon, "sources combine with --daemon")
    }

    func testSetRejectsBothSources() {
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--from-clipboard", "--stdin"])) { err in
            let msg = (err as? LocalizedError)?.errorDescription ?? "\(err)"
            XCTAssertTrue(msg.contains("mutually exclusive"), msg)
        }
    }

    func testDialogOnlyFlagsAreRefusedWithNonDialogSources() {
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--from-clipboard", "--secure"]))
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--stdin", "--label", "L"]))
        XCTAssertNoThrow(try CommandParser.parse("set", ["--service", "s", "--account", "a", "--stdin", "--daemon"]))
    }

    func testSetPairHasNoSourceFlags() {
        XCTAssertThrowsError(try CommandParser.parse("set-pair", ["--service", "s", "--visible-account", "u", "--secure-account", "p", "--stdin"]))
    }

    func testLegacyC1IdentifiersStayReachableForHasAndUnset() throws {
        let legacy = "legacy\u{0080}name"
        XCTAssertThrowsError(try CommandParser.parse("set", ["--service", legacy, "--account", "a"]))
        guard case .has(let service, let account) = try CommandParser.parse("has", ["--service", legacy, "--account", "a"]) else { return XCTFail() }
        XCTAssertEqual(service, legacy); XCTAssertEqual(account, "a")
        guard case .unset(let removedService, let removedAccount) = try CommandParser.parse("unset", ["--service", legacy, "--account", "a"]) else { return XCTFail() }
        XCTAssertEqual(removedService, legacy); XCTAssertEqual(removedAccount, "a")
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
