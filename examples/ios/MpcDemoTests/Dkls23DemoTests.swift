import XCTest
@testable import MpcDemo

final class Dkls23DemoTests: XCTestCase {
    func testKeyGenerationAndSigning() throws {
        let result = try Dkls23Demo.run(message: "test message")

        XCTAssertEqual(result.publicKey.count, 66, "compressed secp256k1 public key")
        XCTAssertEqual(result.messageHash.count, 64)
        XCTAssertEqual(result.signature.count, 128, "64-byte r||s signature")
    }

    func testEachRunProducesANewKey() throws {
        let first = try Dkls23Demo.run()
        let second = try Dkls23Demo.run()
        XCTAssertNotEqual(first.publicKey, second.publicKey)
    }
}
