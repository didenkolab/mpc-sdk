import CryptoKit
import XCTest
@testable import MpcDemo

final class FrostDemoTests: XCTestCase {
    func testKeyGenerationAndSigning() throws {
        let result = try FrostDemo.run(message: "test message")

        XCTAssertEqual(result.publicKey.count, 64, "32-byte Ed25519 public key")
        XCTAssertEqual(result.signature.count, 128, "64-byte Ed25519 signature")
        XCTAssertTrue(result.verified)
    }

    func testSignatureVerifiesWithCryptoKit() throws {
        let result = try FrostDemo.run(message: "test message")

        let key = try Curve25519.Signing.PublicKey(rawRepresentation: try XCTUnwrap(Data(hex: result.publicKey)))
        let signature = try XCTUnwrap(Data(hex: result.signature))
        XCTAssertTrue(key.isValidSignature(signature, for: Data("test message".utf8)))
        XCTAssertFalse(key.isValidSignature(signature, for: Data("other message".utf8)))
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
