import Foundation

/// Runs a complete FROST (Ed25519) 2-of-2 flow — key generation and signing —
/// with both parties inside one process. In a real wallet each party lives on a
/// different device and the JSON messages travel over your own transport.
///
/// FROST party ids start at 1; `to_id` in routed messages is zero-based (party id - 1).
enum FrostDemo {

    struct Result {
        let publicKey: String
        let message: String
        let signature: String
        let verified: Bool
    }

    static func run(message: String = "hello from mpc-sdk") throws -> Result {
        let parties = [1, 2]
        let threshold = 2

        // MARK: Key generation (2 rounds)

        let dkg = try parties.map { id -> OpaquePointer in
            guard let state = NativeMpc.frostDkgInit(partyId: id, nParties: parties.count, threshold: threshold) else {
                throw DemoError(description: "frostDkgInit: \(NativeMpc.frostLastError())")
            }
            return state
        }
        defer { dkg.forEach(NativeMpc.frostDkgFree) }

        // Round 1: every party broadcasts its commitment package.
        let msg1 = try dkg.map { try check(NativeMpc.frostDkgGenerateMsg1($0), "frostDkgGenerateMsg1") }

        // Round 2: each party consumes the others' packages and emits one secret share per recipient.
        var msg2: [String] = []
        for (index, state) in dkg.enumerated() {
            let input = MpcJson.array(msg1.enumerated().filter { $0.offset != index }.map(\.element))
            msg2 += MpcJson.split(try check(NativeMpc.frostDkgHandleMsg1(state, input), "frostDkgHandleMsg1"))
        }

        // Finalize: shares addressed to each party -> its keyshare. Keep it secret.
        let keyshares = try dkg.enumerated().map { index, state in
            let input = MpcJson.array(msg2.filter { MpcJson.int($0, "to_id") == index })
            return try check(NativeMpc.frostDkgHandleMsg2(state, input), "frostDkgHandleMsg2")
        }

        let publicKeys = try keyshares.map { keyshare -> String in
            let json = try check(NativeMpc.frostDerivePublicKey(keyshareJson: keyshare, path: "m"), "frostDerivePublicKey")
            return MpcJson.string(json, "derived_public_key") ?? ""
        }
        guard Set(publicKeys).count == 1, let publicKey = publicKeys.first, !publicKey.isEmpty else {
            throw DemoError(description: "parties derived different public keys: \(publicKeys)")
        }

        // MARK: Signing (1 round of commitments + aggregation)

        // FROST signs the raw message bytes; Ed25519 hashes internally.
        let messageData = Data(message.utf8)

        let signing = try keyshares.map { keyshare -> OpaquePointer in
            guard let state = NativeMpc.frostSigningInit(keyshareJson: keyshare, msgHash: messageData) else {
                throw DemoError(description: "frostSigningInit: \(NativeMpc.frostLastError())")
            }
            return state
        }
        defer { signing.forEach(NativeMpc.frostSigningFree) }

        // Every party broadcasts single-use nonce commitments.
        let commitments = try signing.map { try check(NativeMpc.frostSigningGenerateMsg1($0), "frostSigningGenerateMsg1") }

        // The others' commitments -> this party's signature share.
        let shares = try signing.enumerated().map { index, state in
            let input = MpcJson.array(commitments.enumerated().filter { $0.offset != index }.map(\.element))
            return try check(NativeMpc.frostSigningHandleMsg1(state, input), "frostSigningHandleMsg1")
        }

        // Any party aggregates its own share with the others'.
        let signature = try check(
            NativeMpc.frostCombineSignatures(partialJson: shares[0], msgListJson: MpcJson.array([shares[1]])),
            "frostCombineSignatures"
        )

        // Always verify locally before broadcasting.
        let verified = NativeMpc.frostVerifySignature(publicKeyHex: publicKey, message: messageData, signatureHex: signature)

        return Result(publicKey: publicKey, message: message, signature: signature, verified: verified)
    }

    private static func check(_ value: String, _ step: String) throws -> String {
        guard !value.isEmpty else {
            throw DemoError(description: "\(step): \(NativeMpc.frostLastError())")
        }
        return value
    }
}
