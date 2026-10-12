import CryptoKit
import Foundation

/// Runs a complete DKLs23 2-of-2 flow — key generation and signing — with both
/// parties inside one process. In a real wallet each party lives on a different
/// device and the JSON messages travel over your own transport; the routing
/// rules (`from_id` / `to_id`) stay exactly the same.
enum Dkls23Demo {

    struct Result {
        let publicKey: String
        let messageHash: String
        let signature: String
    }

    static func run(message: String = "hello from mpc-sdk") throws -> Result {
        let parties = [0, 1]
        let n = parties.count
        let threshold = 2

        // MARK: Key generation (4 rounds)

        let dkg = try parties.map { id -> OpaquePointer in
            guard let state = NativeMpc.dkgInit(partyId: id, nParties: n, threshold: threshold) else {
                throw DemoError(description: "dkgInit: \(NativeMpc.dkls23LastError())")
            }
            return state
        }
        defer { dkg.forEach(NativeMpc.dkgFree) }

        // Round 1: every party broadcasts msg1.
        let msg1 = try dkg.map { try check(NativeMpc.dkgGenerateMsg1($0), "dkgGenerateMsg1") }

        // Round 2: each party consumes the others' msg1 and emits P2P msg2.
        var msg2: [String] = []
        for id in parties {
            let input = MpcJson.array(msg1.enumerated().filter { $0.offset != id }.map(\.element))
            msg2 += MpcJson.split(try check(NativeMpc.dkgHandleMsg1(dkg[id], input), "dkgHandleMsg1"))
        }

        // Round 3: each party consumes msg2 addressed to it and emits P2P msg3.
        var msg3: [String] = []
        for id in parties {
            let input = MpcJson.array(msg2.filter { MpcJson.int($0, "to_id") == id })
            msg3 += MpcJson.split(try check(NativeMpc.dkgHandleMsg2(dkg[id], input), "dkgHandleMsg2"))
        }

        // Commitments are broadcast and ordered by party id.
        let commitments = try dkg.map { try check(NativeMpc.dkgCalculateCommitment2($0), "dkgCalculateCommitment2") }
        let commitmentsJson = MpcJson.array(commitments.map { "\"\($0)\"" })

        // Round 4: msg3 addressed to each party + all commitments -> broadcast msg4.
        var msg4: [String] = []
        for id in parties {
            let input = MpcJson.array(msg3.filter { MpcJson.int($0, "to_id") == id })
            msg4.append(try check(NativeMpc.dkgHandleMsg3(dkg[id], input, commitmentsJson), "dkgHandleMsg3"))
        }

        // Finalize: the others' msg4 -> this party's keyshare. Keep it secret.
        let keyshares = try parties.map { id in
            let input = MpcJson.array(msg4.enumerated().filter { $0.offset != id }.map(\.element))
            return try check(NativeMpc.dkgHandleMsg4(dkg[id], input), "dkgHandleMsg4")
        }

        let publicKeys = try keyshares.map { keyshare -> String in
            let json = try check(NativeMpc.deriveChildPubkey(keyshareJson: keyshare, path: "m"), "deriveChildPubkey")
            return MpcJson.string(json, "derived_public_key") ?? ""
        }
        guard Set(publicKeys).count == 1, let publicKey = publicKeys.first, !publicKey.isEmpty else {
            throw DemoError(description: "parties derived different public keys: \(publicKeys)")
        }

        // MARK: Signing (3 rounds + partial signatures)

        let dsg = try keyshares.map { keyshare -> OpaquePointer in
            guard let state = NativeMpc.dsgInit(keyshareJson: keyshare, derivationPath: "m") else {
                throw DemoError(description: "dsgInit: \(NativeMpc.dkls23LastError())")
            }
            return state
        }
        defer { dsg.forEach(NativeMpc.dsgFree) }

        let signMsg1 = try dsg.map { try check(NativeMpc.dsgGenerateMsg1($0), "dsgGenerateMsg1") }

        var signMsg2: [String] = []
        for id in parties {
            let input = MpcJson.array(signMsg1.enumerated().filter { $0.offset != id }.map(\.element))
            signMsg2 += MpcJson.split(try check(NativeMpc.dsgHandleMsg1(dsg[id], input), "dsgHandleMsg1"))
        }

        var signMsg3: [String] = []
        for id in parties {
            let input = MpcJson.array(signMsg2.filter { MpcJson.int($0, "to_id") == id })
            signMsg3 += MpcJson.split(try check(NativeMpc.dsgHandleMsg2(dsg[id], input), "dsgHandleMsg2"))
        }

        // Presignatures are single-use handles kept inside the native library.
        let presignatures = try parties.map { id in
            let input = MpcJson.array(signMsg3.filter { MpcJson.int($0, "to_id") == id })
            return try check(NativeMpc.dsgHandleMsg3(dsg[id], input), "dsgHandleMsg3")
        }

        // Always hash with the target chain's algorithm; SHA-256 is used for the demo.
        let hash = Data(SHA256.hash(data: Data(message.utf8)))

        let partials = try presignatures.map { presig -> (partial: String, msg4: String) in
            let json = try check(NativeMpc.createPartialSignature(presigJson: presig, msgHash: hash),
                                 "createPartialSignature")
            guard let partial = MpcJson.raw(json, "partial"), let msg4 = MpcJson.raw(json, "msg4") else {
                throw DemoError(description: "unexpected partial signature JSON")
            }
            return (partial, msg4)
        }

        // Any party combines its own partial with the others' msg4.
        let signature = try check(
            NativeMpc.combineSignatures(partialJson: partials[0].partial, msg4ListJson: MpcJson.array([partials[1].msg4])),
            "combineSignatures"
        )

        return Result(publicKey: publicKey, messageHash: hash.hexString, signature: signature)
    }

    private static func check(_ value: String, _ step: String) throws -> String {
        guard !value.isEmpty else {
            throw DemoError(description: "\(step): \(NativeMpc.dkls23LastError())")
        }
        return value
    }
}
