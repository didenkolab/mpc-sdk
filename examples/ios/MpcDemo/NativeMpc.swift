import Foundation
import MpcCore

/// Swift bindings to the mpc-sdk Rust FFI
/// (DKLS23 ECDSA + FROST Ed25519) shipped via MpcCore.xcframework.
///
/// All `char*` results from Rust are copied into Swift `String`s and freed
/// with the matching protocol's `*_free_string`. State pointers are owned
/// by Swift objects (`DkgSession`, `SigningSession`, etc.) and released in
/// `deinit` via `*_free_state`.
public enum NativeMpc {

    // MARK: - DKLS23 DKG

    public static func dkgInit(partyId: Int, nParties: Int, threshold: Int) -> OpaquePointer? {
        let state = dkls23_dkg_init(UInt8(partyId), UInt(nParties), UInt(threshold))
        return state.map { OpaquePointer($0) }
    }

    public static func dkgFree(_ state: OpaquePointer) {
        dkls23_dkg_free_state(UnsafeMutablePointer(state))
    }

    public static func dkgGenerateMsg1(_ state: OpaquePointer) -> String {
        rustString(dkls23_dkg_generate_msg1(UnsafeMutablePointer(state)), free: dkls23_free_string)
    }

    public static func dkgHandleMsg1(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(dkls23_dkg_handle_msg1(UnsafeMutablePointer(state), ptr), free: dkls23_free_string)
        }
    }

    public static func dkgHandleMsg2(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(dkls23_dkg_handle_msg2(UnsafeMutablePointer(state), ptr), free: dkls23_free_string)
        }
    }

    public static func dkgCalculateCommitment2(_ state: OpaquePointer) -> String {
        rustString(dkls23_dkg_calculate_commitment_2(UnsafeMutablePointer(state)), free: dkls23_free_string)
    }

    public static func dkgHandleMsg3(_ state: OpaquePointer, _ msgs: String, _ commitments: String) -> String {
        msgs.withCString { mPtr in
            commitments.withCString { cPtr in
                rustString(dkls23_dkg_handle_msg3(UnsafeMutablePointer(state), mPtr, cPtr), free: dkls23_free_string)
            }
        }
    }

    public static func dkgHandleMsg4(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(dkls23_dkg_handle_msg4(UnsafeMutablePointer(state), ptr), free: dkls23_free_string)
        }
    }

    // MARK: - DKLS23 DSG (signing)

    public static func dsgInit(keyshareJson: String, derivationPath: String) -> OpaquePointer? {
        keyshareJson.withCString { kPtr in
            derivationPath.withCString { dPtr in
                let state = dkls23_dsg_init(kPtr, dPtr)
                return state.map { OpaquePointer($0) }
            }
        }
    }

    public static func dsgFree(_ state: OpaquePointer) {
        dkls23_dsg_free_state(UnsafeMutablePointer(state))
    }

    public static func dsgGenerateMsg1(_ state: OpaquePointer) -> String {
        rustString(dkls23_dsg_generate_msg1(UnsafeMutablePointer(state)), free: dkls23_free_string)
    }

    public static func dsgHandleMsg1(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(dkls23_dsg_handle_msg1(UnsafeMutablePointer(state), ptr), free: dkls23_free_string)
        }
    }

    public static func dsgHandleMsg2(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(dkls23_dsg_handle_msg2(UnsafeMutablePointer(state), ptr), free: dkls23_free_string)
        }
    }

    public static func dsgHandleMsg3(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(dkls23_dsg_handle_msg3(UnsafeMutablePointer(state), ptr), free: dkls23_free_string)
        }
    }

    public static func createPartialSignature(presigJson: String, msgHash: Data) -> String {
        precondition(msgHash.count == 32, "msgHash must be exactly 32 bytes")
        return presigJson.withCString { pPtr in
            msgHash.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> String in
                let bytes = buf.bindMemory(to: UInt8.self).baseAddress!
                return rustString(dkls23_create_partial_signature(pPtr, bytes), free: dkls23_free_string)
            }
        }
    }

    public static func combineSignatures(partialJson: String, msg4ListJson: String) -> String {
        partialJson.withCString { pPtr in
            msg4ListJson.withCString { mPtr in
                rustString(dkls23_combine_signatures(pPtr, mPtr), free: dkls23_free_string)
            }
        }
    }

    public static func deriveChildPubkey(keyshareJson: String, path: String) -> String {
        keyshareJson.withCString { kPtr in
            path.withCString { pPtr in
                rustString(dkls23_derive_public_key(kPtr, pPtr), free: dkls23_free_string)
            }
        }
    }

    public static func deriveChildKeyshare(keyshareJson: String, path: String) -> String {
        keyshareJson.withCString { kPtr in
            path.withCString { pPtr in
                rustString(dkls23_derive_keyshare(kPtr, pPtr), free: dkls23_free_string)
            }
        }
    }

    public static func dkls23LastError() -> String {
        rustString(dkls23_get_last_error(), free: dkls23_free_string)
    }

    // MARK: - FROST DKG

    public static func frostDkgInit(partyId: Int, nParties: Int, threshold: Int) -> OpaquePointer? {
        let state = frost_dkg_init(UInt16(partyId), UInt16(nParties), UInt16(threshold))
        return state.map { OpaquePointer($0) }
    }

    public static func frostDkgFree(_ state: OpaquePointer) {
        frost_dkg_free_state(UnsafeMutablePointer(state))
    }

    public static func frostDkgGenerateMsg1(_ state: OpaquePointer) -> String {
        rustString(frost_dkg_generate_msg1(UnsafeMutablePointer(state)), free: frost_free_string)
    }

    public static func frostDkgHandleMsg1(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(frost_dkg_handle_msg1(UnsafeMutablePointer(state), ptr), free: frost_free_string)
        }
    }

    public static func frostDkgHandleMsg2(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(frost_dkg_handle_msg2(UnsafeMutablePointer(state), ptr), free: frost_free_string)
        }
    }

    public static func frostDkgFinalize(_ state: OpaquePointer) -> String {
        rustString(frost_dkg_finalize(UnsafeMutablePointer(state)), free: frost_free_string)
    }

    // MARK: - FROST Signing

    /// FROST signs the raw message (Ed25519 hashes internally), not a pre-computed hash.
    public static func frostSigningInit(keyshareJson: String, msgHash: Data) -> OpaquePointer? {
        keyshareJson.withCString { kPtr in
            msgHash.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> OpaquePointer? in
                let bytes = buf.bindMemory(to: UInt8.self).baseAddress!
                let state = frost_signing_init(kPtr, bytes, UInt(msgHash.count))
                return state.map { OpaquePointer($0) }
            }
        }
    }

    public static func frostSigningFree(_ state: OpaquePointer) {
        frost_signing_free_state(UnsafeMutablePointer(state))
    }

    public static func frostSigningGenerateMsg1(_ state: OpaquePointer) -> String {
        rustString(frost_signing_generate_msg1(UnsafeMutablePointer(state)), free: frost_free_string)
    }

    public static func frostSigningHandleMsg1(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(frost_signing_handle_msg1(UnsafeMutablePointer(state), ptr), free: frost_free_string)
        }
    }

    public static func frostSigningGenerateMsg2(_ state: OpaquePointer) -> String {
        rustString(frost_signing_generate_msg2(UnsafeMutablePointer(state)), free: frost_free_string)
    }

    public static func frostSigningHandleMsg2(_ state: OpaquePointer, _ json: String) -> String {
        json.withCString { ptr in
            rustString(frost_signing_handle_msg2(UnsafeMutablePointer(state), ptr), free: frost_free_string)
        }
    }

    public static func frostCreatePartialSignature(presigJson: String, msgHash: Data) -> String {
        presigJson.withCString { pPtr in
            msgHash.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> String in
                let bytes = buf.bindMemory(to: UInt8.self).baseAddress!
                return rustString(frost_create_partial_signature(pPtr, bytes), free: frost_free_string)
            }
        }
    }

    public static func frostCombineSignatures(partialJson: String, msgListJson: String) -> String {
        partialJson.withCString { pPtr in
            msgListJson.withCString { mPtr in
                rustString(frost_combine_signatures(pPtr, mPtr), free: frost_free_string)
            }
        }
    }

    public static func frostDerivePublicKey(keyshareJson: String, path: String) -> String {
        keyshareJson.withCString { kPtr in
            path.withCString { pPtr in
                rustString(frost_derive_public_key(kPtr, pPtr), free: frost_free_string)
            }
        }
    }

    /// Verifies an Ed25519 signature over the raw message. Returns true if valid.
    public static func frostVerifySignature(publicKeyHex: String, message: Data, signatureHex: String) -> Bool {
        publicKeyHex.withCString { kPtr in
            signatureHex.withCString { sPtr in
                message.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> Bool in
                    let bytes = buf.bindMemory(to: UInt8.self).baseAddress!
                    let result = rustString(frost_verify_signature(kPtr, bytes, UInt(message.count), sPtr),
                                            free: frost_free_string)
                    return result == "true"
                }
            }
        }
    }

    public static func frostLastError() -> String {
        rustString(frost_get_last_error(), free: frost_free_string)
    }

    // MARK: - Private helpers

    private static func rustString(
        _ ptr: UnsafeMutablePointer<CChar>?,
        free: (UnsafeMutablePointer<CChar>?) -> Void
    ) -> String {
        guard let ptr else { return "" }
        defer { free(ptr) }
        return String(cString: ptr)
    }
}
