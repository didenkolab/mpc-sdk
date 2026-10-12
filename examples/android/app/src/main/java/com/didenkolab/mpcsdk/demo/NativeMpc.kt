package com.didenkolab.mpcsdk.demo

/**
 * JNI bindings to the mpc-sdk Rust FFI: DKLS23 (ECDSA secp256k1) and FROST (Ed25519).
 *
 * Kotlin `external fun`s map to `Java_com_didenkolab_mpcsdk_demo_NativeMpc_<name>`
 * symbols in libmpc_jni.so (see src/main/cpp/mpc_jni.cpp). Functions returning
 * String throw IllegalStateException with the Rust error on failure; *Init
 * functions return 0 on failure (read the reason with getLastError()).
 * State pointers must be released with the matching *Free function.
 */
object NativeMpc {

    init {
        System.loadLibrary("mpc_jni")
    }

    // DKLS23 DKG
    external fun dkgInit(partyId: Int, nParties: Int, threshold: Int): Long
    external fun dkgFree(statePtr: Long)
    external fun dkgGenerateMsg1(statePtr: Long): String
    external fun dkgHandleMsg1(statePtr: Long, msgsJson: String): String
    external fun dkgHandleMsg2(statePtr: Long, msgsJson: String): String
    external fun dkgCalculateCommitment2(statePtr: Long): String
    external fun dkgHandleMsg3(statePtr: Long, msgsJson: String, commitmentsJson: String): String
    external fun dkgHandleMsg4(statePtr: Long, msgsJson: String): String

    // DSG (DKLS23 Signing)
    external fun dsgInit(keyshareJson: String, derivationPath: String): Long
    external fun dsgFree(statePtr: Long)
    external fun dsgGenerateMsg1(statePtr: Long): String
    external fun dsgHandleMsg1(statePtr: Long, msgsJson: String): String
    external fun dsgHandleMsg2(statePtr: Long, msgsJson: String): String
    external fun dsgHandleMsg3(statePtr: Long, msgsJson: String): String
    external fun createPartialSignature(presigJson: String, msgHash: ByteArray): String
    external fun combineSignatures(partialJson: String, msg4ListJson: String): String

    // Key Derivation
    external fun deriveChildPubkey(keyshareJson: String, path: String): String
    external fun getLastError(): String

    // FROST DKG
    external fun frostDkgInit(partyId: Int, nParties: Int, threshold: Int): Long
    external fun frostDkgFree(statePtr: Long)
    external fun frostDkgGenerateMsg1(statePtr: Long): String
    external fun frostDkgHandleMsg1(statePtr: Long, msgsJson: String): String
    external fun frostDkgHandleMsg2(statePtr: Long, msgsJson: String): String
    external fun frostDkgFinalize(statePtr: Long): String

    // FROST Signing (signs the raw message; Ed25519 hashes internally)
    external fun frostSigningInit(keyshareJson: String, msgHash: ByteArray): Long
    external fun frostSigningFree(statePtr: Long)
    external fun frostSigningGenerateMsg1(statePtr: Long): String
    external fun frostSigningHandleMsg1(statePtr: Long, msgsJson: String): String
    external fun frostSigningGenerateMsg2(statePtr: Long): String
    external fun frostSigningHandleMsg2(statePtr: Long, msgsJson: String): String
    external fun frostCreatePartialSignature(presigJson: String, msgHash: ByteArray): String
    external fun frostCombineSignatures(partialJson: String, msgListJson: String): String
    external fun frostDerivePublicKey(keyshareJson: String, path: String): String
    external fun frostVerifySignature(publicKeyHex: String, message: ByteArray, signatureHex: String): Boolean
    external fun frostGetLastError(): String
}
