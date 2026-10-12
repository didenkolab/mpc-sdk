package com.didenkolab.mpcsdk.demo

import org.json.JSONObject

/**
 * Runs a complete FROST (Ed25519) 2-of-2 flow — key generation and signing —
 * with both parties inside one process. In a real wallet each party lives on a
 * different device and the JSON messages travel over your own transport.
 *
 * FROST party ids start at 1; `to_id` in routed messages is zero-based (party id - 1).
 */
object FrostDemo {

    data class Result(
        val publicKey: String,
        val message: String,
        val signature: String,
        val verified: Boolean,
    )

    fun run(message: String = "hello from mpc-sdk"): Result {
        val parties = listOf(1, 2)
        val threshold = 2

        // Key generation (2 rounds)

        val dkg = parties.map { id ->
            NativeMpc.frostDkgInit(id, parties.size, threshold).also {
                check(it != 0L) { "frostDkgInit: ${NativeMpc.frostGetLastError()}" }
            }
        }
        val keyshares = try {
            // Round 1: every party broadcasts its commitment package.
            val msg1 = dkg.map { NativeMpc.frostDkgGenerateMsg1(it) }

            // Round 2: each party consumes the others' packages and emits one secret share per recipient.
            val msg2 = dkg.flatMapIndexed { index, state ->
                MpcJson.split(NativeMpc.frostDkgHandleMsg1(state, MpcJson.array(msg1.filterIndexed { i, _ -> i != index })))
            }

            // Finalize: shares addressed to each party -> its keyshare. Keep it secret.
            dkg.mapIndexed { index, state ->
                NativeMpc.frostDkgHandleMsg2(state, MpcJson.array(msg2.filter { MpcJson.toId(it) == index }))
            }
        } finally {
            dkg.forEach(NativeMpc::frostDkgFree)
        }

        val publicKeys = keyshares.map {
            JSONObject(NativeMpc.frostDerivePublicKey(it, "m")).getString("derived_public_key")
        }
        check(publicKeys.toSet().size == 1) { "parties derived different public keys: $publicKeys" }
        val publicKey = publicKeys.first()

        // Signing (1 round of commitments + aggregation)

        // FROST signs the raw message bytes; Ed25519 hashes internally.
        val messageBytes = message.toByteArray()

        val signing = keyshares.map { keyshare ->
            NativeMpc.frostSigningInit(keyshare, messageBytes).also {
                check(it != 0L) { "frostSigningInit: ${NativeMpc.frostGetLastError()}" }
            }
        }
        try {
            // Every party broadcasts single-use nonce commitments.
            val commitments = signing.map { NativeMpc.frostSigningGenerateMsg1(it) }

            // The others' commitments -> this party's signature share.
            val shares = signing.mapIndexed { index, state ->
                NativeMpc.frostSigningHandleMsg1(state, MpcJson.array(commitments.filterIndexed { i, _ -> i != index }))
            }

            // Any party aggregates its own share with the others'.
            val signature = NativeMpc.frostCombineSignatures(shares[0], MpcJson.array(listOf(shares[1])))

            // Always verify locally before broadcasting.
            val verified = NativeMpc.frostVerifySignature(publicKey, messageBytes, signature)

            return Result(publicKey, message, signature, verified)
        } finally {
            signing.forEach(NativeMpc::frostSigningFree)
        }
    }
}
