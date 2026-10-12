package com.didenkolab.mpcsdk.demo

import org.json.JSONObject
import java.security.MessageDigest

/**
 * Runs a complete DKLs23 2-of-2 flow — key generation and signing — with both
 * parties inside one process. In a real wallet each party lives on a different
 * device and the JSON messages travel over your own transport; the routing
 * rules (`from_id` / `to_id`) stay exactly the same.
 */
object Dkls23Demo {

    data class Result(
        val publicKey: String,
        val messageHash: String,
        val signature: String,
    )

    fun run(message: String = "hello from mpc-sdk"): Result {
        val parties = listOf(0, 1)
        val threshold = 2

        // Key generation (4 rounds)

        val dkg = parties.map { id ->
            NativeMpc.dkgInit(id, parties.size, threshold).also {
                check(it != 0L) { "dkgInit: ${NativeMpc.getLastError()}" }
            }
        }
        try {
            // Round 1: every party broadcasts msg1.
            val msg1 = dkg.map { NativeMpc.dkgGenerateMsg1(it) }

            // Round 2: each party consumes the others' msg1 and emits P2P msg2.
            val msg2 = parties.flatMap { id ->
                MpcJson.split(NativeMpc.dkgHandleMsg1(dkg[id], MpcJson.array(msg1.filterIndexed { i, _ -> i != id })))
            }

            // Round 3: each party consumes msg2 addressed to it and emits P2P msg3.
            val msg3 = parties.flatMap { id ->
                MpcJson.split(NativeMpc.dkgHandleMsg2(dkg[id], MpcJson.array(msg2.filter { MpcJson.toId(it) == id })))
            }

            // Commitments are broadcast and ordered by party id.
            val commitments = MpcJson.array(dkg.map { "\"${NativeMpc.dkgCalculateCommitment2(it)}\"" })

            // Round 4: msg3 addressed to each party + all commitments -> broadcast msg4.
            val msg4 = parties.map { id ->
                NativeMpc.dkgHandleMsg3(dkg[id], MpcJson.array(msg3.filter { MpcJson.toId(it) == id }), commitments)
            }

            // Finalize: the others' msg4 -> this party's keyshare. Keep it secret.
            val keyshares = parties.map { id ->
                NativeMpc.dkgHandleMsg4(dkg[id], MpcJson.array(msg4.filterIndexed { i, _ -> i != id }))
            }

            val publicKeys = keyshares.map {
                JSONObject(NativeMpc.deriveChildPubkey(it, "m")).getString("derived_public_key")
            }
            check(publicKeys.toSet().size == 1) { "parties derived different public keys: $publicKeys" }

            return sign(keyshares, parties, publicKeys.first(), message)
        } finally {
            dkg.forEach(NativeMpc::dkgFree)
        }
    }

    // Signing (3 rounds + partial signatures)
    private fun sign(keyshares: List<String>, parties: List<Int>, publicKey: String, message: String): Result {
        val dsg = keyshares.map { keyshare ->
            NativeMpc.dsgInit(keyshare, "m").also {
                check(it != 0L) { "dsgInit: ${NativeMpc.getLastError()}" }
            }
        }
        try {
            val msg1 = dsg.map { NativeMpc.dsgGenerateMsg1(it) }

            val msg2 = parties.flatMap { id ->
                MpcJson.split(NativeMpc.dsgHandleMsg1(dsg[id], MpcJson.array(msg1.filterIndexed { i, _ -> i != id })))
            }

            val msg3 = parties.flatMap { id ->
                MpcJson.split(NativeMpc.dsgHandleMsg2(dsg[id], MpcJson.array(msg2.filter { MpcJson.toId(it) == id })))
            }

            // Presignatures are single-use handles kept inside the native library.
            val presignatures = parties.map { id ->
                NativeMpc.dsgHandleMsg3(dsg[id], MpcJson.array(msg3.filter { MpcJson.toId(it) == id }))
            }

            // Always hash with the target chain's algorithm; SHA-256 is used for the demo.
            val hash = MessageDigest.getInstance("SHA-256").digest(message.toByteArray())

            val partials = presignatures.map { JSONObject(NativeMpc.createPartialSignature(it, hash)) }

            // Any party combines its own partial with the others' msg4.
            val signature = NativeMpc.combineSignatures(
                partials[0].getJSONObject("partial").toString(),
                MpcJson.array(listOf(partials[1].getJSONObject("msg4").toString())),
            )

            return Result(publicKey, hash.toHex(), signature)
        } finally {
            dsg.forEach(NativeMpc::dsgFree)
        }
    }
}
