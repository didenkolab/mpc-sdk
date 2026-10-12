package com.didenkolab.mpcsdk.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.MessageDigest

@RunWith(AndroidJUnit4::class)
class Dkls23DemoTest {

    @Test
    fun keyGenerationAndSigning() {
        val result = Dkls23Demo.run("test message")

        assertEquals("compressed secp256k1 public key", 66, result.publicKey.length)
        assertEquals(64, result.messageHash.length)
        assertEquals("64-byte r||s signature", 128, result.signature.length)
    }

    @Test
    fun signatureVerifiesWithBouncyCastle() {
        val result = Dkls23Demo.run("test message")

        val curve = CustomNamedCurves.getByName("secp256k1")
        val domain = ECDomainParameters(curve.curve, curve.g, curve.n, curve.h)
        val publicKey = ECPublicKeyParameters(curve.curve.decodePoint(result.publicKey.hexToBytes()), domain)
        val signature = result.signature.hexToBytes()
        val hash = MessageDigest.getInstance("SHA-256").digest("test message".toByteArray())

        val verifier = ECDSASigner().apply { init(false, publicKey) }
        assertTrue(
            verifier.verifySignature(
                hash,
                BigInteger(1, signature.copyOfRange(0, 32)),
                BigInteger(1, signature.copyOfRange(32, 64)),
            )
        )
    }

    @Test
    fun eachRunProducesANewKey() {
        assertNotEquals(Dkls23Demo.run().publicKey, Dkls23Demo.run().publicKey)
    }
}

internal fun String.hexToBytes() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
