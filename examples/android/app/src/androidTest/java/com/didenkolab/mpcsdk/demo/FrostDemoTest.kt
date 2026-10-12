package com.didenkolab.mpcsdk.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FrostDemoTest {

    @Test
    fun keyGenerationAndSigning() {
        val result = FrostDemo.run("test message")

        assertEquals("32-byte Ed25519 public key", 64, result.publicKey.length)
        assertEquals("64-byte Ed25519 signature", 128, result.signature.length)
        assertTrue(result.verified)
    }

    @Test
    fun signatureVerifiesWithBouncyCastle() {
        val result = FrostDemo.run("test message")

        fun verify(message: String) = Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(result.publicKey.hexToBytes(), 0))
            val bytes = message.toByteArray()
            update(bytes, 0, bytes.size)
            verifySignature(result.signature.hexToBytes())
        }

        assertTrue(verify("test message"))
        assertFalse(verify("other message"))
    }
}
