package com.didenkolab.mpcsdk.demo

import android.app.Activity
import android.graphics.Typeface
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlin.concurrent.thread

class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val output = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
            text = "Run key generation and signing for one of the protocols."
        }
        val buttons = listOf(
            Button(this).apply { text = "DKLs23 (ECDSA)" } to ::dkls23,
            Button(this).apply { text = "FROST (Ed25519)" } to ::frost,
        )

        for ((button, demo) in buttons) {
            button.setOnClickListener {
                buttons.forEach { it.first.isEnabled = false }
                output.text = "Running…"
                thread {
                    val text = try {
                        demo()
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    runOnUiThread {
                        output.text = text
                        buttons.forEach { it.first.isEnabled = true }
                    }
                }
            }
        }

        val padding = (16 * resources.displayMetrics.density).toInt()
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(padding, padding, padding, padding)
                addView(LinearLayout(context).apply { buttons.forEach { addView(it.first) } })
                addView(ScrollView(context).apply { addView(output) })
            }
        )
    }

    private fun dkls23(): String {
        val result = Dkls23Demo.run()
        return """
            DKLs23 2-of-2 (secp256k1)
            Public key: ${result.publicKey}

            Message hash (SHA-256): ${result.messageHash}
            Signature (r||s): ${result.signature}
        """.trimIndent()
    }

    private fun frost(): String {
        val result = FrostDemo.run()
        return """
            FROST 2-of-2 (Ed25519)
            Public key: ${result.publicKey}

            Message: ${result.message}
            Signature: ${result.signature}
            Verified: ${result.verified}
        """.trimIndent()
    }
}
