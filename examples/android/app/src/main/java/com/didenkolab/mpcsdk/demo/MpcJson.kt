package com.didenkolab.mpcsdk.demo

import org.json.JSONObject

/** Minimal JSON plumbing for routing protocol messages between parties. */
object MpcJson {

    fun array(objects: List<String>) = objects.joinToString(",", "[", "]")

    fun toId(json: String) = JSONObject(json).getInt("to_id")

    /** Splits a JSON array into its raw top-level elements without re-encoding them. */
    fun split(json: String): List<String> {
        val items = mutableListOf<String>()
        var depth = 0
        var inString = false
        var escaped = false
        var start = 0
        for ((i, c) in json.withIndex()) {
            when {
                escaped -> escaped = false
                c == '\\' -> escaped = true
                c == '"' -> inString = !inString
                inString -> Unit
                c == '{' -> {
                    if (depth == 0) start = i
                    depth++
                }
                c == '}' -> {
                    depth--
                    if (depth == 0) items.add(json.substring(start, i + 1))
                }
            }
        }
        return items
    }
}

fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
