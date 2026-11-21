// v1.9.0: зона «wire-кодеки кадров» вынесена из RrpFrame.kt (транш-2):
// u16/u32 BE-хелперы, мини-JSON для payload-кадров, hex-дамп для журнала.
// Sealed-канон RrpFrame (таблица типов + nested-кодеки from/encode) не тронут.
package dev.stelgen.reverseray.core

import java.util.Locale

// --- u16/u32 BE-хелперы (используются также RrpAddress/RrpUri) ---

internal fun putU16(dst: ByteArray, off: Int, v: Int) {
    dst[off] = ((v ushr 8) and 0xFF).toByte()
    dst[off + 1] = (v and 0xFF).toByte()
}

internal fun putU32(dst: ByteArray, off: Int, v: Long) {
    for (i in 0 until 4) {
        dst[off + i] = ((v ushr (8 * (3 - i))) and 0xFFL).toByte()
    }
}

internal fun getU16(src: ByteArray, off: Int): Int =
    ((src[off].toInt() and 0xFF) shl 8) or (src[off + 1].toInt() and 0xFF)

internal fun getU32(src: ByteArray, off: Int): Long =
    ((src[off].toLong() and 0xFF) shl 24) or ((src[off + 1].toLong() and 0xFF) shl 16) or
        ((src[off + 2].toLong() and 0xFF) shl 8) or (src[off + 3].toLong() and 0xFF)

/**
 * Кадр RRP/1: 12 байт BE-заголовка [u8 ver=1][u8 type][u16 flags][u32 stream_id][u32 payload_len].
 *
 * Pure Kotlin: ни одного android.* импорта — кодек собирается и в plain JVM-тестах.
 * Лимиты payload по типам: DATA ≤ 65535, контрольные ≤ 4096.
 */

/** Hex-дамп первых 64 байт (для анализа raw-данных в журнале приложения). */
internal fun RrpFrame.rawHex(): String {
    val p = try { encode().copyOfRange(RrpFrame.HEADER_SIZE, encode().size) } catch (e: Exception) { ByteArray(0) }
    val n = minOf(64, p.size)
    return p.take(n).joinToString(" ") { String.format(Locale.ROOT, "%02x", it) } + if (p.size > n) "…" else ""
}


/** Минимальный JSON-хелпер для JSON-payload кадров (плоские объекты). Pure Kotlin. */
internal object MiniJson {
    fun escape(s: String): String = buildString {
        for (c in s) when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
        }
    }

    fun q(s: String): String = "\"" + escape(s) + "\""

    /** Значения передаются уже валидным JSON-текстом (строки — в кавычках). */
    fun obj(vararg fields: Pair<String, String>): String =
        fields.joinToString(",", "{", "}") { (k, v) -> q(k) + ":" + v }

    /** Плоский JSON-объект → Map: строки декодируются, числа/массивы — сырым текстом. */
    fun parseFlat(p: ByteArray): Map<String, String>? {
        val s = String(p, Charsets.UTF_8)
        val out = mutableMapOf<String, String>()
        var i = 0
        fun skipWs() {
            while (i < s.length && s[i].isWhitespace()) i++
        }
        fun readString(): String? {
            if (i >= s.length || s[i] != '"') return null
            i++
            val sb = StringBuilder()
            while (i < s.length) {
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (i >= s.length) return null
                        when (s[i++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'u' -> {
                                if (i + 4 > s.length) return null
                                val v = s.substring(i, i + 4).toIntOrNull(16) ?: return null
                                sb.append(v.toChar())
                                i += 4
                            }
                            else -> return null
                        }
                    }
                    else -> sb.append(c)
                }
            }
            return null
        }
        skipWs()
        if (i >= s.length || s[i] != '{') return null
        i++
        while (true) {
            skipWs()
            if (i < s.length && s[i] == '}') { i++; break }
            val key = readString() ?: return null
            skipWs()
            if (i >= s.length || s[i] != ':') return null
            i++
            skipWs()
            when {
                i < s.length && s[i] == '"' -> {
                    val v = readString() ?: return null
                    out[key] = v
                }
                i < s.length && s[i] == '[' -> {
                    i++
                    val start = i
                    var depth = 1
                    while (i < s.length && depth > 0) {
                        when (s[i]) {
                            '[' -> depth++
                            ']' -> depth--
                        }
                        i++
                    }
                    if (depth != 0) return null
                    out[key] = s.substring(start, i - 1)
                }
                else -> {
                    val start = i
                    while (i < s.length && s[i] !in ",}") i++
                    out[key] = s.substring(start, i).trim()
                }
            }
            skipWs()
            if (i < s.length && s[i] == ',') { i++; continue }
            if (i < s.length && s[i] == '}') { i++; break }
            return null
        }
        return out
    }
}
