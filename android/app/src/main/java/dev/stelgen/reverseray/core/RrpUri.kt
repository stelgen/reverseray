package dev.stelgen.reverseray.core

import java.io.ByteArrayOutputStream

/** Ошибка парсинга/сериализации rrp:// конфига. */
class RrpUriException(message: String) : IllegalArgumentException(message)

/**
 * Конфиг туннеля из строки вида:
 * ```
 * rrp://token@host:443,8443/?pin=BASE64ORHEX&name=Home
 * ```
 * token и name — percent-encoded; IPv6-хост — в квадратных скобках. Pure Kotlin.
 */
data class RrpUriConfig(
    val token: String,
    val host: String,
    val ports: List<Int>,
    val pin: String? = null,
    val name: String? = null,
) {
    fun serialize(): String = RrpUri.serialize(this)
}

object RrpUri {

    const val SCHEME = "rrp://"

    fun parse(raw: String): RrpUriConfig {
        val s = raw.trim()
        if (!s.take(SCHEME.length).equals(SCHEME, ignoreCase = true)) {
            throw RrpUriException("ожидалась схема rrp://")
        }
        val body = s.substring(SCHEME.length)

        val at = body.indexOf('@')
        if (at < 0) throw RrpUriException("нет токена: rrp://token@host:ports")
        val token = pctDecode(body.substring(0, at))
        if (token.isEmpty()) throw RrpUriException("пустой токен")

        val rest = body.substring(at + 1)
        val qIdx = rest.indexOf('?')
        val query = if (qIdx >= 0) rest.substring(qIdx + 1) else ""
        var hostPart = if (qIdx >= 0) rest.substring(0, qIdx) else rest
        hostPart = hostPart.trimEnd('/')

        val host: String
        val portsStr: String
        if (hostPart.startsWith("[")) {
            val close = hostPart.indexOf(']')
            if (close < 0) throw RrpUriException("IPv6-литерал без закрывающей ]")
            host = hostPart.substring(1, close).trim()
            val tail = hostPart.substring(close + 1)
            if (!tail.startsWith(":")) throw RrpUriException("нет портов после ]")
            portsStr = tail.substring(1)
        } else {
            val colon = hostPart.lastIndexOf(':')
            if (colon < 0) throw RrpUriException("нет портов: host:443,8443")
            host = hostPart.substring(0, colon).trim()
            portsStr = hostPart.substring(colon + 1)
        }
        if (host.isEmpty()) throw RrpUriException("пустой хост")

        val ports = portsStr
            .split(',')
            .map { it.trim() }
            .map {
                val n = it.toIntOrNull() ?: throw RrpUriException("некорректный порт: $it")
                if (n !in 1..65535) throw RrpUriException("порт вне 1..65535: $n")
                n
            }
        if (ports.isEmpty()) throw RrpUriException("список портов пуст")

        var pin: String? = null
        var name: String? = null
        if (query.isNotEmpty()) {
            for (kv in query.split('&')) {
                if (kv.isEmpty()) continue
                val eq = kv.indexOf('=')
                val key = (if (eq < 0) kv else kv.substring(0, eq)).lowercase()
                val value = if (eq < 0) "" else kv.substring(eq + 1)
                when (key) {
                    "pin" -> pin = pctDecode(value)
                    "name" -> name = pctDecode(value)
                }
            }
        }
        return RrpUriConfig(token, host, ports, pin, name)
    }

    fun serialize(config: RrpUriConfig): String {
        val sb = StringBuilder(SCHEME)
        sb.append(pctEncode(config.token)).append('@')
        if (config.host.contains(':')) {
            sb.append('[').append(config.host).append(']')
        } else {
            sb.append(config.host)
        }
        sb.append(':').append(config.ports.joinToString(","))
        val params = mutableListOf<String>()
        config.pin?.let { params.add("pin=" + pctEncode(it)) }
        config.name?.let { params.add("name=" + pctEncode(it)) }
        if (params.isNotEmpty()) sb.append("/?").append(params.joinToString("&"))
        return sb.toString()
    }

    // ---------- percent-encoding (RFC 3986 unreserved + ',' для списка портов) ----------

    private const val SAFE =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~,"

    fun pctEncode(s: String): String {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val sb = StringBuilder(bytes.size + 8)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c < 0x80 && SAFE.indexOf(c.toChar()) >= 0) {
                sb.append(c.toChar())
            } else {
                sb.append('%').append("%02X".format(c))
            }
        }
        return sb.toString()
    }

    fun pctDecode(s: String): String {
        if ('%' !in s) return s
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                if (i + 2 >= s.length) throw RrpUriException("обрезанный percent-encoding")
                val b = s.substring(i + 1, i + 3).toIntOrNull(16)
                    ?: throw RrpUriException("некорректный percent-encoding: ${s.substring(i, i + 3)}")
                out.write(b)
                i += 3
            } else {
                out.write(c.code and 0xFF)
                i++
            }
        }
        return out.toString("UTF-8")
    }
}
