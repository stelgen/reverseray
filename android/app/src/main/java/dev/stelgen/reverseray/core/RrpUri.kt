package dev.stelgen.reverseray.core

import java.io.ByteArrayOutputStream
import java.util.Locale

/** Ошибка парсинга/сериализации rrp:// конфига. */
class RrpUriException(message: String) : IllegalArgumentException(message)

/**
 * Конфиг туннеля из строки вида:
 * ```
 * rrp://token@host:443,8443/?pin=BASE64ORHEX&name=Home&proto=rrp1
 * ```
 * token и name — percent-encoded; IPv6-хост — в квадратных скобках. Pure Kotlin.
 */
data class RrpUriConfig(
    val token: String,
    val host: String,
    val ports: List<Int>,
    val pin: String? = null,
    val name: String? = null,
    /** Транспорт: "tcp" (сырой RRP/1, по умолчанию) или "ws" (WebSocket-апгрейд /rrp). */
    val transport: String = RrpUri.TRANSPORT_TCP,
    /** Протокол туннеля (канон после нормализации; мусор → дефолт, никогда не ошибка). */
    val proto: String = RrpProtocols.DEFAULT,
) {
    fun serialize(): String = RrpUri.serialize(this)
}

object RrpUri {

    const val SCHEME = "rrp://"
    const val TRANSPORT_TCP = "tcp"
    const val TRANSPORT_WS = "ws"

    /**
     * Парсинг rrp://-конфига из «любого» пользовательского ввода.
     * Сначала чистка (sanitizeLink): текст вокруг ссылки, невидимые ASCII/Unicode,
     * кавычки всех видов, декоративные обёртки, хвостовая пунктуация — и только
     * потом разбор по правилам. Известные ошибки копипаста правятся сами.
     */
    fun parse(raw: String): RrpUriConfig = parseSanitized(sanitizeLink(raw))

    /** Разбор уже очищенной строки (используется и в тестах). */
    internal fun parseSanitized(s: String): RrpUriConfig {
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
        var transport = TRANSPORT_TCP
        var proto = RrpProtocols.DEFAULT
        if (query.isNotEmpty()) {
            for (kv in query.split('&')) {
                if (kv.isEmpty()) continue
                val eq = kv.indexOf('=')
                val key = (if (eq < 0) kv else kv.substring(0, eq)).lowercase(Locale.ROOT).trim()
                val value = if (eq < 0) "" else kv.substring(eq + 1)
                when (key) {
                    "pin" -> pin = pctDecode(value)
                    "name" -> name = pctDecode(value)
                    "transport" -> {
                        val t = value.lowercase(Locale.ROOT).trim()
                        transport = when {
                            t == TRANSPORT_WS || t.startsWith("ws") -> TRANSPORT_WS
                            else -> TRANSPORT_TCP // неизвестное/пустое → дефолт, не ошибка
                        }
                    }
                    "proto" -> proto = RrpProtocols.normalize(pctDecode(value))
                    // неизвестные параметры игнорируем — сервер вправе добавить поля
                    else -> {}
                }
            }
        }
        return RrpUriConfig(token, host, ports, pin, name, transport, proto)
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
        if (config.transport.lowercase(Locale.ROOT) == TRANSPORT_WS) params.add("transport=ws")
        // proto — всегда явно: формат ключа несёт протокол, обе стороны парсят
        // его без догадок; мусорное значение сводится к дефолту и там, и там
        params.add("proto=" + pctEncode(config.proto))
        if (params.isNotEmpty()) sb.append("/?").append(params.joinToString("&"))
        return sb.toString()
    }

    // ---------- чистка мусорной ссылки ----------

    /**
     * Чинит типичные ошибки копипаста ДО разбора:
     *  - текст вокруг ссылки («твой конфиг: rrp://…, вставь»);
     *  - управляющие и невидимые символы (0x00-0x1F, 0x7F-0x9F, zero-width,
     *    bidi, U+FEFF, NBSP, U+2028/U+2029 и др.);
     *  - кавычки всех типов по краям: " ' ` « » ‘ ’ ‚ “ ” „ ‹ › 「 」;
     *  - декоративные обёртки: <…>, (…), […], {…}, *…*, _…_, |…|;
     *  - хвостовая пунктуация: . , ; : ! ? … — – / \\.
     * Схема нормализуется к нижнему регистру.
     */
    fun sanitizeLink(input: String): String {
        if (input.isEmpty()) return input
        var s = stripInvisible(input)
        // вырезаем ссылку из окружающего текста
        val idx = s.lowercase(Locale.ROOT).indexOf(SCHEME)
        if (idx >= 0) {
            s = s.substring(idx)
        } else if (s.contains('@') && s.lastIndexOf(':') > s.indexOf('@') && !s.contains("://")) {
            // скопировали без схемы, но структура token@host:port узнаваема;
            // если в тексте есть другая схема (http:// и т.п.) — НЕ придумываем,
            // пусть разбор честно упадёт с внятной ошибкой
            s = SCHEME + s
        }
        // кавычки/обёртки по краям (циклом: «(rrp://…»)»
        s = s.trim().trimQuotesAndWrappers()
        // хвостовая пунктуация копипаста
        s = s.trimEnd('.', ',', ';', ':', '!', '?', '…', '-', '—', '–', '/', '\\')
        // схема к нижнему регистру
        if (s.length >= SCHEME.length && s.take(SCHEME.length).equals(SCHEME, ignoreCase = true)) {
            s = SCHEME + s.substring(SCHEME.length)
        }
        return s
    }

    /** Удаляет управляющие, форматные и «пустые» символы. */
    private fun stripInvisible(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) {
            if (Character.isISOControl(c)) continue // 0x00-0x1F, 0x7F-0x9F
            if (c.isWhitespace()) continue // все пробельные, включая NBSP/U+2028/U+3000
            val t = Character.getType(c).toInt()
            if (t == Character.FORMAT.toInt()) continue // zero-width, bidi, U+FEFF
            if (t == Character.NON_SPACING_MARK.toInt() || t == Character.ENCLOSING_MARK.toInt()) continue
            sb.append(c)
        }
        return sb.toString()
    }

    /** Срезает кавычки/обёртки с обоих концов (несимметричные пары тоже). */
    private fun String.trimQuotesAndWrappers(): String {
        val quotes = charArrayOf(
            '"', '\'', '`', '«', '»', '‘', '’', '‚', '“', '”', '„', '‹', '›', '「', '」',
            '(', ')', '[', ']', '{', '}', '<', '>', '*', '_', '|',
        )
        var s = this
        var changed = true
        while (changed && s.isNotEmpty()) {
            changed = false
            var start = 0
            var end = s.length
            while (start < end && s[start] in quotes) { start++; changed = true }
            while (end > start && s[end - 1] in quotes) { end--; changed = true }
            if (changed) s = s.substring(start, end)
        }
        return s
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
