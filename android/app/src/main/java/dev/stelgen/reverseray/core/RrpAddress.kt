package dev.stelgen.reverseray.core

/**
 * ATYP-кодирование адресов для OPEN (формат SOCKS5) и анти-SSRF guard.
 *
 * Решения принимаются строго по строке/байтам — никакого DNS-резолвинга здесь нет:
 * домены guard пропускает как «не определено», резолвинг и повторная проверка
 * уже разрешённого IP — забота вызывающей стороны.
 */
object RrpAddress {

    const val ATYP_IPV4 = 1
    const val ATYP_DOMAIN = 3
    const val ATYP_IPV6 = 4

    class AddressException(message: String) : Exception(message)

    class AddrBytes(val atyp: Int, val bytes: ByteArray)

    class OpenTarget(val atyp: Int, val host: String, val port: Int, val bytesRead: Int)

    // ---------- кодирование ----------

    /** Полный payload OPEN: [u8 atyp][addr][u16be port]. */
    fun encodeOpen(host: String, port: Int): ByteArray {
        if (port !in 1..65535) throw AddressException("порт вне 1..65535: $port")
        val a = encodeAddr(host)
        val out = ByteArray(a.bytes.size + 3)
        out[0] = a.atyp.toByte()
        a.bytes.copyInto(out, 1)
        putU16(out, a.bytes.size + 1, port)
        return out
    }

    /** [u8 atyp][addr] без порта. IPv6 — только литерал, домен ≤ 255 байт. */
    fun encodeAddr(rawHost: String): AddrBytes {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) throw AddressException("пустой адрес")
        parseIpv4Octets(host)?.let {
            return AddrBytes(ATYP_IPV4, it.map { o -> o.toByte() }.toByteArray())
        }
        if (host.contains(':')) {
            val v6 = parseIpv6Literal(host) ?: throw AddressException("некорректный IPv6-литерал: $host")
            return AddrBytes(ATYP_IPV6, v6)
        }
        val domain = host.toByteArray(Charsets.US_ASCII)
        if (domain.isEmpty()) throw AddressException("пустой домен")
        if (domain.size > 255) throw AddressException("домен длиннее 255 байт")
        val out = ByteArray(1 + domain.size)
        out[0] = domain.size.toByte()
        domain.copyInto(out, 1)
        return AddrBytes(ATYP_DOMAIN, out)
    }

    // ---------- разбор ----------

    /** Разбор payload OPEN с offset. Возвращает host/порт и сколько байт съедено. */
    fun parseOpen(p: ByteArray, offset: Int = 0): OpenTarget {
        var i = offset
        if (i >= p.size) throw AddressException("OPEN: пустой payload")
        val atyp = p[i].toInt() and 0xFF
        i++
        val host: String = when (atyp) {
            ATYP_IPV4 -> {
                if (i + 4 > p.size) throw AddressException("OPEN: короткий IPv4")
                val s = "${u(p[i])}.${u(p[i + 1])}.${u(p[i + 2])}.${u(p[i + 3])}"
                i += 4
                s
            }
            ATYP_DOMAIN -> {
                if (i + 1 > p.size) throw AddressException("OPEN: нет длины домена")
                val n = u(p[i])
                i++
                if (i + n > p.size) throw AddressException("OPEN: домен обрезан")
                val s = String(p, i, n, Charsets.US_ASCII)
                i += n
                s
            }
            ATYP_IPV6 -> {
                if (i + 16 > p.size) throw AddressException("OPEN: короткий IPv6")
                val s = formatIpv6(p, i)
                i += 16
                s
            }
            else -> throw AddressException("OPEN: неизвестный ATYP $atyp")
        }
        if (i + 2 > p.size) throw AddressException("OPEN: нет порта")
        val port = getU16(p, i)
        i += 2
        if (port !in 1..65535) throw AddressException("OPEN: некорректный порт $port")
        return OpenTarget(atyp, host, port, i - offset)
    }

    /** atyp + addr (из кадра Open) → человекочитаемый host. */
    fun decodeAddr(atyp: Int, addr: ByteArray): String = when (atyp) {
        ATYP_IPV4 -> {
            if (addr.size != 4) throw AddressException("IPv4: ожидалось 4 байта")
            "${u(addr[0])}.${u(addr[1])}.${u(addr[2])}.${u(addr[3])}"
        }
        ATYP_IPV6 -> {
            if (addr.size != 16) throw AddressException("IPv6: ожидалось 16 байт")
            formatIpv6(addr, 0)
        }
        ATYP_DOMAIN -> String(addr, Charsets.US_ASCII)
        else -> throw AddressException("неизвестный ATYP $atyp")
    }

    // ---------- IPv4/IPv6 литералы ----------

    private fun u(b: Byte): Int = b.toInt() and 0xFF

    fun isIpv4Literal(host: String): Boolean = parseIpv4Octets(normalizeHost(host)) != null

    /** Строгий IPv4: 4 десятичных октета ≤255, без ведущих нулей. null — не литерал. */
    fun parseIpv4Octets(host: String): IntArray? {
        val parts = host.split('.')
        if (parts.size != 4) return null
        val out = IntArray(4)
        for (i in 0..3) {
            val p = parts[i]
            if (p.isEmpty() || p.length > 3) return null
            for (c in p) if (c !in '0'..'9') return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v
        }
        return out
    }

    /** IPv6-литерал → 16 байт (поддерживает :: и ::ffff:a.b.c.d). null — не литерал. */
    fun parseIpv6Literal(raw: String): ByteArray? {
        var s = raw.trim()
        if (s.length >= 2 && s.startsWith("[") && s.endsWith("]")) {
            s = s.substring(1, s.length - 1)
        }
        val pct = s.indexOf('%')
        if (pct >= 0) s = s.substring(0, pct) // zone-id отбрасываем
        if (s.isEmpty() || !s.contains(':')) return null

        var head: List<String> = emptyList()
        var tail: List<String> = emptyList()
        var compressed = false
        val dc = s.indexOf("::")
        if (dc >= 0) {
            if (s.indexOf("::", dc + 1) >= 0) return null // больше одного ::
            compressed = true
            val l = s.substring(0, dc)
            val r = s.substring(dc + 2)
            head = if (l.isEmpty()) emptyList() else l.split(':')
            tail = if (r.isEmpty()) emptyList() else r.split(':')
        } else {
            head = s.split(':')
        }

        fun parseGroups(parts: List<String>, allowV4: Boolean): MutableList<Int>? {
            val res = mutableListOf<Int>()
            for ((idx, g) in parts.withIndex()) {
                if (g.contains('.')) {
                    if (!allowV4 || idx != parts.lastIndex) return null
                    val o = parseIpv4Octets(g) ?: return null
                    res.add((o[0] shl 8) or o[1])
                    res.add((o[2] shl 8) or o[3])
                } else {
                    if (g.isEmpty() || g.length > 4) return null
                    for (c in g) if (Character.digit(c, 16) < 0) return null
                    res.add(Integer.parseInt(g, 16))
                }
            }
            return res
        }

        val h = parseGroups(head, allowV4 = false) ?: return null
        val t = parseGroups(tail, allowV4 = true) ?: return null
        val zeros = 8 - (h.size + t.size)
        if (zeros < 0) return null
        if (!compressed && zeros != 0) return null

        val words = IntArray(8)
        var w = 0
        for (x in h) words[w++] = x
        if (compressed) w += zeros
        for (x in t) words[w++] = x

        val out = ByteArray(16)
        for (k in 0..7) {
            out[2 * k] = (words[k] shr 8).toByte()
            out[2 * k + 1] = words[k].toByte()
        }
        return out
    }

    /** 16 байт (с off) → сжатая текстовая форма IPv6. */
    fun formatIpv6(b: ByteArray, off: Int = 0): String {
        val words = IntArray(8) { ((b[off + 2 * it].toInt() and 0xFF) shl 8) or (b[off + 2 * it + 1].toInt() and 0xFF) }
        var bestStart = -1
        var bestLen = 0
        var curStart = -1
        var curLen = 0
        for (i in 0..7) {
            if (words[i] == 0) {
                if (curStart < 0) { curStart = i; curLen = 1 } else curLen++
                if (curLen > bestLen) { bestLen = curLen; bestStart = curStart }
            } else {
                curStart = -1
                curLen = 0
            }
        }
        if (bestLen < 2) {
            return (0 until 8).joinToString(":") { Integer.toHexString(words[it]) }
        }
        val left = (0 until bestStart).joinToString(":") { Integer.toHexString(words[it]) }
        val right = (bestStart + bestLen until 8).joinToString(":") { Integer.toHexString(words[it]) }
        return when {
            left.isEmpty() && right.isEmpty() -> "::"
            left.isEmpty() -> "::" + right
            right.isEmpty() -> "$left::"
            else -> "$left::$right"
        }
    }

    private fun normalizeHost(h: String): String {
        var s = h.trim()
        if (s.length >= 2 && s.startsWith("[") && s.endsWith("]")) s = s.substring(1, s.length - 1)
        return s
    }
}

/**
 * SSRF-guard: клиент отказывается диалить приватные/служебные диапазоны.
 * Работает по строке/байтам (без DNS): dotted-quad, десятичная форма, IPv6-литералы.
 */
object SsrfGuard {

    private class V4Range(val base: Long, val prefix: Int) {
        fun contains(v: Long): Boolean = ((v xor base) ushr (32 - prefix)) == 0L
    }

    private fun r(cidr: String, prefix: Int): V4Range {
        val o = RrpAddress.parseIpv4Octets(cidr)
            ?: throw IllegalArgumentException("bad cidr base: $cidr")
        val base = (o[0].toLong() shl 24) or (o[1].toLong() shl 16) or (o[2].toLong() shl 8) or o[3].toLong()
        return V4Range(base, prefix)
    }

    /** (диапазон, является ли он «LAN», который можно разрешить флагом allowLan) */
    private val V4_RANGES: List<Pair<V4Range, Boolean>> = listOf(
        r("0.0.0.0", 8) to false,       // "this network"
        r("10.0.0.0", 8) to true,       // RFC1918 — LAN
        r("100.64.0.0", 10) to true,    // CGNAT — LAN
        r("127.0.0.0", 8) to false,     // loopback
        r("169.254.0.0", 16) to false,  // link-local
        r("172.16.0.0", 12) to true,    // RFC1918 — LAN
        r("192.168.0.0", 16) to true,   // RFC1918 — LAN
        r("198.18.0.0", 15) to false,   // benchmarking
        r("224.0.0.0", 4) to false,     // multicast
        r("240.0.0.0", 4) to false,     // reserved (включая 255.255.255.255)
    )

    private val BLOCKED_NAMES = setOf("localhost", "ip6-localhost", "ip6-loopback")

    /**
     * true — диалить нельзя. allowLan=true снимает блок только с LAN-диапазонов
     * (RFC1918 + CGNAT + fc00::/7); loopback/link-local/multicast/reserved остаются закрытыми.
     */
    fun isBlocked(host: String, allowLan: Boolean = false): Boolean {
        val h = normalize(host)
        if (h.isEmpty()) return true
        if (h in BLOCKED_NAMES || h.endsWith(".localhost")) return true

        // Чисто числовая форма (2130706433 = 127.0.0.1) — классический SSRF bypass
        if (h.all { it in '0'..'9' }) {
            val v = h.toLongOrNull() ?: return true
            if (v > 0xFFFFFFFFL) return true
            return checkV4(v, allowLan)
        }

        RrpAddress.parseIpv4Octets(h)?.let {
            val v = (it[0].toLong() shl 24) or (it[1].toLong() shl 16) or
                (it[2].toLong() shl 8) or it[3].toLong()
            return checkV4(v, allowLan)
        }

        // Dotted-форма с ведущими нулями/мусором (0177.0.0.1) — неоднозначная, блокируем
        val dotted = h.split('.')
        if (dotted.size == 4 && dotted.all { it.isNotEmpty() && it.all { c -> c in '0'..'9' } }) {
            return true
        }

        if (h.contains(':')) {
            val b6 = RrpAddress.parseIpv6Literal(h) ?: return true // невалидный «литерал» — блокируем
            return checkV6(b6, allowLan)
        }

        return false // обычный домен — резолвинг вне guard'а
    }

    private fun checkV4(v: Long, allowLan: Boolean): Boolean {
        for ((range, lan) in V4_RANGES) {
            if (range.contains(v)) return !(allowLan && lan)
        }
        return false
    }

    /**
     * Проверка уже-резолвнутого адреса по байтам (v4 или v6).
     * Закрывает DNS-rebinding: hostname прошёл строковый гвард, но резолвится в приватный IP.
     */
    fun isBlockedAddress(addr: java.net.InetAddress, allowLan: Boolean = false): Boolean {
        val b = addr.address
        return if (b.size == 4) {
            val v = (b[0].toLong() and 0xFF shl 24) or (b[1].toLong() and 0xFF shl 16) or
                (b[2].toLong() and 0xFF shl 8) or (b[3].toLong() and 0xFF)
            checkV4(v, allowLan)
        } else {
            checkV6(b, allowLan)
        }
    }

    private fun checkV6(b: ByteArray, allowLan: Boolean): Boolean {
        var allZero = true
        for (x in b) if (x.toInt() != 0) { allZero = false; break }
        if (allZero) return true // :: — unspecified

        // ::ffff:a.b.c.d — проверяем вложенный IPv4 по тем же правилам
        val v4Mapped = (0..9).all { b[it].toInt() == 0 } &&
            (b[10].toInt() and 0xFF) == 0xFF && (b[11].toInt() and 0xFF) == 0xFF
        if (v4Mapped) {
            val v = ((b[12].toLong() and 0xFF) shl 24) or ((b[13].toLong() and 0xFF) shl 16) or
                ((b[14].toLong() and 0xFF) shl 8) or (b[15].toLong() and 0xFF)
            return checkV4(v, allowLan)
        }

        if ((0..14).all { b[it].toInt() == 0 } && b[15].toInt() == 1) return true // ::1
        val b0 = b[0].toInt() and 0xFF
        val b1 = b[1].toInt() and 0xFF
        if ((b0 and 0xFE) == 0xFC) return !allowLan            // fc00::/7 ULA — LAN
        if (b0 == 0xFE && (b1 and 0xC0) == 0x80) return true   // fe80::/10 link-local
        if (b0 == 0xFF) return true                            // ff00::/8 multicast
        return false
    }

    private fun normalize(host: String): String {
        var s = host.trim().lowercase()
        if (s.length >= 2 && s.startsWith("[") && s.endsWith("]")) s = s.substring(1, s.length - 1)
        val pct = s.indexOf('%')
        if (pct >= 0) s = s.substring(0, pct) // zone-id
        return s
    }
}
