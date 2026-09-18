package dev.stelgen.reverseray.core

/**
 * rrp://TOKEN@host:443,8443/?pin=CA_SPKI_B64URL&name=Home
 * Pure Kotlin; importable/exportable as text or QR.
 */
object RrpUri {

    class Profile(
        val token: String,
        val host: String,
        val ports: List<Int>,
        val pin: String,
        val name: String,
        val allowLan: Boolean = false
    ) {
        fun toUri(): String {
            val ps = ports.joinToString(",")
            val q = mutableListOf<String>()
            if (pin.isNotEmpty()) q.add("pin=$pin")
            q.add("name=${urlEncode(name)}")
            if (allowLan) q.add("lan=1")
            val suffix = if (q.isEmpty()) "/" else "/?${q.joinToString("&")}"
            return "rrp://$token@$host:$ps$suffix"
        }
    }

    fun parse(uri: String): Profile {
        val prefix = "rrp://"
        if (!uri.startsWith(prefix)) throw IllegalArgumentException("not an rrp:// uri")
        val rest = uri.substring(prefix.length)
        val at = rest.indexOf('@')
        if (at <= 0) throw IllegalArgumentException("missing token@")
        val token = rest.substring(0, at)
        val hostPortQ = rest.substring(at + 1)
        val qSplit = hostPortQ.indexOf('?')
        val hostPort = if (qSplit >= 0) hostPortQ.substring(0, qSplit) else hostPortQ
        val query = if (qSplit >= 0) hostPortQ.substring(qSplit + 1) else ""

        val lastColon = hostPort.lastIndexOf(':')
        if (lastColon <= 0) throw IllegalArgumentException("missing :port")
        val host = hostPort.substring(0, lastColon)
        val portsStr = hostPort.substring(lastColon + 1)
        val ports = portsStr.split(',').map {
            val p = it.toIntOrNull() ?: throw IllegalArgumentException("bad port '$it'")
            if (p !in 1..65535) throw IllegalArgumentException("port out of range")
            p
        }.distinct()
        if (ports.isEmpty()) throw IllegalArgumentException("no ports")

        var pin = ""
        var name = host
        var lan = false
        if (query.isNotEmpty()) {
            for (kv in query.split('&')) {
                val i = kv.indexOf('=')
                if (i <= 0) continue
                when (val k = kv.substring(0, i)) {
                    "pin" -> pin = kv.substring(i + 1)
                    "name" -> name = urlDecode(kv.substring(i + 1))
                    "lan" -> lan = kv.substring(i + 1) == "1"
                    else -> if (k.isEmpty()) throw IllegalArgumentException("bad query")
                }
            }
        }
        if (token.isEmpty()) throw IllegalArgumentException("empty token")
        if (host.isEmpty()) throw IllegalArgumentException("empty host")
        return Profile(token, host, ports, pin, name, lan)
    }

    fun urlEncode(s: String): String {
        val sb = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xFF
            if (c in 0x21..0x7E && c != '&'.code && c != '='.code && c != '%'.code) {
                sb.append(c.toChar())
            } else sb.append("%%%02X".format(c))
        }
        return sb.toString()
    }

    fun urlDecode(s: String): String {
        val bytes = ArrayList<Byte>(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '%' && i + 2 < s.length -> {
                    val b = s.substring(i + 1, i + 3).toIntOrNull(16)
                    if (b != null) {
                        bytes.add(b.toByte())
                        i += 3
                    } else {
                        bytes.add(c.code.toByte())
                        i++
                    }
                }
                c == '+' -> {
                    bytes.add(' '.code.toByte()); i++
                }
                else -> {
                    bytes.add(c.code.toByte()); i++
                }
            }
        }
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }
}
