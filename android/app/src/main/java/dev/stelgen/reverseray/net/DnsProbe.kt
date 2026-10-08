package dev.stelgen.reverseray.net

import android.os.Build
import android.os.SystemClock
import android.util.Log
import dev.stelgen.reverseray.core.Msgs
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Честный сбор DNS-фактов устройства (v0.8, канон «ничего не прячем»):
 * показывает юзеру ВЕСЬ набор данных, который приложение реально изучило:
 *
 *  - системные DNS-серверы (не «роутер», а фактические адреса);
 *  - КТО РЕАЛЬНО резолвит: даже если роутер пересылает запросы выше,
 *    TXT-проба (whoami.cloudflare / o-o.myaddr.l.google.com из манифеста
 *    модулей) возвращает IP верхнего резолвера, который дал ответ;
 *  - DNSSEC: подписанная зона с EDNS-DO — ставит ли резолвер AD-флаг;
 *  - DoT (853) и DoH (HTTPS dns-query) — доступность в текущей сети;
 *  - ECS: приложение САМО никогда не шлёт EDNS Client Subnet (снимок
 *    честности: факт, а не обещание);
 *  - шифрование SNI (ECH): не поддерживается на текущем уровне ОС —
 *    показываем честно.
 */
object DnsProbe {

    private const val TAG = "DnsProbe"
    const val DEFAULT_PROBE_NAME = "whoami.cloudflare"

    data class DnsInfo(
        val servers: List<String>,
        val realResolver: String?,          // кто фактически дал ответ
        val realResolverIsRouter: Boolean?, // это адрес из системных DNS (роутер/этот же)?
        val dnssecOk: Boolean?,             // null — проверить не удалось
        val dotReachable: Boolean?,         // 853/tcp до системного DNS
        val dohReachable: Boolean?,         // HTTPS DoH до cloudflare-dns.com
        val ecsSentByApp: Boolean,          // всегда false — мы не шлём ECS
        val sniEncryption: String,          // статус SNI-шифрования честно
        val checkedAtMs: Long,
    )

    @Volatile
    var last: DnsInfo? = null
        private set

    /** Системные DNS: LinkProperties (API 21+), иначе getprop net.dnsN. */
    fun systemServers(): List<String> {
        val out = LinkedHashSet<String>()
        try {
            if (Build.VERSION.SDK_INT >= 21) {
                val cm = android.content.Context.CONNECTIVITY_SERVICE
                val connectivity = appContext().getSystemService(cm) as android.net.ConnectivityManager
                val lp = connectivity.getLinkProperties(connectivity.activeNetwork)
                lp?.dnsServers?.forEach { if (!it.isLoopbackAddress) out.add(it.hostAddress ?: "") }
            }
        } catch (_: Throwable) {
        }
        if (out.isEmpty()) {
            // API 14–20: легаси-свойства
            try {
                val sp = Class.forName("android.os.SystemProperties")
                val get = sp.getMethod("get", String::class.java)
                for (i in 1..4) {
                    val v = get.invoke(null, "net.dns$i") as? String
                    if (!v.isNullOrBlank()) out.add(v)
                }
            } catch (_: Throwable) {
            }
        }
        return out.filter { it.isNotEmpty() }
    }

    private fun appContext(): android.content.Context {
        // ActivityThread.currentApplication() — без instrumentation-зависимости
        return try {
            val at = Class.forName("android.app.ActivityThread")
            val m = at.getMethod("currentApplication")
            m.invoke(null) as android.content.Context
        } catch (_: Throwable) {
            throw IllegalStateException(Msgs.DP_NO_CONTEXT.t())
        }
    }

    // ------------------------------------------------------------- raw DNS

    /** Query TXT qname к указанному резолверу; возвращает TXT-строки ответа. */
    fun queryTxt(resolver: String, qname: String, timeoutMs: Int = 2500): List<String>? {
        return try {
            val id = (SystemClock.elapsedRealtime() and 0xFFFF).toInt()
            val q = buildQuery(id, qname, wantDnssec = false)
            val addr = InetAddress.getByName(resolver)
            DatagramSocket().use { sock ->
                sock.soTimeout = timeoutMs
                sock.send(DatagramPacket(q, q.size, addr, 53))
                val buf = ByteArray(4096)
                val pkt = DatagramPacket(buf, buf.size)
                sock.receive(pkt)
                parseTxtAnswers(buf, pkt.length, id)
            }
        } catch (e: Exception) {
            Log.d(TAG, "TXT $qname @$resolver: ${e.message}")
            null
        }
    }

    /** DNSKEY подписанной зоны с EDNS-DO; true — в ответе стоит AD. */
    fun dnssecAdFlag(resolver: String, zone: String, timeoutMs: Int = 2500): Boolean? {
        return try {
            val id = ((SystemClock.elapsedRealtime() and 0xFFFF) + 7).toInt()
            val q = buildQuery(id, zone, type = 48, wantDnssec = true) // DNSKEY
            val addr = InetAddress.getByName(resolver)
            DatagramSocket().use { sock ->
                sock.soTimeout = timeoutMs
                sock.send(DatagramPacket(q, q.size, addr, 53))
                val buf = ByteArray(4096)
                val pkt = DatagramPacket(buf, buf.size)
                sock.receive(pkt)
                parseHeader(buf, pkt.length, id)?.let { it.second } // AD flag
            }
        } catch (e: Exception) {
            Log.d(TAG, "DNSKEY $zone @$resolver: ${e.message}")
            null
        }
    }

    /** UDP:53 работает по plaintext — данные о резолвере не приватны, это ок. */
    private fun buildQuery(id: Int, qname: String, type: Int = 16, wantDnssec: Boolean): ByteArray {
        val out = ByteArrayOutputStream()
        // header
        out.write((id ushr 8) and 0xFF)
        out.write(id and 0xFF)
        out.write(0x01) // RD
        out.write(0x00)
        out.write(0x00); out.write(0x01) // QDCOUNT=1
        out.write(0x00); out.write(0x00) // ANCOUNT
        out.write(0x00); out.write(0x00) // NSCOUNT
        out.write(0x00); out.write(0x00) // ARCOUNT (обновим при DO)
        // question
        for (label in qname.split('.')) {
            if (label.isEmpty()) continue
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0x00)
        out.write((type ushr 8) and 0xFF); out.write(type and 0xFF)
        out.write(0x00); out.write(0x01) // IN
        if (wantDnssec) {
            // OPT RR: root, type 41, UDP size 4096, DO=0x8000
            out.write(0x00) // root
            out.write(0x00); out.write(41)
            out.write(0x10); out.write(0x00) // 4096
            out.write(0x80); out.write(0x00) // flags: DO
            out.write(0x00); out.write(0x00)
        }
        return out.toByteArray()
    }

    private fun parseHeader(buf: ByteArray, len: Int, wantId: Int): Pair<Boolean, Boolean>? {
        if (len < 12) return null
        val id = ((buf[0].toInt() and 0xFF) shl 8) or (buf[1].toInt() and 0xFF)
        if (id != wantId) return null
        val qr = (buf[2].toInt() and 0x80) != 0
        if (!qr) return null
        val rcode = buf[3].toInt() and 0x0F
        val ad = (buf[3].toInt() and 0x20) != 0
        if (rcode != 0) return null
        return true to ad
    }

    private fun parseTxtAnswers(buf: ByteArray, len: Int, wantId: Int): List<String>? {
        val header = parseHeader(buf, len, wantId) ?: return null
        if (!header.first) return null
        val anCount = ((buf[6].toInt() and 0xFF) shl 8) or (buf[7].toInt() and 0xFF)
        if (anCount <= 0) return emptyList()
        var i = 12
        // skip question
        i = skipName(buf, i)
        i += 4 // qtype/qclass
        val texts = mutableListOf<String>()
        for (a in 0 until anCount) {
            i = skipName(buf, i) // RR name (может быть указателем)
            if (i + 10 > len) break
            val rtype = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 8 // type+class+ttl(4) — ttl внутри
            i += 4
            val rdLen = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
            if (i + rdLen > len) break
            if (rtype == 16) { // TXT
                var j = i
                val end = i + rdLen
                while (j < end) {
                    val l = buf[j].toInt() and 0xFF
                    j++
                    if (j + l > end) break
                    texts.add(String(buf, j, l, Charsets.US_ASCII))
                    j += l
                }
            }
            i += rdLen
        }
        return texts
    }

    private fun skipName(buf: ByteArray, start: Int): Int {
        var i = start
        var jumped = false
        var result = start
        var guard = 0
        while (guard++ < 64) {
            val l = buf[i].toInt() and 0xFF
            if (l == 0) {
                i++
                if (!jumped) result = i
                break
            }
            if (l and 0xC0 == 0xC0) {
                val ptr = ((l and 0x3F) shl 8) or (buf[i + 1].toInt() and 0xFF)
                if (!jumped) result = i + 2
                i = ptr
                jumped = true
                continue
            }
            i += 1 + l
        }
        return result
    }

    // ------------------------------------------------------------- probes

    private fun dotReachable(server: String): Boolean? = try {
        Socket().use { s ->
            s.connect(InetSocketAddress(server, 853), 2000)
            true
        }
    } catch (_: Exception) {
        false
    }

    /** DoH-доступность: реальный HTTPS-запрос dns-query с JSON-ответом. */
    private fun dohReachable(): Boolean? = try {
        val conn = URL("https://cloudflare-dns.com/dns-query?name=example.com&type=A").openConnection() as HttpsURLConnection
        conn.connectTimeout = 2500
        conn.readTimeout = 2500
        conn.setRequestProperty("Accept", "application/dns-json")
        val ok = conn.responseCode == 200
        conn.inputStream.use { it.readBytes() }
        ok
    } catch (_: Exception) {
        false
    }

    /** Полный сбор (блокирующий — вызывать из фонового потока). */
    fun collect(probeName: String = DEFAULT_PROBE_NAME): DnsInfo {
        val servers = systemServers()
        val resolver0 = servers.firstOrNull()
        var real: String? = null
        var isRouter: Boolean? = null
        var dnssec: Boolean? = null
        var dot: Boolean? = null
        if (resolver0 != null) {
            val txt = queryTxt(resolver0, probeName) ?: queryTxt(resolver0, "o-o.myaddr.l.google.com")
            val candidate = txt?.lastOrNull { looksLikeIp(it) }
            if (candidate != null) {
                real = candidate
                isRouter = servers.any { it == candidate }
            }
            dnssec = dnssecAdFlag(resolver0, "cloudflare.com")
            dot = dotReachable(resolver0)
        }
        val doh = dohReachable()
        val info = DnsInfo(
            servers = servers,
            realResolver = real,
            realResolverIsRouter = isRouter,
            dnssecOk = dnssec,
            dotReachable = dot,
            dohReachable = doh,
            ecsSentByApp = false,
            sniEncryption = Msgs.DP_SNI_OS.t(),
            checkedAtMs = System.currentTimeMillis(),
        )
        last = info
        return info
    }

    private fun looksLikeIp(s: String): Boolean =
        Regex("^[0-9a-fA-F:.]{3,45}$").matches(s.trim()) && s.contains('.') || s.contains(':')

    /** Человекочитаемые строки для вкладки «О сети». */
    fun describe(info: DnsInfo): List<Pair<String, String>> {
        val out = mutableListOf<Pair<String, String>>()
        out.add(Msgs.DP_SYSTEM_DNS.t() to (info.servers.joinToString(", ").ifEmpty { Msgs.DP_NOT_DETERMINED.t() }))
        out.add(
            Msgs.DP_REAL_RESOLVER.t() to (info.realResolver?.let {
                val tag = if (info.realResolverIsRouter == true) Msgs.DP_ROUTER_SUFFIX.t() else Msgs.DP_UPPER_SUFFIX.t()
                it + tag
            } ?: Msgs.DP_UNDEFINED.t()),
        )
        out.add(Msgs.DP_DNSSEC.t() to when (info.dnssecOk) {
            true -> Msgs.DP_DNSSEC_YES.t()
            false -> Msgs.DP_DNSSEC_NO.t()
            null -> Msgs.DP_DNSSEC_FAIL.t()
        })
        out.add("DoT (TCP 853)" to when (info.dotReachable) {
            true -> Msgs.DP_DOT_AVAILABLE.t()
            false -> Msgs.DP_DOT_UNAVAILABLE.t()
            null -> Msgs.DP_NOT_CHECKED.t()
        })
        out.add("DoH (dns-query HTTPS)" to when (info.dohReachable) {
            true -> Msgs.DP_ECS_AVAILABLE.t()
            false -> Msgs.DP_ECS_UNAVAILABLE.t()
            null -> Msgs.DP_NOT_CHECKED.t()
        })
        out.add("ECS (Client Subnet)" to if (info.ecsSentByApp) Msgs.DP_ECC_SENT.t() else Msgs.DP_ECC_NOT_SENT.t())
        out.add(Msgs.DP_ECH.t() to info.sniEncryption)
        return out
    }
}