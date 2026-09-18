package dev.stelgen.reverseray.core

import java.net.Inet4Address
import java.net.InetAddress

/**
 * Anti-SSRF guard: refuses to dial private/loopback/link-local ranges
 * unless the user explicitly enabled LAN access.
 */
object SsrfGuard {

    // (name, base ip bytes, prefix bits)
    private val BLOCKED_V4 = listOf(
        "0.0.0.0/8" to cidr(intArrayOf(0, 0, 0, 0), 8),
        "10.0.0.0/8" to cidr(intArrayOf(10, 0, 0, 0), 8),
        "100.64.0.0/10" to cidr(intArrayOf(100, 64, 0, 0), 10),   // CGNAT
        "127.0.0.0/8" to cidr(intArrayOf(127, 0, 0, 0), 8),
        "169.254.0.0/16" to cidr(intArrayOf(169, 254, 0, 0), 16), // link-local
        "172.16.0.0/12" to cidr(intArrayOf(172, 16, 0, 0), 12),
        "192.168.0.0/16" to cidr(intArrayOf(192, 168, 0, 0), 16),
        "198.18.0.0/15" to cidr(intArrayOf(198, 18, 0, 0), 15),   // benchmark
        "224.0.0.0/4" to cidr(intArrayOf(224, 0, 0, 0), 4),       // multicast
        "240.0.0.0/4" to cidr(intArrayOf(240, 0, 0, 0), 4)        // reserved
    )

    private val HOSTNAME_BLOCKED = setOf("localhost", "ip6-localhost", "ip6-loopback")

    fun cidr(base: IntArray, prefix: Int): Pair<ByteArray, Int> =
        ByteArray(4) { base[it].toByte() } to prefix

    fun isBlocked(host: String, allowLan: Boolean = false): Boolean {
        if (allowLan) return false
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty()) return true
        if (h in HOSTNAME_BLOCKED) return true
        val addr: InetAddress = runCatching { InetAddress.getByName(h) }.getOrNull() ?: return true
        return when (addr) {
            is Inet4Address -> matchesV4(addr.address)
            else -> isBlockedV6(addr.address)
        }
    }

    fun matchesV4(ip: ByteArray): Boolean {
        val v = ip.toInt() and 0xFFFFFFFFL
        val top = (v ushr 24) and 0xFF
        if (top == 0.toLong() || top == 127.toLong()) return true
        for ((cidrName, m) in BLOCKED_V4) {
            if (matches(ip, m.first, m.second)) return true
        }
        return false
    }

    private fun matches(ip: ByteArray, base: ByteArray, prefix: Int): Boolean {
        val fullBytes = prefix / 8
        for (i in 0 until fullBytes) {
            if (ip[i] != base[i]) return false
        }
        val rem = prefix % 8
        if (rem == 0) return true
        val mask = (0xFF shl (8 - rem)) and 0xFF
        return (ip[fullBytes].toInt() and mask) == (base[fullBytes].toInt() and mask)
    }

    fun isBlockedV6(ip: ByteArray): Boolean {
        // IPv4-mapped
        val mapped = ip.size == 16 && ip.sliceArray(0..9).all { it == 0.toByte() } &&
                ip[10] == 0xFF.toByte() && ip[11] == 0xFF.toByte()
        if (mapped) return matchesV4(ip.sliceArray(12..15))
        val top = ((ip[0].toInt() and 0xFF) shl 8) or (ip[1].toInt() and 0xFF)
        return top == 0x0000 ||  // ::/128 unspecified, ::1 loopback is 0x0000..1
                (top and 0xFFC0) == 0xFC00 ||  // fc00::/7 ULA
                (top and 0xFFC0) == 0xFE80 ||  // fe80::/10 link-local
                (top and 0xFFF0) == 0xFF00     // ff00::/8 multicast
    }
}
