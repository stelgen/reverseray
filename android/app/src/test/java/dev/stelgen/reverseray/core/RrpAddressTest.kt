package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class RrpAddressTest {

    @Test
    fun `ssrf guard blocks every listed range`() {
        val blocked = listOf(
            "0.0.0.0", "0.1.2.3",                      // 0/8
            "10.0.0.1", "10.255.255.255",              // 10/8
            "100.64.0.1", "100.127.255.255",           // 100.64/10
            "127.0.0.1", "127.8.8.8",                  // 127/8
            "169.254.1.1",                             // 169.254/16
            "172.16.0.1", "172.31.255.255",            // 172.16/12
            "192.168.1.1",                             // 192.168/16
            "198.18.0.1", "198.19.255.255",            // 198.18/15
            "224.0.0.1", "239.255.255.255",            // 224/4
            "240.0.0.1", "255.255.255.255",            // 240/4
            "::1",                                     // loopback
            "fc00::1", "fd12:3456::1",                 // fc00::/7
            "fe80::1",                                 // fe80::/10
            "ff02::1",                                 // ff00::/8
            "localhost", "myhost.localhost", "ip6-localhost",
        )
        for (h in blocked) {
            assertTrue("должен быть заблокирован: $h", SsrfGuard.isBlocked(h))
        }
    }

    @Test
    fun `public hosts are not blocked`() {
        assertFalse(SsrfGuard.isBlocked("8.8.8.8"))
        assertFalse(SsrfGuard.isBlocked("1.1.1.1"))
        assertFalse(SsrfGuard.isBlocked("example.com"))
    }

    @Test
    fun `allow lan unblocks rfc1918 and cgnat but not loopback`() {
        assertFalse(SsrfGuard.isBlocked("192.168.1.1", allowLan = true))
        assertFalse(SsrfGuard.isBlocked("10.1.2.3", allowLan = true))
        assertFalse(SsrfGuard.isBlocked("172.16.0.9", allowLan = true))
        assertFalse(SsrfGuard.isBlocked("100.64.0.9", allowLan = true))
        assertFalse(SsrfGuard.isBlocked("fd00::1", allowLan = true))

        assertTrue(SsrfGuard.isBlocked("127.0.0.1", allowLan = true))
        assertTrue(SsrfGuard.isBlocked("localhost", allowLan = true))
        assertTrue(SsrfGuard.isBlocked("169.254.10.10", allowLan = true))
        assertTrue(SsrfGuard.isBlocked("224.0.0.5", allowLan = true))
        assertTrue(SsrfGuard.isBlocked("fe80::1", allowLan = true))
    }

    @Test
    fun `ipv4-mapped ipv6 follows v4 rules`() {
        assertTrue(SsrfGuard.isBlocked("::ffff:192.168.1.1"))
        assertTrue(SsrfGuard.isBlocked("::ffff:127.0.0.1"))
        assertFalse(SsrfGuard.isBlocked("::ffff:8.8.8.8"))
    }

    @Test
    fun `decimal host form is checked as ipv4`() {
        assertTrue(SsrfGuard.isBlocked("2130706433"))     // 127.0.0.1
        assertFalse(SsrfGuard.isBlocked("134744072"))     // 8.8.8.8
    }

    @Test
    fun `unspecified ipv6 blocked`() {
        assertTrue(SsrfGuard.isBlocked("::"))
    }

    @Test
    fun `open payload encode-parse roundtrip`() {
        for (host in listOf("example.com", "203.0.113.7", "2001:db8::1")) {
            val payload = RrpAddress.encodeOpen(host, 8443)
            val t = RrpAddress.parseOpen(payload)
            assertEquals(host, t.host)
            assertEquals(8443, t.port)
            assertEquals(payload.size, t.bytesRead)
        }
    }

    @Test
    fun `ipv6 formatting is canonical`() {
        val b = RrpAddress.parseIpv6Literal("2001:0db8:0000:0000:0000:0000:0000:0001")!!
        assertEquals("2001:db8::1", RrpAddress.formatIpv6(b))
    }

    @Test
    fun `parse open errors`() {
        for (bad in listOf(
            ByteArray(0),                             // пустой
            byteArrayOf(9, 0, 1, 0, 1),               // неизвестный atyp
            byteArrayOf(3, 20, 'a'.code.toByte()),    // домен обрезан
            byteArrayOf(1, 1, 2, 3),                  // нет порта
        )) {
            try {
                RrpAddress.parseOpen(bad)
                fail("ожидался AddressException для ${bad.contentToString()}")
            } catch (e: RrpAddress.AddressException) {
                // ок
            }
        }
    }

    @Test
    fun `encode addr rejects invalid ipv6 literal`() {
        try {
            RrpAddress.encodeAddr(":::")
            fail("ожидался AddressException")
        } catch (e: RrpAddress.AddressException) {
            // ок
        }
    }
}
