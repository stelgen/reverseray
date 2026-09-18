package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RrpUriTest {

    @Test
    fun parseAndRoundtrip() {
        val uri = "rrp://tok123@srv.example.com:443,8443/?pin=abc-123&name=My%20Home"
        val p = RrpUri.parse(uri)
        assertEquals("tok123", p.token)
        assertEquals("srv.example.com", p.host)
        assertEquals(listOf(443, 8443), p.ports)
        assertEquals("abc-123", p.pin)
        assertEquals("My Home", p.name)
        assertEquals(uri, p.toUri())
    }

    @Test
    fun minimalUri() {
        val p = RrpUri.parse("rrp://t@h:443")
        assertEquals("h", p.host)
        assertEquals(listOf(443), p.ports)
        assertEquals("h", p.name)
    }

    @Test
    fun lanFlagRoundtrip() {
        val p = RrpUri.parse("rrp://t@h:443/?lan=1")
        assertTrue(p.allowLan)
    }

    @Test
    fun rejects() {
        assertThrows(IllegalArgumentException::class.java) { RrpUri.parse("https://x") }
        assertThrows(IllegalArgumentException::class.java) { RrpUri.parse("rrp://t@h") }
        assertThrows(IllegalArgumentException::class.java) { RrpUri.parse("rrp://@h:443") }
        assertThrows(IllegalArgumentException::class.java) { RrpUri.parse("rrp://t@h:0") }
        assertThrows(IllegalArgumentException::class.java) { RrpUri.parse("rrp://t@h:99999") }
    }
}
