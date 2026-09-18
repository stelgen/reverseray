package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RrpUriTest {

    @Test
    fun `parse full uri`() {
        val cfg = RrpUri.parse("rrp://tok123@vpn.example.net:443,8443/?pin=AAECAw&name=Home")
        assertEquals("tok123", cfg.token)
        assertEquals("vpn.example.net", cfg.host)
        assertEquals(listOf(443, 8443), cfg.ports)
        assertEquals("AAECAw", cfg.pin)
        assertEquals("Home", cfg.name)
    }

    @Test
    fun `canonical string serialize roundtrip`() {
        val raw = "rrp://token@host.example:443,8443/?pin=SPKI&name=Home"
        assertEquals(raw, RrpUri.parse(raw).serialize())
    }

    @Test
    fun `parse-serialize roundtrip with encoding`() {
        val cfg = RrpUriConfig(
            token = "tok en/прикол",
            host = "2001:db8::1",
            ports = listOf(443, 8443, 9443),
            pin = "q83hAbcd=",
            name = "Дом/Работа 1",
        )
        val parsed = RrpUri.parse(cfg.serialize())
        assertEquals(cfg, parsed)
    }

    @Test
    fun `parse without query and with ipv6 host`() {
        val cfg = RrpUri.parse("rrp://t@[2001:db8::1]:443")
        assertEquals("t", cfg.token)
        assertEquals("2001:db8::1", cfg.host)
        assertEquals(listOf(443), cfg.ports)
        assertEquals("rrp://t@[2001:db8::1]:443", cfg.serialize())
    }

    @Test
    fun `case-insensitive scheme`() {
        val cfg = RrpUri.parse("RRP://t@h.example:443")
        assertEquals("t", cfg.token)
    }

    @Test
    fun `errors`() {
        assertThrows(RrpUriException::class.java) { RrpUri.parse("http://t@h:443") }
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://h:443") }          // нет @
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://@h:443") }         // пустой токен
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://t@h") }            // нет портов
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://t@h:0") }          // порт < 1
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://t@h:99999") }      // порт > 65535
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://t@h:abc") }        // порт не число
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://t@[2001:db8::1") } // нет ]
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://t@h:443/?pin=%ZZ") }
        assertThrows(RrpUriException::class.java) { RrpUri.parse("rrp://t@h:443/?pin=%A") } // обрезанный pct
    }
}
