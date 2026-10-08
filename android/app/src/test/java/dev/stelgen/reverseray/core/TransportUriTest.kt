package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** transport=ws/tcp в rrp:// строке (v0.7). */
class TransportUriTest {

    @Test
    fun `default transport is tcp`() {
        val cfg = RrpUri.parse("rrp://tok@h:4433/?pin=abc")
        assertEquals(RrpUri.TRANSPORT_TCP, cfg.transport)
    }

    @Test
    fun `transport ws parses`() {
        val cfg = RrpUri.parse("rrp://tok@h:4433/?pin=abc&transport=WS")
        assertEquals(RrpUri.TRANSPORT_WS, cfg.transport)
    }

    @Test
    fun `transport ws serializes back`() {
        val cfg = RrpUri.parse("rrp://tok@h:4433/?pin=abc&transport=ws&name=Home")
        assertEquals(RrpUri.TRANSPORT_WS, cfg.transport)
        val s = cfg.serialize()
        assertTrue(s.contains("transport=ws"))
        assertEquals(cfg, RrpUri.parse(s))
    }

    @Test
    fun `tcp transport not serialized (default)`() {
        val cfg = RrpUri.parse("rrp://tok@h:4433/?transport=tcp")
        assertTrue(!cfg.serialize().contains("transport"))
    }

    @Test
    fun `unknown transport rejected`() {
        assertThrows(RrpUriException::class.java) {
            RrpUri.parse("rrp://tok@h:4433/?transport=grpc")
        }
    }
}
