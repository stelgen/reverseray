package dev.stelgen.reverseray.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Кодек UDP-кадров RRP (v0.7): UDP_ASSOC / UDP_DATA. */
class UdpFrameTest {

    @Test
    fun `udp assoc encodes empty payload with stream id`() {
        val f = RrpFrame.UdpAssoc(42L)
        val bytes = f.encode()
        assertEquals(RrpFrame.TYPE_UDP_ASSOC, bytes[1].toInt() and 0xFF)
        assertEquals(12, bytes.size)
        val parsed = RrpFrame.parse(bytes)
        assertTrue(parsed is RrpFrame.UdpAssoc)
        assertEquals(42L, parsed.streamId)
    }

    @Test
    fun `udp data ipv4 round trip`() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val f = RrpFrame.UdpData(7L, RrpAddress.ATYP_IPV4, byteArrayOf(8, 8, 4, 4), 53, data)
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.UdpData
        assertEquals(7L, parsed.streamId)
        assertEquals(RrpAddress.ATYP_IPV4, parsed.atyp)
        assertArrayEquals(byteArrayOf(8, 8, 4, 4), parsed.addr)
        assertEquals(53, parsed.port)
        assertArrayEquals(data, parsed.bytes)
    }

    @Test
    fun `udp data domain round trip`() {
        val host = "example.com"
        val encoded = RrpAddress.encodeAddr(host) // [len][name]
        val f = RrpFrame.UdpData(9L, encoded.atyp, encoded.bytes, 443, "x".toByteArray())
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.UdpData
        assertEquals("example.com", RrpAddress.decodeAddr(parsed.atyp, parsed.addr))
        assertEquals(443, parsed.port)
    }

    @Test
    fun `udp data ipv6 round trip`() {
        val addr = ByteArray(16) { (it * 3).toByte() }
        val f = RrpFrame.UdpData(3L, RrpAddress.ATYP_IPV6, addr, 5353, "v6".toByteArray())
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.UdpData
        assertArrayEquals(addr, parsed.addr)
        assertEquals(5353, parsed.port)
        assertEquals(RrpAddress.ATYP_IPV6, parsed.atyp)
    }

    @Test
    fun `udp data follows data payload limit`() {
        assertEquals(
            RrpFrame.maxPayloadFor(RrpFrame.TYPE_DATA),
            RrpFrame.maxPayloadFor(RrpFrame.TYPE_UDP_DATA),
        )
    }
}
