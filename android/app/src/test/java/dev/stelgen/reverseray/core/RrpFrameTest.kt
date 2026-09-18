package dev.stelgen.reverseray.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.EOFException

class RrpFrameTest {

    private fun header(type: Int, len: Int, ver: Int = 1, streamId: Int = 0): ByteArray {
        val h = ByteArray(12)
        h[0] = ver.toByte()
        h[1] = type.toByte()
        h[4] = ((streamId ushr 24) and 0xFF).toByte()
        h[5] = ((streamId ushr 16) and 0xFF).toByte()
        h[6] = ((streamId ushr 8) and 0xFF).toByte()
        h[7] = (streamId and 0xFF).toByte()
        h[8] = ((len ushr 24) and 0xFF).toByte()
        h[9] = ((len ushr 16) and 0xFF).toByte()
        h[10] = ((len ushr 8) and 0xFF).toByte()
        h[11] = (len and 0xFF).toByte()
        return h
    }

    @Test
    fun `roundtrip data frame`() {
        val f = RrpFrame.Data(42L, 0, byteArrayOf(1, 2, 3, 4))
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.Data
        assertEquals(42L, parsed.streamId)
        assertArrayEquals(f.bytes, parsed.bytes)
    }

    @Test
    fun `roundtrip hello json frame`() {
        val f = RrpFrame.Hello("агент/1 \"тест\"", 1, listOf("chacha20", "alpn"), 64)
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.Hello
        assertEquals("агент/1 \"тест\"", parsed.agent)
        assertEquals(1, parsed.protocolVersion)
        assertEquals(listOf("chacha20", "alpn"), parsed.caps)
        assertEquals(64, parsed.maxStreams)
    }

    @Test
    fun `roundtrip ready frame`() {
        val f = RrpFrame.Ready("t-123", "egress", 32, 524288L)
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.Ready
        assertEquals("t-123", parsed.tunnelId)
        assertEquals("egress", parsed.role)
        assertEquals(32, parsed.maxStreams)
        assertEquals(524288L, parsed.tunnelWindow)
    }

    @Test
    fun `roundtrip open frame with domain`() {
        val addr = RrpAddress.encodeAddr("example.com")
        val f = RrpFrame.Open(9L, addr.atyp, addr.bytes, 8443)
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.Open
        assertEquals(9L, parsed.streamId)
        assertEquals(RrpAddress.ATYP_DOMAIN, parsed.atyp)
        assertEquals(8443, parsed.port)
        assertEquals("example.com", RrpAddress.decodeAddr(parsed.atyp, parsed.addr))
    }

    @Test
    fun `roundtrip ping pong nonce`() {
        val nonce = ByteArray(8) { it.toByte() }
        val pong = RrpFrame.parse(RrpFrame.Ping(nonce).encode()) as? RrpFrame.Pong // safe cast: ping не является pong
        assertTrue(pong == null) // ping не должен декодироваться как pong
        val p = RrpFrame.parse(RrpFrame.Ping(nonce).encode()) as RrpFrame.Ping
        assertArrayEquals(nonce, p.nonce)
        val q = RrpFrame.parse(RrpFrame.Pong(nonce).encode()) as RrpFrame.Pong
        assertArrayEquals(nonce, q.nonce)
    }

    @Test
    fun `roundtrip error frame`() {
        val f = RrpFrame.ErrorFrame(403, "denied: нет подписки")
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.ErrorFrame
        assertEquals(403, parsed.code)
        assertEquals("denied: нет подписки", parsed.message)
    }

    @Test
    fun `window frame max u32 increment`() {
        val f = RrpFrame.Window(7L, 0xFFFFFFFFL)
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.Window
        assertEquals(7L, parsed.streamId)
        assertEquals(0xFFFFFFFFL, parsed.increment)
    }

    @Test
    fun `oversized data payload rejected on encode`() {
        try {
            RrpFrame.Data(1L, 0, ByteArray(RrpFrame.MAX_DATA_PAYLOAD + 1)).encode()
            fail("ожидался RrpFrameException")
        } catch (e: RrpFrameException) {
            assertTrue(e.message!!.contains("лимита"))
        }
    }

    @Test
    fun `oversized control payload rejected on encode`() {
        try {
            RrpFrame.Stats("x".repeat(RrpFrame.MAX_CONTROL_PAYLOAD + 1)).encode()
            fail("ожидался RrpFrameException")
        } catch (e: RrpFrameException) {
            assertTrue(e.message!!.contains("лимита"))
        }
    }

    @Test
    fun `oversized data payload rejected on parse`() {
        // len = 65536 = 0x00010000 при типе DATA — выше лимита
        val h = header(RrpFrame.TYPE_DATA, 65536)
        try {
            RrpFrame.parse(h)
            fail("ожидался RrpFrameException")
        } catch (e: RrpFrameException) {
            assertTrue(e.message!!.contains("лимита"))
        }
    }

    @Test
    fun `oversized control payload rejected on parse`() {
        // len = 4097 при типе HELLO — выше контрольного лимита
        val h = header(RrpFrame.TYPE_HELLO, 4097)
        try {
            RrpFrame.parse(h)
            fail("ожидался RrpFrameException")
        } catch (e: RrpFrameException) {
            assertTrue(e.message!!.contains("лимита"))
        }
    }

    @Test
    fun `malformed header - wrong version`() {
        val h = header(RrpFrame.TYPE_DATA, 0, ver = 2)
        try {
            RrpFrame.parse(h)
            fail("ожидался RrpFrameException")
        } catch (e: RrpFrameException) {
            assertTrue(e.message!!.contains("версия"))
        }
    }

    @Test
    fun `malformed header - unknown type`() {
        val h = header(0xAB, 0)
        try {
            RrpFrame.parse(h)
            fail("ожидался RrpFrameException")
        } catch (e: RrpFrameException) {
            assertTrue(e.message!!.contains("неизвестный тип"))
        }
    }

    @Test
    fun `malformed header - truncated payload`() {
        val h = header(RrpFrame.TYPE_DATA, 10)
        val body = ByteArray(5)
        val buf = h + body
        try {
            RrpFrame.parse(ByteArrayInputStream(buf))
            fail("ожидался EOFException")
        } catch (e: EOFException) {
            // ок
        }
    }

    @Test
    fun `malformed header - short header`() {
        try {
            RrpFrame.parse(ByteArrayInputStream(ByteArray(11)))
            fail("ожидался EOFException")
        } catch (e: EOFException) {
            // ок
        }
    }

    @Test
    fun `auth and hello-ok json roundtrip`() {
        val a = RrpFrame.parse(RrpFrame.Auth("token-hmac", "aaBBcc==", "n0nc3=").encode()) as RrpFrame.Auth
        assertEquals("token-hmac", a.mode)
        assertEquals("aaBBcc==", a.hmacB64)
        assertEquals("n0nc3=", a.nonceB64)

        val ok = RrpFrame.parse(
            RrpFrame.HelloOk("sess-1", "0.1.0", 262144L).encode()
        ) as RrpFrame.HelloOk
        assertEquals("sess-1", ok.sessionId)
        assertEquals("0.1.0", ok.serverVer)
        assertEquals(262144L, ok.tunnelWindow)
    }
}
