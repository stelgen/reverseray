package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class RrpFrameTest {

    @Test
    fun roundtrip() {
        val payload = "hello".toByteArray()
        val out = ByteArrayOutputStream()
        RrpFrame.write(out, RrpFrame.TYPE_DATA, 0x42, 7, payload)
        val f = RrpFrame.read(ByteArrayInputStream(out.toByteArray()))
        assertEquals(RrpFrame.TYPE_DATA, f.type)
        assertEquals(0x42, f.flags)
        assertEquals(7L, f.streamId)
        assertEquals("hello", String(f.payload))
    }

    @Test
    fun oversizedDataRejectedOnWrite() {
        assertThrows(IOException::class.java) {
            RrpFrame.write(ByteArrayOutputStream(), RrpFrame.TYPE_DATA, 0, 1,
                ByteArray(RrpFrame.MAX_DATA_PAYLOAD + 1))
        }
    }

    @Test
    fun oversizedControlRejected() {
        assertThrows(IOException::class.java) {
            RrpFrame.write(ByteArrayOutputStream(), RrpFrame.TYPE_AUTH, 0, 0,
                ByteArray(RrpFrame.MAX_CONTROL_PAYLOAD + 1))
        }
    }

    @Test
    fun badVersionRejected() {
        val raw = byteArrayOf(2, RrpFrame.TYPE_DATA.toByte(), 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 65)
        assertThrows(java.io.IOException::class.java) {
            RrpFrame.read(ByteArrayInputStream(raw))
        }
    }

    @Test
    fun truncatedPayloadThrows() {
        val raw = byteArrayOf(1, RrpFrame.TYPE_DATA.toByte(), 0, 0, 0, 0, 0, 1, 0, 0, 0, 5, 1, 2)
        assertThrows(java.io.EOFException::class.java) {
            RrpFrame.read(ByteArrayInputStream(raw))
        }
    }

    @Test
    fun openPayloadDomainRoundtrip() {
        val p = RrpFrame.encodeOpen(RrpFrame.ATYP_DOMAIN, "example.com".toByteArray(), 443)
        assertEquals(RrpFrame.ATYP_DOMAIN, p[0].toInt() and 0xFF)
        assertEquals(11, p[1].toInt() and 0xFF)
        assertEquals(443, ((p[p.size - 2].toInt() and 0xFF) shl 8) or (p.last().toInt() and 0xFF))
        assertTrue(p.size == 1 + 1 + 11 + 2)
    }
}
