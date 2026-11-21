package dev.stelgen.reverseray.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Межъязыковой KAT (Go ↔ Kotlin) ядра Buffer/1 (docs/spec/buffer.md):
 * те же hex-векторы, что в server/internal/buf/buf_test.go — байт-в-байт.
 * Меняя канон — обновляй вектор ОБЕИХ сторон.
 */
class RrpStreamBufferKATTest {

    companion object {
        private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private val VEC_A = hex("616263") // «abc»
        private val VEC_B = hex("6465")   // «de»
        private val VEC_C = hex("2122")   // повторная попытка
        private val VEC_BIG = ByteArray(90 * 1024) { 0x11 }
    }

    @Test
    fun pushAndPollFifo() {
        val b = RrpStreamBuffer()
        assertTrue(b.push(VEC_A))
        assertTrue(b.push(VEC_B))
        assertTrue(b.push(VEC_C))
        assertEquals(VEC_A.size + VEC_B.size + VEC_C.size, b.len())
        assertArrayEquals(VEC_A, b.poll())
        assertArrayEquals(VEC_B, b.poll())
        assertArrayEquals(VEC_C, b.poll())
        assertNull(b.poll())
        assertEquals(0, b.len())
    }

    @Test
    fun overflowFails() {
        val b = RrpStreamBuffer()
        assertTrue(b.push(VEC_BIG))
        assertTrue(b.push(VEC_BIG))
        assertEquals(2 * 90 * 1024, b.len())
        // MODE_FAIL: переполнение — false, данные не принимаются (не блокируются)
        assertFalse(b.push(VEC_BIG)) // 184320+92160 > 262144
        assertEquals(2 * 90 * 1024, b.len())
    }

    @Test
    fun pushFrontRestoresOrder() {
        val b = RrpStreamBuffer()
        assertTrue(b.push(VEC_A))
        assertTrue(b.push(VEC_B))
        val first = b.poll()!!
        assertArrayEquals(VEC_A, first)
        b.pushFront(first)
        assertArrayEquals(VEC_A, b.poll())
        assertArrayEquals(VEC_B, b.poll())
    }

    @Test
    fun clearEmpties() {
        val b = RrpStreamBuffer()
        assertTrue(b.push(VEC_A))
        b.clear()
        assertEquals(0, b.len())
        assertNull(b.poll())
    }
}
