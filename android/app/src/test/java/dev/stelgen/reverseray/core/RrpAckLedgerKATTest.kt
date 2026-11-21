package dev.stelgen.reverseray.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Межъязыковой KAT (Go ↔ Kotlin) LEDGER Buffer/2 (docs/spec/ack.md):
 * те же векторы, что в server/internal/buf/ledger_test.go — байт-в-байт.
 * Меняя канон — обновляй вектор ОБЕИХ сторон.
 */
class RrpAckLedgerKATTest {

    companion object {
        private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private val VEC_1 = hex("0011")
        private val VEC_2 = hex("2233")
        private val VEC_3 = hex("445566")
    }

    private fun chunks(l: RrpAckLedger) = l.snapshot().map { it.bytes }

    @Test
    fun appendOffsetsAbsolute() {
        val l = RrpAckLedger()
        assertEquals(0L, l.append(VEC_1))
        assertEquals(2L, l.append(VEC_2))
        assertEquals(4L, l.append(VEC_3))
        assertEquals(3, l.size())
        assertEquals(0L, l.base)
        assertEquals(7L, l.end)
    }

    @Test
    fun evictStraddleTrimsHead() {
        val l = RrpAckLedger()
        l.append(VEC_1)
        l.append(VEC_2)
        l.append(VEC_3)
        l.evictTo(5) // 4 байта подтверждено целиком + 1 из головы straddle
        assertEquals(5L, l.base)
        assertArrayEquals(arrayOf(hex("5566")), chunks(l).toTypedArray())
        l.evictTo(7)
        assertEquals(0, l.size())
    }

    @Test
    fun evictBackwardsNoOp() {
        val l = RrpAckLedger()
        l.append(VEC_1)
        l.append(VEC_2)
        l.evictTo(2)
        l.evictTo(1) // назад — игнор
        assertEquals(2L, l.base)
        assertArrayEquals(arrayOf(VEC_2), chunks(l).toTypedArray())
    }

    @Test
    fun replayFromFloorsAndTrims() {
        val l = RrpAckLedger()
        l.append(VEC_1)
        l.append(VEC_2)
        l.append(VEC_3)
        l.evictTo(5)
        val replay = l.replayFrom(5)
        assertEquals(1, replay.size)
        assertEquals(5L, replay[0].offset)
        assertArrayEquals(hex("5566"), replay[0].bytes)
        assertEquals(0, l.replayFrom(7).size)
    }

    @Test
    fun setBaseOnResumeOnlyEmptyLedger() {
        val l = RrpAckLedger()
        l.append(VEC_1)
        l.setBase(10) // LEDGER не пуст — no-op
        assertEquals(0L, l.base)
        l.evictTo(2)
        l.setBase(10) // пуст — resume-нумерация с K
        assertEquals(10L, l.base)
        assertEquals(10L, l.append(VEC_2))
    }

    @Test
    fun chunkCopiesOnAppend() {
        val l = RrpAckLedger()
        val src = VEC_1.copyOf()
        l.append(src)
        src[0] = 0x7F.toByte() // владелец буфера переиспользовал — LEDGER не задет
        assertArrayEquals(VEC_1, l.snapshot()[0].bytes)
    }
}
