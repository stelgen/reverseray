package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * v1.8.1: id стримов телефона — ЧЁТНЫЕ (серверные — нечётные:
 * server/session.openStream nextID += 2). Регрессия v1.8.0: E2E-пробник
 * брал нечётный id → коллизия с серверным пространством.
 */
class PhoneStreamIdTest {

    @Test
    fun `phone stream ids are even`() {
        for (seq in 1L..100L) {
            val id = RrpClient.phoneStreamId(seq)
            assertEquals("id=$id нечётный", 0L, id % 2)
        }
    }

    @Test
    fun `phone ids never collide with server odd space`() {
        // серверные: 1,3,5,7...; телефонные: 2,4,6,8...
        val serverIds = (1..1000L).map { it * 2 - 1 }.toSet()
        for (seq in 1L..1000L) {
            assertNotEquals("коллизия с серверным id", true, RrpClient.phoneStreamId(seq) in serverIds)
        }
    }

    @Test
    fun `u32 overflow wraps safely staying even`() {
        // seq большой → *2 > u32 → маска заворачивает, чётность сохраняется
        val id = RrpClient.phoneStreamId(0x7FFFFFFFL)
        assertEquals(0xFFFFFFFEL, id)
        assertEquals(0L, id % 2)
    }

    @Test
    fun `first allocated id is 2`() {
        assertEquals(2L, RrpClient.phoneStreamId(1L))
    }
}
