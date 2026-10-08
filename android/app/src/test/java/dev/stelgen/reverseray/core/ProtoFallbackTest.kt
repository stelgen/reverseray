package dev.stelgen.reverseray.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v0.8.1: клиентский фоллбек протоколов. Канон: фоллбечит ТОЛЬКО клиент
 * (на rrp1), сервер — никогда (иначе цикл из-за рассинхрона обновлений
 * и заморозки модулей при выключенном авто-обновлении).
 */
class ProtoFallbackTest {

    @Test
    fun `falls back after threshold on non-base protocol`() {
        assertFalse(ProtoFallback.shouldFallback("mtproto2", 0))
        assertFalse(ProtoFallback.shouldFallback("mtproto2", ProtoFallback.THRESHOLD - 1))
        assertTrue(ProtoFallback.shouldFallback("mtproto2", ProtoFallback.THRESHOLD))
        assertTrue(ProtoFallback.shouldFallback("mtproto2", ProtoFallback.THRESHOLD + 5))
    }

    @Test
    fun `never falls back on base protocol`() {
        assertFalse(ProtoFallback.shouldFallback("rrp1", 1))
        assertFalse(ProtoFallback.shouldFallback("rrp1", 100))
    }

    @Test
    fun `garbage proto never falls back`() {
        assertFalse(ProtoFallback.shouldFallback("", 10))
        assertFalse(ProtoFallback.shouldFallback("!!!мусор!!!", 10))
        assertFalse(ProtoFallback.shouldFallback("   ", 10))
    }

    @Test
    fun `fallback reason explains client-only rollback`() {
        val reason = ProtoFallback.fallbackReason("mtproto2")
        assertTrue("причина должна упоминать протокол", reason.contains("mtproto2") || reason.contains("MTProto"))
        assertTrue("причина должна объяснять клиентский фоллбек", reason.contains("клиент"))
        assertTrue("причина должна объяснять, что сервер не откатывается", reason.contains("сервер"))
    }
}
