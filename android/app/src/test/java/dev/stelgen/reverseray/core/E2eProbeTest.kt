package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v1.8.0: юнит-тесты end-to-end пробника полезной нагрузки:
 * калибровка таймаутов от RTT-базлайна и классификация исходов
 * (успех / RST / read-timeout / троттлинг).
 */
class E2eProbeTest {

    // ------------------------------------------------------- timeoutFor

    @Test
    fun `timeout calibrated from rtt baseline and clamped`() {
        val cfg = E2eProbe.Cfg()
        // малый RTT: 6×100+2000 = 2600 → кламп в min 3000
        assertEquals(3_000L, E2eProbe.timeoutFor(100, cfg))
        // средний RTT: 6×500+2000 = 5000
        assertEquals(5_000L, E2eProbe.timeoutFor(500, cfg))
        // нет базлайна (rtt 0): base 2000 → кламп в min 3000 (ложно-живых нет)
        assertEquals(3_000L, E2eProbe.timeoutFor(0, cfg))
        // длинный RTT: 6×2000+2000 = 14000 → кламп в max 12000
        assertEquals(12_000L, E2eProbe.timeoutFor(2_000, cfg))
    }

    @Test
    fun `timeout cfg is injectable`() {
        val cfg = E2eProbe.Cfg(rttFactor = 2, baseMs = 100, minTimeoutMs = 50, maxTimeoutMs = 1_000)
        // 2×500+100 = 1100 → кламп в max 1000
        assertEquals(1_000L, E2eProbe.timeoutFor(500, cfg))
    }

    // ------------------------------------------------------- classify

    private fun res(
        elapsed: Long = 300,
        bytes: Int = 120,
        eof: Boolean = false,
        timedOut: Boolean = false,
        matched: Boolean = true,
    ) = E2eProbe.ReadResult(elapsed, bytes, eof, timedOut, matched)

    @Test
    fun `timeout outcome is dead`() {
        val o = E2eProbe.classify(res(timedOut = true, matched = false), rttEwmaMs = 100)
        assertEquals(E2eProbe.Outcome.ReadTimeout, o)
        assertTrue(o.isDead)
    }

    @Test
    fun `eof without bytes is rst and dead`() {
        val o = E2eProbe.classify(res(bytes = 0, eof = true, matched = false), rttEwmaMs = 100)
        assertEquals(E2eProbe.Outcome.Rst, o)
        assertTrue(o.isDead)
    }

    @Test
    fun `fast matched response is ok and alive`() {
        val o = E2eProbe.classify(res(elapsed = 300), rttEwmaMs = 100)
        assertEquals(E2eProbe.Outcome.Ok(300, 120), o)
        assertFalse(o.isDead)
    }

    @Test
    fun `slow matched response is throttle not dead`() {
        // baseline = max(8×100, 6000) = 6000; 9000 > 6000 → троттлинг
        val o = E2eProbe.classify(res(elapsed = 9_000), rttEwmaMs = 100)
        assertEquals(E2eProbe.Outcome.Throttle(9_000, 6_000), o)
        assertFalse(o.isDead)
    }

    @Test
    fun `long rtt raises throttle baseline`() {
        // baseline = max(8×1500, 6000) = 12000; 9000 < 12000 → Ok
        val o = E2eProbe.classify(res(elapsed = 9_000), rttEwmaMs = 1_500)
        assertEquals(E2eProbe.Outcome.Ok(9_000, 120), o)
    }

    @Test
    fun `bytes without marker mid-cut is rst`() {
        val o = E2eProbe.classify(res(matched = false, eof = true), rttEwmaMs = 100)
        assertEquals(E2eProbe.Outcome.Rst, o)
        assertTrue(o.isDead)
    }

    @Test
    fun `marker is configurable`() {
        val cfg = E2eProbe.Cfg(marker = "OK")
        val hit = E2eProbe.classify(res(matched = true), rttEwmaMs = 100, cfg = cfg)
        assertEquals(E2eProbe.Outcome.Ok(300, 120), hit)
    }
}
