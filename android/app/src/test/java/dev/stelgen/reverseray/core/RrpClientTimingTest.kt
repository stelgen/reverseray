package dev.stelgen.reverseray.core

import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/** Тайминги клиента: PING 60с ±10%, backoff 1→60с ±30%, кап 60с. */
class RrpClientTimingTest {

    @Test
    fun `ping interval within jitter band`() {
        val rnd = Random(42)
        repeat(200) {
            val ms = RrpClient.pingIntervalMs(rnd)
            assertTrue("ping $ms вне [54с;66с]", ms in 54_000L..66_000L)
        }
    }

    @Test
    fun `backoff grows exponentially and caps at 60s`() {
        val rnd = Random(7)
        var prevMin = 0L
        for (attempt in 0..6) {
            val samples = List(50) { RrpClient.backoffDelayMs(attempt, rnd) }
            val min = samples.min()
            val max = samples.max()
            // база = 2^attempt секунд, джиттер ±30% → min >= 0.7*base, max <= 1.3*base
            val base = (1L shl attempt).coerceAtMost(60L) * 1000L
            assertTrue("attempt=$attempt min=$min < 0.7*base", min >= base * 7 / 10)
            assertTrue("attempt=$attempt max=$max > 1.3*base", max <= base * 13 / 10 + 1)
            assertTrue(min >= prevMin)
            prevMin = min
        }
        // после капа — все в районе 60с
        for (attempt in 6..12) {
            val ms = RrpClient.backoffDelayMs(attempt, rnd)
            assertTrue("attempt=$attempt ms=$ms вне кап-диапазона", ms in 42_000L..78_000L)
        }
    }
}
