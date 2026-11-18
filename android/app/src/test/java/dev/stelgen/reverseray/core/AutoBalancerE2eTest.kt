package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v1.8.0: A/B старого и нового детекта AutoBalancer на ОДНИХ fixture-снимках.
 *
 * Сценарий-фикстура — ТСПУ-блокировка по сигнатурам: контрольные кадры живы
 * (PING без потерь, RTT в норме, серверный PROBE ок), а payload режется →
 * E2E-пробник видит read-timeout/rst.
 *
 *  - ВАРИАНТ A (старый детект, Sample без e2e): связь выглядит живой —
 *    смена НЕ происходит (ложно-живое соединение);
 *  - ВАРИАНТ B (новый детект, Sample с e2e): мёртвый исход → deadLoss,
 *    смена вне гистерезиса (кулдаун/память провалов сохранены).
 */
class AutoBalancerE2eTest {

    private fun cfg() = AutoBalancer.Cfg(
        degradeWindowMs = 1_000,
        minSamples = 2,
        stabilityWindowMs = 2_000,
        minSwitchIntervalMs = 1_000,
        maxCooldownMs = 8_000,
        failCooldownMs = 5_000,
    )

    private fun bal() = AutoBalancer(cfg()).apply {
        candidates = listOf("mtproto2", "wireguard", "bittorrent")
        current = "wireguard"
    }

    /** Fixture: «живые» контрольные кадры (ТСПУ режет только payload). */
    private fun controlAlive(at: Long) = AutoBalancer.Sample(
        atMs = at, rttMs = 100, lossRatio = 0.0, probeOk = true,
    )

    /** Fixture + E2E: payload режется (read-timeout). */
    private fun e2eDead(at: Long) = controlAlive(at).copy(
        e2e = E2eProbe.Outcome.ReadTimeout,
    )

    @Test
    fun `AB - signature block - old detection never switches`() {
        val b = bal()
        // старый детект: 10 минут «идеальных» контрольных проб — молчание
        for (i in 0 until 120) {
            assertEquals(AutoBalancer.Decision.Nothing, b.onSample(controlAlive(i * 5_000L)))
        }
    }

    @Test
    fun `AB - signature block - new detection switches immediately as dead`() {
        val b = bal()
        val d = b.onSample(e2eDead(0))
        assertTrue("E2E-мёртвый исход обязан переключать вне гистерезиса: $d", d is AutoBalancer.Decision.Switch)
        assertEquals("bittorrent", (d as AutoBalancer.Decision.Switch).target)
        assertTrue("причина содержит классификацию исхода", d.reason.contains("read-timeout"))
    }

    @Test
    fun `AB - new detection keeps hysteresis for throttle`() {
        val b = bal()
        // троттлинг — НЕ мёртвый путь: обычный гистерезис (первая проба — Wait)
        val slow = controlAlive(0).copy(e2e = E2eProbe.Outcome.Throttle(9_000, 6_000))
        assertEquals(AutoBalancer.Decision.Wait::class, b.onSample(slow)::class)
        val d = b.onSample(slow.copy(atMs = 900))
        assertTrue("устойчивый троттлинг обязан переключать: $d", d is AutoBalancer.Decision.Switch)
    }

    @Test
    fun `AB - e2e ok does not poison old signals`() {
        val b = bal()
        val ok = controlAlive(0).copy(e2e = E2eProbe.Outcome.Ok(300, 120))
        assertEquals(AutoBalancer.Decision.Nothing, b.onSample(ok))
    }

    @Test
    fun `AB - dead via e2e bypasses stability window but respects cooldown`() {
        val b = bal()
        b.onSample(e2eDead(0))
        val d = b.onSample(e2eDead(500))
        b.onSwitchResult(600, (d as AutoBalancer.Decision.Switch).target, ok = true)
        // stability window (2с): e2e-обрыв НЕ ждёт stability, но кулдаун (1с) жив
        assertTrue(b.onSample(e2eDead(1_100)) is AutoBalancer.Decision.Wait)
        val d2 = b.onSample(e2eDead(1_700))
        assertTrue("обрыв по e2e обязан переключать после кулдауна: $d2", d2 is AutoBalancer.Decision.Switch)
    }

    @Test
    fun `AB - failed switches on e2e dead keep cooldown growth and fail memory`() {
        val b = bal()
        b.onSample(e2eDead(0))
        val d1 = b.onSample(e2eDead(500)) as AutoBalancer.Decision.Switch
        assertEquals("bittorrent", d1.target)
        b.onSwitchResult(600, d1.target, ok = false)
        // провал: кулдаун удвоен; e2e-обрыв в кулдауне — Wait
        assertTrue(b.onSample(e2eDead(1_500)) is AutoBalancer.Decision.Wait)
        val d2 = b.onSample(e2eDead(2_700))
        assertTrue(d2 is AutoBalancer.Decision.Switch)
        // память провалов: bittorrent остывает (failCooldown 5с) → round-robin
        // после current(wireguard) пропускает его и берёт mtproto2
        assertEquals("память провалов сохранена", "mtproto2", (d2 as AutoBalancer.Decision.Switch).target)
    }

    @Test
    fun `AB - rst outcome is also dead`() {
        val b = bal()
        val d = b.onSample(controlAlive(0).copy(e2e = E2eProbe.Outcome.Rst))
        assertTrue(d is AutoBalancer.Decision.Switch)
    }
}
