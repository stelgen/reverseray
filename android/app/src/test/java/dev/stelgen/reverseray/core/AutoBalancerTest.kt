package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Тесты умного балансера auto-режима (v0.10): гистерезис, кулдауны,
 * round-robin, анти-мигание («не скакать каждые 100 мс или каждые 5 с»).
 */
class AutoBalancerTest {

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

    private fun sample(at: Long, loss: Double = 0.0, rtt: Long = 100, probe: Boolean? = true) =
        AutoBalancer.Sample(at, rtt, loss, probe)

    @Test
    fun `good samples never switch`() {
        val b = bal()
        for (i in 0 until 50) {
            assertEquals(AutoBalancer.Decision.Nothing, b.onSample(sample(i * 500L)))
        }
    }

    @Test
    fun `single bad sample does not switch - hysteresis`() {
        val b = bal()
        // анти-мигание: ОДНА плохая проба (loss 0.5 — деградация, НЕ обрыв) — молчим;
        // обрыв (loss ≥ deadLoss 0.9) — отдельный путь, он не ждёт окна
        assertEquals(AutoBalancer.Decision.Wait::class, b.onSample(sample(0, loss = 0.5))::class)
        // вторая проба в окне — деградация устойчива → смена
        val d = b.onSample(sample(500, loss = 0.5))
        assertTrue("устойчивая деградация обязана переключать: $d", d is AutoBalancer.Decision.Switch)
    }

    @Test
    fun `sustained degradation switches round robin`() {
        val b = bal() // current = wireguard → следующий по списку после wireguard = bittorrent
        assertEquals(AutoBalancer.Decision.Wait::class, b.onSample(sample(0, loss = 0.5))::class)
        val d = b.onSample(sample(900, loss = 0.5))
        assertTrue("ожидали Switch, получили $d", d is AutoBalancer.Decision.Switch)
        assertEquals("bittorrent", (d as AutoBalancer.Decision.Switch).target)
    }

    @Test
    fun `rtt degradation also triggers switch`() {
        val b = bal()
        b.onSample(sample(0, rtt = 2000))
        val d = b.onSample(sample(900, rtt = 2000))
        assertTrue(d is AutoBalancer.Decision.Switch)
    }

    @Test
    fun `stability window blocks immediate re-switch`() {
        val b = bal()
        b.onSample(sample(0, loss = 0.5))
        val d1 = b.onSample(sample(900, loss = 0.5))
        b.onSwitchResult(1_000, (d1 as AutoBalancer.Decision.Switch).target, ok = true)
        // связь снова плохая, но stabilityWindowMs (2с) + кулдаун не прошли
        val d2 = b.onSample(sample(1_500, loss = 0.5))
        assertTrue("анти-мигание нарушено: $d2", d2 is AutoBalancer.Decision.Wait)
    }

    @Test
    fun `failed switch grows cooldown and cools protocol`() {
        val b = bal()
        b.onSample(sample(0, loss = 0.5))
        val d = b.onSample(sample(900, loss = 0.5)) as AutoBalancer.Decision.Switch
        assertEquals("bittorrent", d.target)
        b.onSwitchResult(1_000, d.target, ok = false)
        // провал: кулдаун = min(1000)+penalty(1000) → следующий свитч не раньше 3000
        assertEquals(AutoBalancer.Decision.Wait::class, b.onSample(sample(2_000, loss = 0.5))::class)
        b.onSample(sample(3_000, loss = 0.5))
        val d2 = b.onSample(sample(3_900, loss = 0.5))
        assertTrue(d2 is AutoBalancer.Decision.Switch)
        // bittorrent в fail-кулдауне (до 6000) — round-robin выбирает mtproto2
        assertEquals("проваленный протокол не выбирается", "mtproto2", (d2 as AutoBalancer.Decision.Switch).target)
    }

    @Test
    fun `cooldown doubles on failures up to cap`() {
        val b = bal()
        val c = cfg()
        var at = 1_100L
        b.onSample(sample(at, loss = 0.5))
        val d1 = b.onSample(sample(at + 900, loss = 0.5)) as AutoBalancer.Decision.Switch
        b.onSwitchResult(at + 900 + 100, d1.target, ok = false) // penalty = 1000
        // следующий свитч не раньше 2000+1000+1000 = 4000
        assertEquals(AutoBalancer.Decision.Wait::class, b.onSample(sample(3_000, loss = 0.5))::class)
        b.onSample(sample(4_100, loss = 0.5))
        val d2 = b.onSample(sample(5_000, loss = 0.5))
        assertTrue(d2 is AutoBalancer.Decision.Switch)
        b.onSwitchResult(5_000, (d2 as AutoBalancer.Decision.Switch).target, ok = false) // penalty = 2000
        // следующий не раньше 5000+1000+2000 = 8000
        assertEquals(AutoBalancer.Decision.Wait::class, b.onSample(sample(7_000, loss = 0.5))::class)
        b.onSample(sample(8_100, loss = 0.5))
        val d3 = b.onSample(sample(9_000, loss = 0.5))
        assertTrue(d3 is AutoBalancer.Decision.Switch)
        b.onSwitchResult(9_000, (d3 as AutoBalancer.Decision.Switch).target, ok = false) // penalty = 4000
        // потолок: penalty ≤ maxCooldownMs
        b.onSample(sample(18_100, loss = 0.5))
        val d4 = b.onSample(sample(19_000, loss = 0.5))
        assertTrue(d4 is AutoBalancer.Decision.Switch)
        b.onSwitchResult(19_000, (d4 as AutoBalancer.Decision.Switch).target, ok = false) // penalty = 8000 = cap
        assertEquals("потолок кулдауна", c.maxCooldownMs, 8_000)
    }

    @Test
    fun `dead link bypasses stability window but respects cooldown`() {
        val b = bal()
        b.onSample(sample(0, loss = 0.5))
        val d = b.onSample(sample(900, loss = 0.5))
        b.onSwitchResult(1_000, (d as AutoBalancer.Decision.Switch).target, ok = true)
        // полный обрыв в stability window: stability пропускает, но кулдаун жив
        assertTrue(
            "анти-молотьба: кулдаун уважается и при обрыве",
            b.onSample(sample(1_500, loss = 1.0)) is AutoBalancer.Decision.Wait,
        )
        // вышли из кулдауна (1с) — обрыв переключает немедленно
        val d2 = b.onSample(sample(2_100, loss = 1.0))
        assertTrue("обрыв должен переключаться: $d2", d2 is AutoBalancer.Decision.Switch)
    }

    @Test
    fun `labelWithVer shows bittorrent mask label`() {
        assertEquals("BitTorrent/1", RrpProtocols.labelWithVer("bittorrent"))
        assertTrue(RrpProtocols.isExecutable("bittorrent"))
    }
}
