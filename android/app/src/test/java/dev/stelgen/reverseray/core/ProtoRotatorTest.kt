package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * v1.8.0: тесты режима «Ротация» (ProtoRotator): расписание 30 минут,
 * строгий round-robin, взаимоисключаемость по построению (без памяти
 * провалов — это не авто).
 */
class ProtoRotatorTest {

    private val cands = listOf("mtproto2", "wireguard", "bittorrent")

    private fun rot(intervalMs: Long = ProtoRotator.DEFAULT_INTERVAL_MS) = ProtoRotator(intervalMs)

    private val T0 = 1_000_000L

    @Test
    fun `default interval is 30 minutes`() {
        assertEquals(30 * 60 * 1000L, ProtoRotator.DEFAULT_INTERVAL_MS)
        assertEquals(ProtoRotator.DEFAULT_INTERVAL_MS, ProtoRotator().intervalMs)
    }

    @Test
    fun `first tick anchors schedule without switching`() {
        val r = rot()
        // включение ≠ немедленная смена: первый тик только якорит расписание
        assertNull(r.onTick(T0, "wireguard", cands))
        // через 5 минут после якоря — ещё рано
        assertNull(r.onTick(T0 + 5 * 60_000, "wireguard", cands))
    }

    @Test
    fun `switches strictly at interval boundary in strict order`() {
        val r = rot()
        assertNull(r.onTick(T0, "wireguard", cands))
        // 30 мин − 1 мс — рано
        assertNull(r.onTick(T0 + ProtoRotator.DEFAULT_INTERVAL_MS - 1, "wireguard", cands))
        // ровно на границе — смена на следующий после wireguard: bittorrent
        assertEquals("bittorrent", r.onTick(T0 + ProtoRotator.DEFAULT_INTERVAL_MS, "wireguard", cands))
        // следующие 30 мин — строго по порядку: mtproto2
        assertNull(r.onTick(T0 + ProtoRotator.DEFAULT_INTERVAL_MS + 60_000, "bittorrent", cands))
        assertEquals(
            "mtproto2",
            r.onTick(T0 + 2 * ProtoRotator.DEFAULT_INTERVAL_MS, "bittorrent", cands),
        )
        // и снова wireguard (полный круг)
        assertEquals(
            "wireguard",
            r.onTick(T0 + 3 * ProtoRotator.DEFAULT_INTERVAL_MS, "mtproto2", cands),
        )
    }

    @Test
    fun `current outside candidates starts from first`() {
        val r = rot()
        assertNull(r.onTick(T0, "rrp1", cands))
        assertEquals("mtproto2", r.onTick(T0 + ProtoRotator.DEFAULT_INTERVAL_MS, "rrp1", cands))
    }

    @Test
    fun `fewer than two candidates never switches`() {
        val r = rot()
        assertNull(r.onTick(T0, "wireguard", listOf("wireguard")))
        assertNull(r.onTick(T0, "wireguard", emptyList()))
        // даже после якоря и срока
        assertNull(r.onTick(T0 + ProtoRotator.DEFAULT_INTERVAL_MS, "wireguard", listOf("wireguard")))
    }

    @Test
    fun `reset re-anchors schedule`() {
        val r = rot()
        assertNull(r.onTick(T0, "wireguard", cands))
        assertEquals("bittorrent", r.onTick(T0 + ProtoRotator.DEFAULT_INTERVAL_MS, "wireguard", cands))
        r.reset()
        // после reset — новый якорь, немедленной смены нет
        assertNull(r.onTick(T0 + 2 * ProtoRotator.DEFAULT_INTERVAL_MS, "bittorrent", cands))
        assertEquals(
            "mtproto2",
            r.onTick(T0 + 3 * ProtoRotator.DEFAULT_INTERVAL_MS, "bittorrent", cands),
        )
    }

    @Test
    fun `custom interval is injectable`() {
        val r = rot(intervalMs = 1_000)
        assertNull(r.onTick(T0, "wireguard", cands))
        assertNull(r.onTick(T0 + 900, "wireguard", cands))
        assertEquals("bittorrent", r.onTick(T0 + 1_000, "wireguard", cands))
    }
}
