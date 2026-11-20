package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v1.8.0: тесты режима «Ротация» (ProtoRotator): расписание 30 минут,
 * строгий round-robin, взаимоисключаемость по построению (без памяти
 * провалов — это не авто).
 */
class ProtoRotatorTest {

    private val cands = listOf("mtproto2", "wireguard", "bittorrent")

    private fun rot(intervalMs: Long = ProtoRotator.DEFAULT_INTERVAL_MS) = ProtoRotator(intervalMs)

    private val t0 = 1_000_000L

    @Test
    fun `default interval is 30 minutes`() {
        assertEquals(30 * 60 * 1000L, ProtoRotator.DEFAULT_INTERVAL_MS)
        assertEquals(ProtoRotator.DEFAULT_INTERVAL_MS, ProtoRotator().intervalMs)
    }

    @Test
    fun `first tick anchors schedule without switching`() {
        val r = rot()
        // включение ≠ немедленная смена: первый тик только якорит расписание
        assertNull(r.onTick(t0, "wireguard", cands))
        // через 5 минут после якоря — ещё рано
        assertNull(r.onTick(t0 + 5 * 60_000, "wireguard", cands))
    }

    @Test
    fun `switches strictly at interval boundary in strict order`() {
        val r = rot()
        assertNull(r.onTick(t0, "wireguard", cands))
        // 30 мин − 1 мс — рано
        assertNull(r.onTick(t0 + ProtoRotator.DEFAULT_INTERVAL_MS - 1, "wireguard", cands))
        // ровно на границе — смена на следующий после wireguard: bittorrent
        assertEquals("bittorrent", r.onTick(t0 + ProtoRotator.DEFAULT_INTERVAL_MS, "wireguard", cands))
        // следующие 30 мин — строго по порядку: mtproto2
        assertNull(r.onTick(t0 + ProtoRotator.DEFAULT_INTERVAL_MS + 60_000, "bittorrent", cands))
        assertEquals(
            "mtproto2",
            r.onTick(t0 + 2 * ProtoRotator.DEFAULT_INTERVAL_MS, "bittorrent", cands),
        )
        // и снова wireguard (полный круг)
        assertEquals(
            "wireguard",
            r.onTick(t0 + 3 * ProtoRotator.DEFAULT_INTERVAL_MS, "mtproto2", cands),
        )
    }

    @Test
    fun `current outside candidates starts from first`() {
        val r = rot()
        assertNull(r.onTick(t0, "rrp1", cands))
        assertEquals("mtproto2", r.onTick(t0 + ProtoRotator.DEFAULT_INTERVAL_MS, "rrp1", cands))
    }

    @Test
    fun `fewer than two candidates never switches`() {
        val r = rot()
        assertNull(r.onTick(t0, "wireguard", listOf("wireguard")))
        assertNull(r.onTick(t0, "wireguard", emptyList()))
        // даже после якоря и срока
        assertNull(r.onTick(t0 + ProtoRotator.DEFAULT_INTERVAL_MS, "wireguard", listOf("wireguard")))
    }

    @Test
    fun `reset re-anchors schedule`() {
        val r = rot()
        assertNull(r.onTick(t0, "wireguard", cands))
        assertEquals("bittorrent", r.onTick(t0 + ProtoRotator.DEFAULT_INTERVAL_MS, "wireguard", cands))
        r.reset()
        // после reset — новый якорь, немедленной смены нет
        assertNull(r.onTick(t0 + 2 * ProtoRotator.DEFAULT_INTERVAL_MS, "bittorrent", cands))
        assertEquals(
            "mtproto2",
            r.onTick(t0 + 3 * ProtoRotator.DEFAULT_INTERVAL_MS, "bittorrent", cands),
        )
    }

    @Test
    fun `custom interval is injectable`() {
        val r = rot(intervalMs = 1_000)
        assertNull(r.onTick(t0, "wireguard", cands))
        assertNull(r.onTick(t0 + 900, "wireguard", cands))
        assertEquals("bittorrent", r.onTick(t0 + 1_000, "wireguard", cands))
    }

    // ---- v1.8.3: кандидаты ротации (ROTATABLE) — apimask исключён ----

    @Test
    fun `ROTATABLE excludes apimask and default`() {
        assertFalse(RrpProtocols.ROTATABLE.contains(RrpProtocols.DEFAULT))
        assertFalse(RrpProtocols.ROTATABLE.contains(Apimask.FEATURE))
    }

    @Test
    fun `ROTATABLE is a subset of EXECUTABLE in registry order`() {
        assertEquals(
            RrpProtocols.EXECUTABLE.filter { RrpProtocols.ROTATABLE.contains(it) },
            RrpProtocols.ROTATABLE,
        )
    }

    @Test
    fun `full round-robin over ROTATABLE never picks apimask`() {
        val r = rot(intervalMs = 1_000)
        val seen = mutableListOf<String>()
        var cur = "mtproto2"
        var at = t0
        // якорь + 4 смены (полный круг + 1)
        assertNull(r.onTick(at, cur, RrpProtocols.ROTATABLE))
        repeat(4) {
            at += 1_000
            val next = r.onTick(at, cur, RrpProtocols.ROTATABLE)
            if (next != null) {
                seen.add(next)
                cur = next
            }
        }
        assertTrue(seen.isNotEmpty())
        assertFalse(seen.contains(Apimask.FEATURE))
        assertFalse(seen.contains(RrpProtocols.DEFAULT))
    }

    @Test
    fun `with unfiltered EXECUTABLE the rotator would reach apimask — hence ROTATABLE`() {
        // BUG-документация: до v1.8.3 кандидаты брались из EXECUTABLE — ротатор
        // рано или поздно выбирал apimask, а серверный planner не свитчит его
        // (switchKeyPlan: unsupported switch target) → цикл провалов каждые 30 мин.
        val all = RrpProtocols.EXECUTABLE.filter { it != RrpProtocols.DEFAULT }
        val r = rot(intervalMs = 1_000)
        assertNull(r.onTick(t0, "mtproto2", all))
        var cur = "mtproto2"
        var at = t0
        val seen = mutableListOf<String>()
        repeat(4) {
            at += 1_000
            val next = r.onTick(at, cur, all)
            if (next != null) {
                seen.add(next)
                cur = next
            }
        }
        // репродуктор: в EXECUTABLE apimask был — ротатор ДОШЁЛ бы до него
        assertTrue(seen.contains(Apimask.FEATURE))
    }
}
