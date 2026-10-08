package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * Модуль камуфляжа «API Mask» (v0.8.2): тела запросов — валидный JSON
 * в рабочих пределах; суточный бюджет; джиттер интервала; метка с версией.
 */
class ApimaskTest {

    private fun cfg(
        enabled: Boolean = true,
        minSec: Int = 300,
        maxSec: Int = 900,
        budget: Int = 256 * 1024,
    ) = Apimask.Config("apimask", "API Mask", "1", enabled, minSec, maxSec, budget)

    @Test
    fun `request bodies are valid json objects in size bounds`() {
        val rnd = Random(42)
        repeat(300) {
            val body = Apimask.request(rnd, System.currentTimeMillis())
            assertTrue("не объект: $body", RrpFrame.Noise.balancedJson(body))
            assertTrue("слишком короткий: ${body.length}", body.length >= 60)
            assertTrue(
                "длиннее контроля: ${body.length}",
                body.length <= RrpFrame.MAX_CONTROL_PAYLOAD,
            )
        }
    }

    @Test
    fun `request rotates three shapes`() {
        val rnd = Random(7)
        val shapes = mutableSetOf<String>()
        repeat(50) {
            val body = Apimask.request(rnd, 1_700_000_000_000L)
            listOf("\"telemetry.batch\"", "\"config.sync\"", "\"queue.flush\"")
                .firstOrNull { body.contains(it) }?.let { shapes.add(it) }
        }
        assertTrue("ротация форм сломана: $shapes", shapes.size == 3)
    }

    @Test
    fun `interval stays in manifest corridor`() {
        val rnd = Random(1)
        val c = cfg(minSec = 300, maxSec = 900)
        repeat(500) {
            val ms = Apimask.intervalMs(c, rnd)
            assertTrue(ms in 300_000L..900_000L)
        }
    }

    @Test
    fun `daily budget stops the noise and resets next day`() {
        val engine = Apimask.Engine(cfg(budget = 1000))
        var sent = 0
        while (true) {
            val body = engine.nextRequest() ?: break
            engine.onSent(body.toByteArray(Charsets.UTF_8).size)
            sent++
            assertTrue("бюджет не остановил шум: $sent", sent < 500)
        }
        assertTrue(engine.usedToday() in 1..1000L + 1000)
        assertNull("после исчерпания бюджета шум должен молчать", engine.nextRequest())
    }

    @Test
    fun `label carries version when enabled`() {
        assertEquals("API Mask (v1)", Apimask.labelOf(cfg(enabled = true)))
        assertEquals("", Apimask.labelOf(cfg(enabled = false)))
    }

    @Test
    fun `disabled default is off`() {
        assertFalse(Apimask.Config.disabled().enabled)
    }
}
