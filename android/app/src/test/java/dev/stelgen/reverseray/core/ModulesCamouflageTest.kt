package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Секция camouflage общего манифеста (v0.8.2): парсинг, мусор отсекается,
 * применение в реестр — один источник правды APK↔сервер.
 * Robolectric: парсер манифеста использует org.json (Android-стек).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class ModulesCamouflageTest {

    private val base = """
        {"schema":1,"version":"0.8.2","updated":"2026-10-08",
         "protocols":[{"id":"rrp1","name":"RRP/1","ver":"1","default":true},
                      {"id":"mtproto2","name":"MTProto/2","ver":"2.0"}],
         "policy":{"probe_default_target":"1.1.1.1:443"}
        }
    """.trimIndent()

    @Test
    fun `parses camouflage section`() {
        val json = base.replace(
            "\"policy\"",
            "\"camouflage\":{\"id\":\"apimask\",\"name\":\"API Mask\",\"ver\":\"1\"," +
                "\"enabled\":true,\"min_interval_sec\":120,\"max_interval_sec\":600," +
                "\"max_bytes_per_day\":65536},\"policy\"",
        )
        val m = Modules.parse(json)
        val c = m.camouflage!!
        assertEquals("apimask", c.id)
        assertEquals("API Mask", c.name)
        assertEquals("1", c.ver)
        assertTrue(c.enabled)
        assertEquals(120, c.minIntervalSec)
        assertEquals(65536, c.maxBytesPerDay)
    }

    @Test
    fun `absent section means disabled`() {
        val m = Modules.parse(base)
        assertEquals(null, m.camouflage)
    }

    @Test(expected = Modules.ManifestException::class)
    fun `garbage camouflage id rejects whole manifest`() {
        Modules.parse(base.replace("\"policy\"", "\"camouflage\":{\"id\":\"EVIL ID\"},\"policy\""))
    }

    @Test
    fun `apply wires registry and can be disabled again`() {
        val json = base.replace(
            "\"policy\"",
            "\"camouflage\":{\"id\":\"apimask\",\"name\":\"API Mask\",\"ver\":\"1\",\"enabled\":true},\"policy\"",
        )
        Modules.apply(Modules.parse(json))
        val cfg = RrpProtocols.camouflageConfig()
        assertTrue(cfg.enabled)
        assertEquals("API Mask", cfg.name)
        assertEquals("API Mask (v1)", RrpProtocols.camouflageLabel())

        // секция исчезла → модуль выключен (манифест решает)
        Modules.apply(Modules.parse(base))
        assertFalse(RrpProtocols.camouflageConfig().enabled)
        assertEquals("", RrpProtocols.camouflageLabel())
    }

    @Test
    fun `garbage numbers clamp to defaults`() {
        Modules.apply(
            Modules.parse(
                base.replace(
                    "\"policy\"",
                    "\"camouflage\":{\"id\":\"apimask\",\"min_interval_sec\":-5," +
                        "\"max_interval_sec\":999999,\"max_bytes_per_day\":0},\"policy\"",
                ),
            ),
        )
        val cfg = RrpProtocols.camouflageConfig()
        assertEquals(300, cfg.minIntervalSec) // дефолт
        assertEquals(900, cfg.maxIntervalSec) // дефолт
        assertEquals(256 * 1024, cfg.maxBytesPerDay) // дефолт
    }
}
