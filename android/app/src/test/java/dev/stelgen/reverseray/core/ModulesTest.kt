package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Модули (v0.8): манифест — общий с сервером. Проверяем канон:
 * валидация, мусор НЕ применяется, rrp1 обязателен, даунгрейд запрещён,
 * реестр применяется в RrpProtocols без переустановки APK.
 */
@RunWith(RobolectricTestRunner::class) // org.json в unit-тестах живёт в Robolectric
@Config(sdk = [31])
class ModulesTest {

    private val goodManifest = """
    {
      "schema": 1,
      "version": "0.8.0",
      "protocols": [
        {"id": "rrp1", "name": "RRP/1", "default": true},
        {"id": "mtproto2", "name": "MTProto/2"}
      ],
      "policy": {"probe_default_target": "1.1.1.1:443", "dns_probe_names": ["whoami.cloudflare"]}
    }
    """.trimIndent()

    @Test
    fun `parses good manifest`() {
        val m = Modules.parse(goodManifest)
        assertEquals("0.8.0", m.version)
        assertEquals(listOf("rrp1", "mtproto2"), m.enabledProtocolIds())
        assertEquals("1.1.1.1:443", m.probeTarget)
        assertEquals(listOf("whoami.cloudflare"), m.dnsProbeNames)
    }

    @Test
    fun `applies registry to RrpProtocols`() {
        Modules.apply(Modules.parse(goodManifest))
        assertEquals("0.8.0", RrpProtocols.registryVersion())
        assertTrue(RrpProtocols.displayList().contains("rrp1"))
        assertTrue(RrpProtocols.displayList().contains("mtproto2"))
        assertEquals("mtproto2", RrpProtocols.normalize("mtproto2"))
        // v0.8.1: версии протоколов видны в кнопках/статусах
        assertEquals("MTProto/2 (v2.0)" + Msgs.LABEL_PAYLOAD_ENC.t(), RrpProtocols.displayName("mtproto2"))
    }

    @Test
    fun `garbage manifests are rejected`() {
        val bad = listOf(
            "{\"schema\":2,\"version\":\"0.8.0\",\"protocols\":[{\"id\":\"rrp1\"}]}",
            "{\"schema\":1,\"version\":\"hello\",\"protocols\":[{\"id\":\"rrp1\"}]}",
            "{\"schema\":1,\"version\":\"0.8.0\",\"protocols\":[]}",
            "{\"schema\":1,\"version\":\"0.8.0\",\"protocols\":[{\"id\":\"mtproto2\"}]}",
            "{\"schema\":1,\"version\":\"0.8.0\",\"protocols\":[{\"id\":\"rrp1\"},{\"id\":\"rrp1\"}]}",
            "{\"schema\":1,\"version\":\"0.8.0\",\"protocols\":[{\"id\":\"RRP!\"}]}",
            "{\"schema\":1,\"version\":\"0.8.0\",\"protocols\":[{\"id\":\"rrp1\"}],\"policy\":{\"probe_default_target\":\"no-port\"}}",
            "не json вовсе",
        )
        for (b in bad) {
            try {
                Modules.parse(b)
                fail("мусорный манифест принят: $b")
            } catch (_: Modules.ManifestException) {
            }
        }
        // мусор НЕ применён — реестр не изменился с последнего валидного
        assertEquals("0.8.0", RrpProtocols.registryVersion())
    }

    @Test
    fun `disabled protocol excluded from negotiation`() {
        val body = goodManifest.replace(
            "{\"id\": \"mtproto2\", \"name\": \"MTProto/2\"}",
            "{\"id\": \"mtproto2\", \"name\": \"MTProto/2\", \"enabled\": false}",
        )
        val m = Modules.parse(body)
        assertEquals(listOf("rrp1"), m.enabledProtocolIds())
        Modules.apply(m)
        assertFalse(RrpProtocols.displayList().contains("mtproto2"))
        // нормализация мусора всё равно к дефолту
        assertEquals("rrp1", RrpProtocols.normalize("mtproto2"))
    }

    @Test
    fun `version compare canon`() {
        assertTrue(Modules.versionCompare("0.8.0", "0.7.4") > 0)
        assertEquals(0, Modules.versionCompare("0.8.0", "0.8.0"))
        assertTrue(Modules.versionCompare("0.7.4", "0.8.0") < 0)
        assertTrue(Modules.versionCompare("v0.8.1", "0.8.0") > 0)
    }

    @Test
    fun `normalizeId canon`() {
        assertEquals("mtproto2", Modules.normalizeId("MTProto2"))
        assertEquals("", Modules.normalizeId("RRP!"))
        assertEquals("", Modules.normalizeId(""))
        assertEquals("", Modules.normalizeId("a".repeat(17)))
    }
}