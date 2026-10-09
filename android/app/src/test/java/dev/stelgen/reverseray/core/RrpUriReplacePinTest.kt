package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** v0.9.0: ротация CA — замена пина в ссылке сохраняет всё остальное. */
class RrpUriReplacePinTest {

    private val link =
        "rrp://TOKEN_abc@81.25.59.194:4433,8443/?pin=OLD_PIN_VALUE&name=phone-1"

    @Test
    fun `replacePin keeps everything but pin`() {
        val updated = RrpUri.replacePin(link, "NEW_PIN_VALUE")
        assertNotNull(updated)
        val cfg = RrpUri.parse(updated!!)
        assertEquals("NEW_PIN_VALUE", cfg.pin)
        assertEquals("TOKEN_abc", cfg.token)
        assertEquals("81.25.59.194", cfg.host)
        assertEquals(listOf(4433, 8443), cfg.ports)
        assertEquals("phone-1", cfg.name)
        // сериализация стабильно содержит новый пин
        assertTrue(updated.contains("pin=NEW_PIN_VALUE"))
        assertTrue(!updated.contains("OLD_PIN_VALUE"))
    }

    @Test
    fun `replacePin is idempotent and chainable`() {
        val a = RrpUri.replacePin(link, "PIN_A")!!
        val b = RrpUri.replacePin(a, "PIN_B")!!
        assertEquals("PIN_B", RrpUri.parse(b).pin)
        // мусорный пин отклоняем заранее
        assertNull(RrpUri.replacePin(link, " "))
        assertNull(RrpUri.replacePin("not a link at all", "PIN"))
        assertNull(RrpUri.replacePin("", "PIN"))
    }
}