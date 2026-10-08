package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** v0.8.1: поле ver манифеста — публичная версия протокола для всего стека. */
@RunWith(RobolectricTestRunner::class) // org.json в unit-тестах живёт в Robolectric
@Config(sdk = [31])
class ModulesVerTest {

    @Test
    fun `manifest ver parsing`() {
        val body = """
            {"schema":1,"version":"0.8.1","protocols":[
              {"id":"rrp1","name":"RRP/1","ver":"1","default":true},
              {"id":"mtproto2","name":"MTProto/2","ver":"2.0"},
              {"id":"future1","name":"Future/1"}]}
        """.trimIndent()
        val m = Modules.parse(body)
        assertEquals("1", m.protocols[0].ver)
        assertEquals("2.0", m.protocols[1].ver)
        assertEquals("", m.protocols[2].ver) // версии нет — валидно
        assertEquals(mapOf("rrp1" to "1", "mtproto2" to "2.0", "future1" to ""), m.protocolVers())
        assertEquals("MTProto/2", m.protocolLabels()["mtproto2"])
    }

    @Test
    fun `garbage ver becomes empty not error`() {
        val body = """
            {"schema":1,"version":"0.8.1","protocols":[
              {"id":"rrp1","name":"RRP/1","ver":"1 \"hax\"","default":true}]}
        """.trimIndent()
        val m = Modules.parse(body) // НЕ бросает
        assertEquals("", m.protocols[0].ver)
    }

    @Test
    fun `sanitizeVer rules`() {
        assertEquals("2.0", Modules.sanitizeVer("2.0"))
        assertEquals(" 2.1 ".trim(), Modules.sanitizeVer(" 2.1 "))
        assertEquals("", Modules.sanitizeVer("1 2"))
        assertEquals("", Modules.sanitizeVer("1\"2"))
        assertEquals("", Modules.sanitizeVer(null))
        assertEquals("", Modules.sanitizeVer("12345678901234567"))
        assertEquals("1.0-b_c+1", Modules.sanitizeVer("1.0-b_c+1"))
    }

    @Test
    fun `apply feeds labels and versions into registry`() {
        try {
            val body = """
                {"schema":1,"version":"0.8.1","protocols":[
                  {"id":"rrp1","name":"RRP/1","ver":"1","default":true},
                  {"id":"mtproto2","name":"MTProto/2","ver":"2.0"}]}
            """.trimIndent()
            Modules.apply(Modules.parse(body))
            assertEquals("MTProto/2 (v2.0)", RrpProtocols.labelWithVer("mtproto2"))
            assertEquals("RRP/1 (v1)", RrpProtocols.labelWithVer("rrp1"))
        } finally {
            RrpProtocols.applyRegistry(RrpProtocols.BUNDLED, "")
        }
    }
}
