package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v0.9.2 (R9): реестр протоколов — «известен» ≠ «исполняем». Новый протокол
 * из манифеста модуля ВСЕГДА виден в GUI (displayList/normalize), но коннект
 * идёт только исполняемым протоколом (normalizeExecutable → rrp1) + честный
 * лог в TunnelService. Table-driven по всем заявленным протоколам.
 */
class RrpProtocolsExecutableTest {

    private fun withRegistry(ids: List<String>, block: () -> Unit) {
        val oldOnChanged = RrpProtocols.onRegistryChanged
        try {
            RrpProtocols.onRegistryChanged = null
            RrpProtocols.applyRegistry(ids, "test")
            block()
        } finally {
            RrpProtocols.onRegistryChanged = oldOnChanged
            RrpProtocols.applyRegistry(listOf("rrp1", "mtproto2"), "")
        }
    }

    @Test
    fun `заявленный модулем протокол виден в GUI`() = withRegistry(listOf("rrp1", "mtproto2", "future9")) {
        assertTrue(RrpProtocols.displayList().contains("future9"))
        // отображаемая нормализация сохраняет заявленный id
        assertEquals("future9", RrpProtocols.normalize("future9"))
        assertEquals("MTProto/2 (v2.0)", RrpProtocols.labelWithVer("mtproto2"))
    }

    @Test
    fun `неисполняемый протокол сводится к фундаменту при подключении`() = withRegistry(listOf("rrp1", "mtproto2", "future9")) {
        assertEquals("rrp1", RrpProtocols.normalizeExecutable("future9"))
        assertEquals("rrp1", RrpProtocols.normalizeExecutable("мусор"))
        assertEquals("rrp1", RrpProtocols.normalizeExecutable(null))
        assertEquals("rrp1", RrpProtocols.normalizeExecutable(""))
        assertEquals("rrp1", RrpProtocols.normalizeExecutable("rrp1"))
        assertEquals("mtproto2", RrpProtocols.normalizeExecutable("mtproto2"))
    }

    @Test
    fun `rrp1 всегда исполняем - фундамент не теряется`() {
        for (id in RrpProtocols.displayList()) {
            if (id == RrpProtocols.DEFAULT) {
                assertTrue(RrpProtocols.isExecutable(id))
            }
        }
        assertTrue(RrpProtocols.isExecutable(RrpProtocols.DEFAULT))
        assertFalse(RrpProtocols.isExecutable("unknown-id"))
    }

    @Test
    fun `слушатель реестра уведомляется при применении манифеста`() {
        var notified = 0
        val old = RrpProtocols.onRegistryChanged
        try {
            RrpProtocols.onRegistryChanged = { notified++ }
            RrpProtocols.applyRegistry(listOf("rrp1", "mtproto2", "proto3"), "v")
            assertTrue("GUI обязан узнавать о новых протоколах сразу", notified >= 1)
        } finally {
            RrpProtocols.onRegistryChanged = old
            RrpProtocols.applyRegistry(listOf("rrp1", "mtproto2"), "")
        }
    }
}
