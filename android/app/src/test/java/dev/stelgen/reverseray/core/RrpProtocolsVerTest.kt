package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v0.8.1: версии протоколов пробрасываются по всему стеку. Канон:
 * метка известного протокола несёт версию ("RRP/1", "MTProto/2"); у нового
 * протокола без публичной версии — пусто, нигде ничего не приписываем.
 */
class RrpProtocolsVerTest {

    @Test
    fun `bundled protocols carry versions`() {
        assertEquals("RRP/1", RrpProtocols.label("rrp1"))
        assertEquals("1", RrpProtocols.ver("rrp1"))
        assertEquals("MTProto/2", RrpProtocols.label("mtproto2"))
        assertEquals("2.0", RrpProtocols.ver("mtproto2"))
        // v0.10 ФИКС ДУБЛЕЙ: версия уже в метке ("Name/Ver") — НЕ дублируем скобками.
        assertEquals("RRP/1", RrpProtocols.labelWithVer("rrp1"))
        assertEquals("MTProto/2 (v2.0)", RrpProtocols.labelWithVer("mtproto2"))
        assertEquals("BitTorrent/1", RrpProtocols.labelWithVer("bittorrent"))
    }

    @Test
    fun `version is not duplicated in menu labels`() {
        // регрессия меню «Смена протокола»: «RRP/1 (v1)» было дублированием
        for (id in RrpProtocols.BUNDLED) {
            val shown = RrpProtocols.labelWithVer(id)
            val v = RrpProtocols.ver(id)
            if (v.isNotEmpty()) {
                assertTrue(
                    "версия задвоена: $shown",
                    !shown.contains("(v$v)"),
                )
            }
        }
    }

    @Test
    fun `registry with versions is applied`() {
        try {
            RrpProtocols.applyRegistryFull(
                listOf("rrp1", "mtproto2", "proto9"),
                "0.8.1",
                mapOf("rrp1" to "RRP/1", "mtproto2" to "MTProto/2", "proto9" to "Proto/9"),
                mapOf("rrp1" to "1", "mtproto2" to "2.0", "proto9" to "9"),
            )
            // v0.10: версия уже в метке "Proto/9" — скобки не приписываем
            assertEquals("Proto/9", RrpProtocols.labelWithVer("proto9"))
            assertEquals("9", RrpProtocols.ver("proto9"))
        } finally {
            // вернуть встроенный реестр (глобальное состояние)
            RrpProtocols.applyRegistry(RrpProtocols.BUNDLED, "")
        }
    }

    @Test
    fun `protocol without version shows no version anywhere`() {
        try {
            RrpProtocols.applyRegistryFull(
                listOf("rrp1", "future1"),
                "0.8.1",
                mapOf("rrp1" to "RRP/1", "future1" to "Future/1"),
                mapOf("rrp1" to "1"), // future1 без версии
            )
            assertEquals("Future/1", RrpProtocols.labelWithVer("future1"))
            assertEquals("", RrpProtocols.ver("future1"))
            assertTrue("версия не должна приписываться", !RrpProtocols.labelWithVer("future1").contains("v"))
        } finally {
            RrpProtocols.applyRegistry(RrpProtocols.BUNDLED, "")
        }
    }

    @Test
    fun `garbage version is cleaned not fatal`() {
        try {
            RrpProtocols.applyRegistryFull(
                listOf("rrp1", "proto7"),
                "0.8.1",
                mapOf("rrp1" to "RRP/1", "proto7" to "Proto/7"),
                mapOf("rrp1" to "1", "proto7" to "1 \"hax\""),
            )
            assertEquals("мусорная версия = версии нет", "", RrpProtocols.ver("proto7"))
        } finally {
            RrpProtocols.applyRegistry(RrpProtocols.BUNDLED, "")
        }
    }

    @Test
    fun `unknown id falls back to raw id without version`() {
        assertEquals("неттакого", RrpProtocols.label("неттакого"))
        assertEquals("", RrpProtocols.ver("неттакого"))
    }

/** v0.9.1: слои — старый тонкий движок + НОВЫЙ протокол из манифеста:
 *  реестр подхватывает id/метку/версию, дефолт остаётся rrp1, мусор → rrp1,
 *  движок никогда сам не прыгает на незнакомый протокол. */
    @Test
    fun `new protocol from manifest layers into old thin engine`() {
        RrpProtocols.applyRegistryFull(
            ids = listOf("rrp1", "future2"),
            version = "0.9.1",
            labels = mapOf("rrp1" to "RRP/1", "future2" to "Future/2"),
            vers = mapOf("rrp1" to "1", "future2" to "2"),
        )
        try {
            // v0.10: версия уже в метке "Future/2" — скобки не приписываем
            assertEquals("Future/2", RrpProtocols.labelWithVer("future2"))
            assertTrue(RrpProtocols.displayList().contains("future2"))
            assertEquals("future2", RrpProtocols.normalize("future2"))
            // движок остаётся на стабильном дефолте
            assertEquals("rrp1", RrpProtocols.normalize(null))
            assertEquals("rrp1", RrpProtocols.normalize("мусор"))
        } finally {
            RrpProtocols.applyRegistryFull(listOf("rrp1"), "1", mapOf("rrp1" to "RRP/1"), mapOf("rrp1" to "1"))
        }
    }
}
