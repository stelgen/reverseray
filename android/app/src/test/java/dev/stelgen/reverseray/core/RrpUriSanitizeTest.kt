package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v0.7.4: бронепарсер rrp:// ссылок — юзер вставляет «типичный мусор»:
 * невидимые ASCII/Unicode-символы, кавычки всех типов, текст вокруг ссылки,
 * точки/запятые на концах — парсер обязан сам починить и разобрать.
 */
class RrpUriSanitizeTest {

    private val canon = "rrp://qFNaL8E2@81.25.59.194:4433/?pin=AAA&name=phone-1&proto=rrp1"

    @Test
    fun `clean link parses as is`() {
        val cfg = RrpUri.parse(canon)
        assertEquals("81.25.59.194", cfg.host)
        assertEquals(listOf(4433), cfg.ports)
        assertEquals("qFNaL8E2", cfg.token)
        assertEquals("rrp1", cfg.proto)
    }

    @Test
    fun `invisible ascii control chars are stripped`() {
        val junk = " \u0000\u0001\u0007\u001B rrp://qFNaL8E2@81.25.59.194:4433/?pin=AAA\u0000\u001F"
        val cfg = RrpUri.parse(junk)
        assertEquals("81.25.59.194", cfg.host)
    }

    @Test
    fun `zero-width and bidi unicode chars are stripped`() {
        val junk = "\u200B\u200C\u200D\u200E\u202A\uFEFFrrp://qFNaL8E2@81.25.59.194:4433\u200B/?pin=AAA\u2060"
        val cfg = RrpUri.parse(junk)
        assertEquals("81.25.59.194", cfg.host)
    }

    @Test
    fun `nbsp and unicode whitespace are stripped`() {
        val junk = "\u00A0 rrp://qFNaL8E2@81.25.59.194:4433\u2028/?pin=AAA\u3000"
        val cfg = RrpUri.parse(junk)
        assertEquals("81.25.59.194", cfg.host)
    }

    @Test
    fun `all kinds of quotes are trimmed`() {
        val variants = listOf(
            "\"$canon\"",
            "'$canon'",
            "`$canon`",
            "«$canon»",
            "„$canon“",
            "“$canon”",
            "‘$canon’",
            "「$canon」",
        )
        variants.forEach { junk ->
            val cfg = RrpUri.parse(junk)
            assertEquals("81.25.59.194", cfg.host)
        }
    }

    @Test
    fun `surrounding text and trailing punctuation are stripped`() {
        val junk = "твой конфиг: «$canon», вставь в приложение."
        val cfg = RrpUri.parse(junk)
        assertEquals("phone-1", cfg.name)
        assertEquals(4433, cfg.ports.first())
    }

    @Test
    fun `decorative wrappers are trimmed`() {
        listOf(
            "<$canon>",
            "($canon)",
            "[$canon]",
            "{$canon}",
        ).forEach { junk ->
            assertEquals("81.25.59.194", RrpUri.parse(junk).host)
        }
    }

    @Test
    fun `link without scheme but with token host port is fixed`() {
        val junk = "qFNaL8E2@81.25.59.194:4433/?pin=AAA"
        val cfg = RrpUri.parse(junk)
        assertEquals("81.25.59.194", cfg.host)
    }

    @Test
    fun `foreign scheme is not silently swallowed`() {
        assertThrows(RrpUriException::class.java) { RrpUri.parse("http://t@h:443") }
    }

    @Test
    fun `proto junk falls back to default`() {
        val cfg = RrpUri.parse("rrp://t@h.example:443/?proto=trojan-а-лайк")
        assertEquals(RrpProtocols.DEFAULT, cfg.proto)
        assertEquals("rrp1", RrpUri.parse("rrp://t@h.example:443/?proto=RRP1").proto)
    }

    @Test
    fun `transport junk falls back to tcp`() {
        val cfg = RrpUri.parse("rrp://t@h.example:443/?transport=ws!")
        assertEquals("ws", cfg.transport)
        assertEquals("tcp", RrpUri.parse("rrp://t@h.example:443/?transport=что-то").transport)
    }

    @Test
    fun `serialize always carries explicit proto`() {
        val s = RrpUri.parse(canon).serialize()
        assertTrue(s.contains("proto=rrp1"))
    }
}
