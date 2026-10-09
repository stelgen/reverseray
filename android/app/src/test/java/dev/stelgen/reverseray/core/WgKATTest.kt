package dev.stelgen.reverseray.core

// WgKATTest — КРОСС-ЯЗЫКОВОЙ вектор WireGuard (v0.9.5): msg1/msg2 и WG-пакеты
// построены Go-сервером (internal/wg, TestGenerateKAT → katgen в wg_test.go).
// Kotlin обязан байт-в-байт воспроизвести msg1, сойтись в ключах, расшифровать
// пакеты Go и дать идентичный шифртекст — иначе APK и сервер «говорят на
// разных языках» и wireguard не поднимется. Векторы детерминированы
// (фиксированные ключи/метка TAI64N/индексы), регенерация — Go-тестом.

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WgKATTest {

    private fun hx(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // Фиксированные ключи KAT (гекс, верхний регистр).
    private val srvPub = hx("5869AFF450549732CBAAED5E5DF9B30A6DA31CB0E5742BAD5AD4A1A768F1A67B")
    private val cliPriv = hx("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")
    private val cliPub = hx("07A37CBC142093C8B755DC1B10E86CB426374AD16AA853ED0BDFC0B2B86D1C7C")
    private val ephPriv = hx("4142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60")
    private val psk = hx("E42A11FBDB6B27DBDD7349D1881F12B9D8E7497A591CE0458945ED22161EB60E")
    private val stamp = hx("A0A1A2A3A4A5A6A7A8A9AAAB")
    private val msg1 = hx("010000000403020164B101B1D0BE5A8704BD078F9895001FC03E8E9F9522F188DD128D9846D48466C778A78599FD6CEECD28BA1593F6C70D076A957C687153AF799B45B31BED92C96F8FE41DBFA02E3235E55D324D9E7916544A5BB71F08D422229C89D85F95326C880EF734E44A7E4896E3DBCC98C6B6A505BECA092A98DBF47D086E5200000000000000000000000000000000")
    private val msg2 = hx("020000000D0C0B0A04030201C9C6CDAAE22F6D123BCC4EDAC946243AA575F17DF00B0AE03BB91B7211EB2B7F3D28CDE7231A556936FE303E6C1FABF13F6DEF6EF6E26201DEAC3288F29575BC00000000000000000000000000000000")
    private val keyC2S = hx("B6FAA14A979D74D2FF2D4769D3B839F2650A80C760EA443E4820B1E2C8CCCD06")
    private val keyS2C = hx("B435F88E32026A061792FBA5D534E8F971C210C99059AE5F730AFBFF4150D545")
    private val sndC = 0x01020304L
    private val sndS = 0x0A0B0C0DL
    private val plainC2S = "reverseray-wg-kat-c2s-0001".toByteArray()
    private val boxC2S = hx("040000000D0C0B0A00000000000000007BA678223752E992F1D85A6EA84EC79067132A0DF6AE86237583C2D61BB6B4C7A2759551DFDDC1521752")
    private val plainS2C = "reverseray-wg-kat-s2c-0001".toByteArray()
    private val boxS2C = hx("040000000403020100000000000000008FDA040B6A6A87FA8DAA2D3F71BC5B7B0FE2221E84F3B3FB16F9BA1807E778BF7F88403DDA71FFD0931F")

    @Test
    fun `msg1 byte-identical to go`() {
        val (msg, _) = Wg.newClientHandshake(
            srvPub, psk,
            injectClientStatic = Wg.KeyPair(cliPriv, cliPub),
            injectEph = Wg.KeyPair(ephPriv, Wg.publicKey(ephPriv)),
            injectSender = sndC,
            injectStamp = stamp,
        )
        assertArrayEquals("msg1 ≠ Go", msg1, msg)
    }

    @Test
    fun `keys agree and go packets decrypt`() {
        val (_, ch) = Wg.newClientHandshake(
            srvPub, psk,
            injectClientStatic = Wg.KeyPair(cliPriv, cliPub),
            injectEph = Wg.KeyPair(ephPriv, Wg.publicKey(ephPriv)),
            injectSender = sndC,
            injectStamp = stamp,
        )
        ch.consumeResponse(msg2, psk)
        assertArrayEquals(keyC2S, ch.sendKey)
        assertArrayEquals(keyS2C, ch.recvKey)
        assertEquals(sndS, ch.recvIdx)

        val tr = Wg.clientTransport(ch)
        // Клиент открывает ТОЛЬКО s2c-боксы (ключ сервера→клиента).
        assertArrayEquals(plainS2C, tr.open(boxS2C))
        // Детерминированный seal: шифртекст Kotlin (c2s) == шифртекст Go.
        assertArrayEquals(boxC2S, tr.seal(plainC2S))
        // Прямая проверка s2c-ключа детерминированным seal (зеркало Go).
        val s2cPkt = ByteArray(16 + Wg.seal(keyS2C, 0, null, plainS2C).size)
        Wg.putLe32(s2cPkt, 0, 4)
        Wg.putLe32(s2cPkt, 4, sndC) // receiver = наш sender_index
        for (i in 0 until 8) s2cPkt[8 + i] = 0
        Wg.seal(keyS2C, 0, null, plainS2C).copyInto(s2cPkt, 16)
        assertArrayEquals(boxS2C, s2cPkt)
        assertTrue(boxC2S[0].toInt() == 4)
    }

    @Test
    fun `pubkey derivation matches go`() {
        assertArrayEquals(cliPub, Wg.publicKey(cliPriv))
    }

    @Test
    fun `replay window rejects repeats`() {
        val (_, ch) = Wg.newClientHandshake(
            srvPub, psk,
            injectClientStatic = Wg.KeyPair(cliPriv, cliPub),
            injectEph = Wg.KeyPair(ephPriv, Wg.publicKey(ephPriv)),
            injectSender = sndC,
            injectStamp = stamp,
        )
        ch.consumeResponse(msg2, psk)
        val tr = Wg.clientTransport(ch)
        // Клиент открывает s2c-поток: повтор того же пакета — реплей.
        tr.open(boxS2C)
        try {
            tr.open(boxS2C)
            fail("повтор пакета должен отвергаться")
        } catch (_: Wg.WgException) {
        }
    }

    private fun fail(msg: String): Nothing = throw AssertionError(msg)
}