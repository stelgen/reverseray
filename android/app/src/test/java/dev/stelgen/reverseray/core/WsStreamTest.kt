package dev.stelgen.reverseray.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64

/**
 * WsStream на plain JVM: апгрейд-ответ, маскированная запись, парсинг
 * серверных кадров (binary/ping/close).
 */
class WsStreamTest {

    /**
     * Серверная сторона эмулируется байтами: input = HTTP-ответ апгрейда +
     * последующие WS-кадры «сервера»; output собирает всё, что записал клиент.
     */
    private fun makeStream(response: String, serverFrames: ByteArray): Pair<WsStream, ByteArrayOutputStream> {
        val serverToClient = ByteArrayInputStream(response.toByteArray(Charsets.US_ASCII) + serverFrames)
        val clientToServer = ByteArrayOutputStream()
        val ws = WsStream(serverToClient, clientToServer, "h", 443, deterministicRng())
        return ws to clientToServer
    }

    /** Хвост wire после HTTP-апгрейд-запроса (кадры, записанные клиентом). */
    private fun framesAfterRequest(wire: ByteArray): ByteArray {
        val end = listOf(0x0D, 0x0A, 0x0D, 0x0A) // CRLF CRLF - конец HTTP-запроса

        for (i in 0..wire.size - 4) {
            if ((0..3).all { wire[i + it].toInt() == end[it] }) {
                return wire.copyOfRange(i + 4, wire.size)
            }
        }
        throw AssertionError("upgrade request not found in wire")
    }

    /** Детерминированный RNG: ключ апгрейда в тесте воспроизводим. */
    private fun deterministicRng() =
        java.security.SecureRandom.getInstance("SHA1PRNG").apply { setSeed(0x5EED5EEDL) }

    /** Ключ, который клиент отправит первым вызовом nextBytes(16). */
    private fun clientKey(): String {
        val b = ByteArray(16)
        deterministicRng().nextBytes(b)
        return Base64.getEncoder().encodeToString(b)
    }

    private fun binaryFrame(payload: ByteArray, mask: Boolean = false): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x82)
        if (payload.size < 126) {
            out.write((if (mask) 0x80 else 0) or payload.size)
        } else {
            out.write((if (mask) 0x80 else 0) or 126)
            out.write((payload.size ushr 8) and 0xFF)
            out.write(payload.size and 0xFF)
        }
        out.write(payload)
        return out.toByteArray()
    }

    @Test
    fun `handshake accepts 101 with correct accept header`() {
        val key = clientKey()
        val accept = Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-1").digest((key + WsStream.WS_GUID).toByteArray()),
        )
        val (ws, _) = makeStream(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
                "Sec-WebSocket-Accept: $accept\r\n\r\n",
            binaryFrame("hello".toByteArray()),
        )
        ws.handshake()
        val got = ByteArray(5)
        assertEquals(5, ws.read(got, 0, 5))
        assertArrayEquals("hello".toByteArray(), got)
    }

    @Test
    fun `handshake rejects non-101`() {
        val (ws, _) = makeStream("HTTP/1.1 404 Not Found\r\n\r\n", ByteArray(0))
        try {
            ws.handshake()
            throw AssertionError("expected failure")
        } catch (e: RrpClientException) {
            assertTrue(e.message!!.contains("404"))
        }
    }

    @Test
    fun `outgoing frames are masked binary messages`() {
        val key = clientKey()
        val accept = Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-1").digest((key + WsStream.WS_GUID).toByteArray()),
        )
        val (ws, wire) = makeStream(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: $accept\r\n\r\n", ByteArray(0),
        )
        ws.handshake()
        val payload = "RRP-frame-bytes".toByteArray()
        ws.writeMessage(payload)
        val raw = framesAfterRequest(wire.toByteArray())
        // FIN|binary, MASK=1
        assertEquals(0x82.toByte(), raw[0])
        assertEquals(0x80.toByte(), (raw[1].toInt() and 0x80).toByte())
        assertEquals(payload.size, raw[1].toInt() and 0x7F)
        // размаскируем и сверим
        val mask = raw.sliceArray(2..5)
        val data = raw.sliceArray(6 until raw.size)
        for (i in data.indices) {
            assertEquals(payload[i], (data[i].toInt() xor mask[i % 4].toInt()).toByte())
        }
    }

    @Test
    fun `ping answered with pong transparently`() {
        val key = clientKey()
        val accept = Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-1").digest((key + WsStream.WS_GUID).toByteArray()),
        )
        val ping = ByteArrayOutputStream()
        ping.write(0x89)
        ping.write(4)
        ping.write(byteArrayOf(1, 2, 3, 4))
        val frames = ping.toByteArray() + binaryFrame("d".toByteArray())
        val (ws, wire) = makeStream(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: $accept\r\n\r\n", frames,
        )
        ws.handshake()
        val got = ByteArray(1)
        assertEquals(1, ws.read(got, 0, 1))
        assertEquals('d'.code.toByte(), got[0])
        // клиент должен был ответить pong (0x8A) — в первом кадре после запроса
        val raw = framesAfterRequest(wire.toByteArray())
        assertTrue(raw.size >= 2 + 4)
        assertTrue((raw[0].toInt() and 0x0F) == 0xA)
    }

    @Test
    fun `close frame means EOF`() {
        val key = clientKey()
        val accept = Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-1").digest((key + WsStream.WS_GUID).toByteArray()),
        )
        val close = byteArrayOf(0x88.toByte(), 0x00)
        val (ws, _) = makeStream(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: $accept\r\n\r\n", close,
        )
        ws.handshake()
        assertEquals(-1, ws.read(ByteArray(4), 0, 4))
    }
}
