package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Кадр NOISE (0x26, v0.8.2) и READY.features: кодирование/разбор,
 * вложенный JSON серверных ответов, мусор отсекается.
 */
class RrpFrameNoiseTest {

    @Test
    fun `noise roundtrip keeps payload`() {
        val body = "{\"app\":\"com.acme.workspace\",\"events\":[{\"n\":1,\"meta\":{\"x\":2}}]}"
        val frame = RrpFrame.Noise(body)
        val parsed = RrpFrame.parse(frame.encode())
        assertTrue(parsed is RrpFrame.Noise)
        assertEquals(body, (parsed as RrpFrame.Noise).json)
    }

    @Test
    fun `noise accepts nested server responses`() {
        // сервер отвечает объектами с вложенными объектами/массивами:
        // парсер НЕ должен падать на вложенности (MiniJson.parseFlat тут не участвует)
        val serverBody = "{\"code\":200,\"items\":[{\"id\":\"ab\"}],\"settings\":{\"opt1\":true}}"
        val parsed = RrpFrame.parse(
            RrpFrame.Noise(serverBody).encode(),
        )
        assertEquals(serverBody, (parsed as RrpFrame.Noise).json)
    }

    @Test(expected = RrpFrameException::class)
    fun `noise rejects non object`() {
        RrpFrame.Noise.fromPayload("[1,2,3]".toByteArray())
    }

    @Test(expected = RrpFrameException::class)
    fun `noise rejects unbalanced json`() {
        RrpFrame.Noise.fromPayload("{\"a\":{\"b\":1}".toByteArray())
    }

    @Test
    fun `noise respects control payload limit`() {
        val big = "{\"pad\":\"" + "x".repeat(RrpFrame.MAX_CONTROL_PAYLOAD) + "\"}"
        try {
            RrpFrame.Noise(big).encode()
            org.junit.Assert.fail("ожидали RrpFrameException")
        } catch (_: RrpFrameException) {
            // ожидаемо: payload > 4096
        }
    }

    /** Оборачивает JSON-payload в полноценный кадр READY (0x04, ver=1). */
    private fun readyFrame(json: String): ByteArray {
        val payload = json.toByteArray(Charsets.UTF_8)
        val out = ByteArray(RrpFrame.HEADER_SIZE + payload.size)
        out[0] = RrpFrame.VERSION.toByte()
        out[1] = RrpFrame.TYPE_READY.toByte()
        out[RrpFrame.HEADER_SIZE - 4] = (payload.size ushr 24).toByte()
        out[RrpFrame.HEADER_SIZE - 3] = (payload.size ushr 16).toByte()
        out[RrpFrame.HEADER_SIZE - 2] = (payload.size ushr 8).toByte()
        out[RrpFrame.HEADER_SIZE - 1] = payload.size.toByte()
        payload.copyInto(out, RrpFrame.HEADER_SIZE)
        return out
    }

    @Test
    fun `ready parses server features`() {
        val json = "{\"tunnel_id\":\"t1\",\"role\":\"active\",\"max_streams\":64," +
            "\"tunnel_window\":2097152,\"proto\":\"rrp1\",\"protocols\":[\"rrp1\",\"mtproto2\"]," +
            "\"features\":[\"apimask\"]}"
        val ready = RrpFrame.parse(readyFrame(json)) as RrpFrame.Ready
        assertEquals(listOf("apimask"), ready.features)
        assertEquals(listOf("rrp1", "mtproto2"), ready.protocols)
    }

    @Test
    fun `ready without features is compatible with old servers`() {
        val json = "{\"tunnel_id\":\"t1\",\"role\":\"active\",\"max_streams\":64," +
            "\"tunnel_window\":2097152,\"proto\":\"rrp1\",\"protocols\":[\"rrp1\"]}"
        val ready = RrpFrame.parse(readyFrame(json)) as RrpFrame.Ready
        assertTrue(ready.features.isEmpty())
    }
}
