package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Канонический обмен APK ↔ сервер: кодировка HELLO/AUTH/PROBE (v0.7.4). */
class RrpFrameCanonTest {

    @Test
    fun `hello payload carries ver as quoted string`() {
        val bytes = RrpFrame.Hello("ReverseRay-Android/0.7.4", 1, "phone-1", listOf("chacha20"), 64).encode()
        val payload = String(bytes.copyOfRange(RrpFrame.HEADER_SIZE, bytes.size), Charsets.UTF_8)
        // в0.7.3 баг: "ver":1 числом — Go-сервер падал на json.Unmarshal в string
        assertTrue("должно быть \"ver\":\"1\", got: $payload", payload.contains("\"ver\":\"1\""))
        assertTrue(!payload.contains("\"ver\":1"))
        assertTrue(payload.contains("\"proto\":\"rrp1\""))
        assertTrue(payload.contains("\"protocols\""))
    }

    @Test
    fun `hello roundtrip keeps proto and protocols`() {
        val f = RrpFrame.Hello("agent", 1, "dev", listOf("c"), 64, proto = "rrp1", protocols = listOf("rrp1"))
        val parsed = RrpFrame.parse(f.encode()) as RrpFrame.Hello
        assertEquals("rrp1", parsed.proto)
        assertEquals(listOf("rrp1"), parsed.protocols)
    }

    @Test
    fun `hello ok parses proto and protocols from server`() {
        val serverJson = """{"session_id":"s1","server_ver":"dev","nonce":"AAAA","tunnel_window":2097152,"proto":"rrp1","protocols":["rrp1"]}"""
        val parsed = RrpFrame.parse(frameBytes(RrpFrame.TYPE_HELLO_OK, serverJson.toByteArray())) as RrpFrame.HelloOk
        assertEquals("rrp1", parsed.proto)
        assertEquals(listOf("rrp1"), parsed.protocols)
    }

    @Test
    fun `ready parses proto`() {
        val serverJson = """{"tunnel_id":"t1","role":"active","max_streams":256,"tunnel_window":2097152,"proto":"rrp1","protocols":["rrp1"]}"""
        val parsed = RrpFrame.parse(frameBytes(RrpFrame.TYPE_READY, serverJson.toByteArray())) as RrpFrame.Ready
        assertEquals("rrp1", parsed.proto)
    }

    @Test
    fun `probe req payload carries target and timeout`() {
        val req = RrpFrame.ProbeReq("1.1.1.1:443", 5000)
        val bytes = req.encode()
        assertEquals(RrpFrame.TYPE_PROBE, bytes[1].toInt() and 0xFF)
        val payload = String(bytes.copyOfRange(RrpFrame.HEADER_SIZE, bytes.size), Charsets.UTF_8)
        assertTrue(payload.contains("\"target\":\"1.1.1.1:443\""))
        assertTrue(payload.contains("\"timeout_ms\":5000"))

        val resp = RrpFrame.ProbeResp(ok = true, err = "", proto = "rrp1")
        val parsedResp = RrpFrame.parse(resp.encode()) as RrpFrame.ProbeResp
        assertTrue(parsedResp.ok)
        assertEquals("rrp1", parsedResp.proto)

        val fail = RrpFrame.ProbeResp(ok = false, err = "нет egress", proto = "rrp1")
        val parsedFail = RrpFrame.parse(fail.encode()) as RrpFrame.ProbeResp
        assertEquals(false, parsedFail.ok)
        assertEquals("нет egress", parsedFail.err)
    }
    /** 12-байтовый BE-заголовок + payload — имитация кадра от сервера. */
    private fun frameBytes(type: Int, payload: ByteArray): ByteArray {
        val out = ByteArray(12 + payload.size)
        out[0] = 1
        out[1] = type.toByte()
        out[2] = 0; out[3] = 0
        for (i in 0 until 4) out[4 + i] = 0
        val len = payload.size
        out[8] = ((len ushr 24) and 0xFF).toByte()
        out[9] = ((len ushr 16) and 0xFF).toByte()
        out[10] = ((len ushr 8) and 0xFF).toByte()
        out[11] = (len and 0xFF).toByte()
        payload.copyInto(out, 12)
        return out
    }
}
