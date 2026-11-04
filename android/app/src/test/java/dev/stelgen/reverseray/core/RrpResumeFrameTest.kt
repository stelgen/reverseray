package dev.stelgen.reverseray.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** v1.3.0 «буфер трафика»: кадры резюме стримов (0x2D/0x2E). */
class RrpResumeFrameTest {

    @Test
    fun resumeTokenRoundtrip() {
        val tok = ByteArray(16) { (it * 7).toByte() }
        val f = RrpFrame.ResumeToken(tok)
        val bytes = f.encode()
        val parsed = RrpFrame.parse(bytes.inputStream()) as RrpFrame.ResumeToken
        assertArrayEquals(tok, parsed.token)
        assertEquals(RrpFrame.TYPE_RESUME_TOKEN, parsed.type)
    }

    @Test
    fun openResumeRoundtrip() {
        val tok = ByteArray(16) { (it * 13 + 1).toByte() }
        val f = RrpFrame.OpenResume(tok)
        val bytes = f.encode()
        val parsed = RrpFrame.parse(bytes.inputStream()) as RrpFrame.OpenResume
        assertArrayEquals(tok, parsed.token)
        assertEquals(RrpFrame.TYPE_OPEN_RESUME, parsed.type)
    }

    @Test
    fun wrongTokenSizeRejected() {
        for (bad in listOf(0, 8, 15, 17, 4096)) {
            val payload = ByteArray(bad)
            try {
                RrpFrame.ResumeToken.fromPayload(payload)
                throw AssertionError("payload $bad не отклонён")
            } catch (e: RrpFrameException) {
                assertTrue(e.message!!.contains("RESUME"))
            }
        }
    }

    @Test
    fun tokenSurvivesWireFormat() {
        // Кадр должен проходить по сети байт-в-байт (заголовок 12 Б + payload 16 Б).
        val tok = ByteArray(16) { (it + 3).toByte() }
        val bytes = RrpFrame.ResumeToken(tok).encode()
        assertEquals(12 + 16, bytes.size)
        val f2 = RrpFrame.parse(bytes.inputStream()) as RrpFrame.ResumeToken
        assertArrayEquals(tok, f2.token)
    }
}