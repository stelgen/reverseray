package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

/** Минимальная future для err_code OPEN: завершение, ожидание, таймаут. */
class OpenFutureTest {

    @Test
    fun `complete before get returns code immediately`() {
        val f = OpenFuture()
        f.complete(RrpClient.ERR_OK)
        assertEquals(RrpClient.ERR_OK, f.get(100))
    }

    @Test
    fun `get with timeout returns default code when nothing completes`() {
        val f = OpenFuture()
        val start = System.currentTimeMillis()
        val code = f.get(120)
        assertTrue("ожидались >=100 мс", System.currentTimeMillis() - start >= 90)
        assertEquals(RrpClient.ERR_GENERAL, code)
    }

    @Test
    fun `get without timeout blocks until complete`() {
        val f = OpenFuture()
        Thread {
            Thread.sleep(80)
            f.complete(RrpClient.ERR_SSRF_BLOCKED)
        }.start()
        assertEquals(RrpClient.ERR_SSRF_BLOCKED, f.get())
    }
}
