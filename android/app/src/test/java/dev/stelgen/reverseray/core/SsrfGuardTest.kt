package dev.stelgen.reverseray.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SsrfGuardTest {

    private val blocked = listOf(
        "0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255",
        "100.64.0.1", "100.127.255.255", "127.0.0.1", "127.8.8.8",
        "169.254.1.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
        "198.18.0.5", "224.0.0.1", "240.0.0.1", "255.255.255.255",
        "localhost"
    )

    private val allowed = listOf(
        "8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "100.128.0.1",
        "198.20.0.1", "172.15.255.255", "192.169.0.1"
    )

    @Test
    fun privateRangesBlocked() {
        for (h in blocked) {
            assertTrue("must block $h", SsrfGuard.isBlocked(h))
        }
    }

    @Test
    fun publicAllowed() {
        for (h in allowed) {
            assertFalse("must allow $h", SsrfGuard.isBlocked(h))
        }
    }

    @Test
    fun allowLanDisablesGuard() {
        assertFalse(SsrfGuard.isBlocked("192.168.1.1", allowLan = true))
    }

    @Test
    fun badHostnamesBlocked() {
        assertTrue(SsrfGuard.isBlocked(""))
        assertTrue(SsrfGuard.isBlocked("nonexistent.invalid.host."))
    }
}
