package dev.stelgen.reverseray.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/**
 * SsrfGuard по уже-резолвнутым адресам (защита от DNS-rebinding):
 * hostname «смотрится» публичным, но резолвится в приватный IP.
 */
class SsrfGuardAddressTest {

    private fun v4(a: Int, b: Int, c: Int, d: Int): InetAddress =
        InetAddress.getByAddress(byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte()))

    @Test
    fun `private resolved addresses are blocked`() {
        for (addr in listOf(
            v4(10, 0, 0, 5), v4(172, 16, 4, 4), v4(192, 168, 1, 1),
            v4(100, 64, 9, 9), v4(127, 0, 0, 1), v4(169, 254, 3, 3),
            v4(0, 0, 0, 0), v4(224, 0, 0, 5), v4(240, 1, 1, 1),
        )) {
            assertTrue("must block ${addr.hostAddress}", SsrfGuard.isBlockedAddress(addr))
        }
    }

    @Test
    fun `public resolved addresses allowed`() {
        for (addr in listOf(v4(8, 8, 8, 8), v4(93, 184, 216, 34), v4(172, 32, 0, 1))) {
            assertFalse("must allow ${addr.hostAddress}", SsrfGuard.isBlockedAddress(addr))
        }
    }

    @Test
    fun `allowLan opens only lan ranges`() {
        assertTrue(SsrfGuard.isBlockedAddress(v4(192, 168, 0, 9), allowLan = true) == false)
        assertTrue(SsrfGuard.isBlockedAddress(v4(127, 0, 0, 1), allowLan = true))
        assertTrue(SsrfGuard.isBlockedAddress(v4(169, 254, 1, 2), allowLan = true))
    }

    @Test
    fun `ipv6 ranges by bytes`() {
        val ula = InetAddress.getByAddress(
            byteArrayOf(0xfd.toByte(), 0x00) + ByteArray(14)
        )
        assertTrue(SsrfGuard.isBlockedAddress(ula))
        val ll = InetAddress.getByAddress(
            byteArrayOf(0xfe.toByte(), 0x80.toByte()) + ByteArray(14)
        )
        assertTrue(SsrfGuard.isBlockedAddress(ll))
        // v4-mapped приватный
        val mapped = InetAddress.getByAddress(
            ByteArray(10) + byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 192.toByte(), 168.toByte(), 0, 7)
        )
        assertTrue(SsrfGuard.isBlockedAddress(mapped))
        // публичный v6 (2000::/3)
        val pub = InetAddress.getByAddress(
            byteArrayOf(0x20, 0x01) + ByteArray(14)
        )
        assertFalse(SsrfGuard.isBlockedAddress(pub))
    }
}
