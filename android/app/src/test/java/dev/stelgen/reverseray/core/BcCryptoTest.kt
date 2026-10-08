package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.Security

/**
 * Регрессия "no such algorithm: SHA-512 for provider BC".
 * v0.7: RRP-клиент использует BcTlsCrypto (lightweight, без JCA) — TLS-крипто
 * больше вообще не зависит от платформенного провайдера "BC", который на
 * Android урезан (полная регистрация остаётся belt-and-suspenders).
 */
class BcCryptoTest {

    @Test
    fun `tls crypto is lightweight BcTlsCrypto - no JCA provider dependency`() {
        val crypto = RrpClient.defaultCrypto()
        assertTrue(
            "ожидался org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto, получен ${crypto.javaClass.name}",
            crypto.javaClass.name.contains("BcTlsCrypto"),
        )
    }

    @Test
    fun `sha-512 resolvable through BC after ensure`() {
        RrpClient.ensureFullBouncyCastle()
        val provider = Security.getProvider("BC")
        assertNotNull("BC provider must be registered", provider)
        assertTrue(
            "BC must be the full BouncyCastleProvider from the APK",
            provider.javaClass.name.contains("bouncycastle"),
        )
        assertNotNull(MessageDigest.getInstance("SHA-512", "BC"))
        assertNotNull(MessageDigest.getInstance("SHA-256", "BC"))
    }

    @Test
    fun `sha-512 available without any provider games (default JVM path)`() {
        assertNotNull(MessageDigest.getInstance("SHA-512"))
        assertEquals(64, MessageDigest.getInstance("SHA-512").digest(ByteArray(10)).size)
    }

    @Test
    fun `ensure is idempotent`() {
        RrpClient.ensureFullBouncyCastle()
        RrpClient.ensureFullBouncyCastle()
        assertNotNull(Security.getProvider("BC"))
    }
}
