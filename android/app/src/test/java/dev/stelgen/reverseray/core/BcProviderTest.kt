package dev.stelgen.reverseray.core

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.Security

/**
 * Регрессия на "no such algorithm: SHA-512 for provider BC" (Android 12):
 * BC-TLS резолвит дайджесты через Security по имени "BC" — там системный
 * урезанный провайдер отсутствует. ensureFullBouncyCastle() обязан
 * зарегистрировать полный BC из пакета.
 */
class BcProviderTest {

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
    fun `ensure is idempotent`() {
        RrpClient.ensureFullBouncyCastle()
        RrpClient.ensureFullBouncyCastle()
        assertNotNull(Security.getProvider("BC"))
    }
}
