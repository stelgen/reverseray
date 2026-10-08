package dev.stelgen.reverseray.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger

/**
 * КРОСС-ЯЗЫКОВОЙ вектор MTProto (v0.8): конверты зашифрованы Go-сервером
 * (internal/mtproto, генератор katgen_test.go). Kotlin обязан расшифровать
 * их и пройти проверку msg_key — иначе APK и сервер «говорят на разных
 * языках» и mtproto2 не поднимется. Направления:
 *  - K_ENV_SERVER (x=8) — расшифровка клиентом (decryptUp);
 *  - K_ENV_CLIENT (x=0) — зеркало сервера (decryptDown, для тестов).
 */
class MtProtoKATTest {

    private val authKey = run {
        // детерминированный ключ: повторённый SHA-256("cross-lang-kat") до 256 байт
        val seed = java.security.MessageDigest.getInstance("SHA-256")
            .digest("cross-lang-kat".toByteArray(Charsets.UTF_8))
        ByteArray(256) { i -> seed[i % seed.size] }
    }

    private val salt = MtProtoB64.hex(K_SALT)
    private val sessionId = MtProtoB64.hex(K_SESSION_ID)

    @Test
    fun `decrypts go-encoded server envelope`() {
        val crypto = MtProto.SessionCrypto(authKey, salt, sessionId)
        val plain = crypto.decryptUp(MtProtoB64.hex(K_ENV_SERVER))
        assertEquals(K_PAYLOAD, String(plain, Charsets.UTF_8))
    }

    @Test
    fun `decrypts go-encoded client envelope via server mirror`() {
        val crypto = MtProto.SessionCrypto(authKey, salt, sessionId)
        val plain = crypto.decryptDown(MtProtoB64.hex(K_ENV_CLIENT))
        assertEquals(K_PAYLOAD, String(plain, Charsets.UTF_8))
    }

    @Test
    fun `envelope roundtrip matches go kdf shape`() {
        val crypto = MtProto.SessionCrypto(authKey, salt, sessionId)
        val env = crypto.encryptDown(K_PAYLOAD.toByteArray(Charsets.UTF_8))
        // форма конверта: [key_id 8][msg_key 16][IGE кратно 16]
        assertEquals(8, crypto.authKeyId.size)
        assertEquals(0, (env.size - 24) % 16)
        assertArrayEquals(crypto.authKeyId, env.copyOfRange(0, 8))
        val round = crypto.decryptDown(env)
        assertEquals(K_PAYLOAD, String(round, Charsets.UTF_8))
    }

    @Test
    fun `tampered envelope is rejected`() {
        val crypto = MtProto.SessionCrypto(authKey, salt, sessionId)
        val env = MtProtoB64.hex(K_ENV_SERVER).copyOf()
        env[env.size - 2] = (env[env.size - 2].toInt() xor 0x55).toByte()
        try {
            crypto.decryptUp(env)
            fail("изменённый конверт принят")
        } catch (e: MtProto.MtProtoException) {
            // ок
        }
    }

    @Test
    fun `msg_id parity follows canon`() {
        // клиент→сервер: чётные msg_id; конверт Go-сервера (x=8) — нечётный.
        // Проверяем форму: вектор Go K_ENV_SERVER расшифровывается, значит
        // парity-соглашение одинаково на обеих сторонах (Go-тесты плюс этот KAT).
        val crypto = MtProto.SessionCrypto(authKey, salt, sessionId)
        assertNotNull(crypto.decryptUp(MtProtoB64.hex(K_ENV_SERVER)))
    }

    // ---- DH (канон Telegram) ----

    @Test
    fun `dh prime is safe prime with g=3 canon`() {
        assertTrue(MtProto.P.isProbablePrime(20))
        assertTrue(MtProto.P.subtract(BigInteger.ONE).shiftRight(1).isProbablePrime(20))
        assertEquals(2L, MtProto.P.mod(BigInteger.valueOf(3)).longValueExact())
        assertEquals(2048, MtProto.P.bitLength())
    }

    @Test
    fun `client dh produces valid pair and shared key`() {
        val dh = MtProto.ClientDh()
        dh.generatePrivate()
        MtProto.validatePublic(dh.public)
        assertEquals(256, MtProto.publicBytes(dh.public).size)
        // общий ключ с самим собой (симметрия формы) — ненулевой и 256 байт
        val shared = dh.shared(dh.public)
        assertEquals(256, shared.size)
        assertTrue(shared.any { it != 0.toByte() })
    }

    @Test
    fun `rejects out-of-range peer public`() {
        val bad = listOf(
            BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
            MtProto.P.subtract(BigInteger.ONE),
            MtProto.P, // >= P
        )
        for (b in bad) {
            try {
                MtProto.validatePublic(b)
                fail("принята невалидная доля: $b")
            } catch (_: MtProto.MtProtoException) {
            }
        }
    }

    // ---- константы Go-вектора (сгенерированы katgen_test.go на сервере) ----

    private object MtProtoB64 {
        fun hex(s: String): ByteArray = s.chunked(2).map { ((it[0].digitToInt(16) shl 4) + it[1].digitToInt(16)).toByte() }.toByteArray()
    }

    private companion object {
        private const val K_SALT =
            "53414c5431323334"
        private const val K_SESSION_ID =
            "5345535349443838"
        private const val K_ENV_CLIENT =
            "d64107c573188b9ebe9bdad57e20f76f3aa9ad96ad3189b42c04300386820d3e" +
                "136e76dfd4314c9f8c267b0f4a80b686595c5a3b90d670684da091b5fb79c101" +
                "641330decd42319c8ed0f444f766fa51e8860539945d2ce3dafa7f21ec636da4" +
                "2dccc37fcc4030e4bf17ff867040a4cd4ec0e96ec5f8489b5ad22c0aacb5684f" +
                "8c9c58edb54ba809"
        private const val K_ENV_SERVER =
            "d64107c573188b9e486112fca83a24dab66a8928ee9f79522528c778e9025cda" +
                "1ed820ac17143658e109c7ae2d2b3c6c0ae1bb656ee50e2f66043e521c5640e3" +
                "bb5e4fb2fe1153dbe25aaf44c04e3ae5a3d40ad9bff79929843e4635589d4a06" +
                "894da2d5846c8a95badd3b334dafa800d19a2df5f397ae3ce3589b4510e62c70" +
                "0f87a18893cb8375"
        private const val K_PAYLOAD = "ReverseRay MTProto 2.0 cross-language test vector 0123456789"
    }
}