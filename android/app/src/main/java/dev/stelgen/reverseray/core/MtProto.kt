package dev.stelgen.reverseray.core

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * MTProto 2.0-крипто для протокола туннеля mtproto2 (v0.8).
 *
 * ЗЕРКАЛО server/internal/mtproto (Go) — алгоритмы байт-в-байт:
 *  - DH: официальный dh_prime Telegram (safe prime, вшит «known good» по
 *    рекомендации Security Guidelines), g=3; валидация долей пира:
 *    1 < peer < p−1 и коридор [2^1984, p−2^1984];
 *  - auth_key = 256 байт big-endian g_ab; auth_key_id = SHA1(auth_key)[0:8];
 *  - msg_key = SHA256(auth_key[88+x:120+x] + plaintext)[8:24] (канон 2.0);
 *  - AES-256-IGE поверх ECB (без провайдер-зависимостей — как на сервере);
 *  - конверт [key_id 8][msg_key 16][IGE(inner)]; inner = [salt 8][session 8]
 *    [msg_id 8][seq 4][len 4][data][pad]; msg_id чётный клиент→сервер и
 *    нечётный сервер→клиент; паддинг 16..31 байт (канон 12..1024).
 *
 * Кросс-языковой вектор (Go-сервер зашифровал, Kotlin расшифровывает и
 * наоборот) — MtProtoKATTest: гарантия что APK и сервер говорят одно и то же.
 */
object MtProto {

    const val PROTO_ID = "mtproto2"

    // Официальный dh_prime Telegram (core.telegram.org/mtproto/security_guidelines).
    private const val DH_PRIME_HEX =
        "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F" +
        "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37" +
        "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64" +
        "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4" +
        "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754" +
        "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4" +
        "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F" +
        "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B"

    val P: BigInteger = BigInteger(DH_PRIME_HEX, 16)
    val G: BigInteger = BigInteger.valueOf(3)
    private val BOUND_LOW: BigInteger = BigInteger.ONE.shiftLeft(2048 - 64) // 2^1984
    private val BOUND_HIGH: BigInteger = P.subtract(BOUND_LOW)

    const val X_CLIENT = 0 // клиент → сервер
    const val X_SERVER = 8 // сервер → клиент

    class MtProtoException(message: String) : Exception(message)

    // ---------------------------------------------------------------- DH

    /** Валидация публичной доли пира (канон Security Guidelines). */
    fun validatePublic(pub: BigInteger) {
        if (pub <= BigInteger.ONE) throw MtProtoException("g_peer <= 1")
        if (pub >= P.subtract(BigInteger.ONE)) throw MtProtoException("g_peer >= P-1")
        if (pub < BOUND_LOW) throw MtProtoException("g_peer < 2^1984")
        if (pub > BOUND_HIGH) throw MtProtoException("g_peer > P - 2^1984")
    }

    /** Публичная доля как ровно 256 байт big-endian. */
    fun publicBytes(pub: BigInteger): ByteArray = padded256(pub)

    private fun padded256(v: BigInteger): ByteArray {
        val b = v.toByteArray() // возможен ведущий 0 на знак
        val unsigned = if (b.size == 257 && b[0].toInt() == 0) b.copyOfRange(1, 257) else b
        if (unsigned.size > 256) throw MtProtoException("g_peer > 256 байт")
        val out = ByteArray(256)
        System.arraycopy(unsigned, 0, out, 256 - unsigned.size, unsigned.size)
        return out
    }

    fun publicFromBytes(b: ByteArray): BigInteger {
        if (b.size != 256) throw MtProtoException("публичная доля должна быть 256 байт")
        return BigInteger(1, b)
    }

    /**
     * DH-сторона клиента: pair.generatePrivate() → отправить g_b.
     * Приватная доля нормирована в коридор, публичная проверяется —
     * повторяем до успеха (как на сервере).
     */
    class ClientDh(private val rnd: SecureRandom = SecureRandom()) {
        var priv: BigInteger = BigInteger.ZERO
            private set
        var public: BigInteger = BigInteger.ZERO
            private set

        fun generatePrivate() {
            for (attempt in 0 until 64) {
                val buf = ByteArray(256)
                rnd.nextBytes(buf)
                var x = BigInteger(1, buf)
                x = x.mod(P.subtract(BOUND_LOW)).add(BOUND_LOW)
                val pub = G.modPow(x, P)
                try {
                    validatePublic(pub)
                    priv = x
                    public = pub
                    return
                } catch (_: MtProtoException) {
                    // повторить
                }
            }
            throw MtProtoException("не удалось сгенерировать валидную пару")
        }

        /** Общий ключ g_ab как 256 байт (auth_key). */
        fun shared(peerPublic: BigInteger): ByteArray {
            validatePublic(peerPublic)
            val gab = peerPublic.modPow(priv, P)
            if (gab < BOUND_LOW || gab > BOUND_HIGH) throw MtProtoException("g_ab вне коридора")
            return padded256(gab)
        }
    }

    fun authKeyId(authKey: ByteArray): ByteArray {
        val sum = MessageDigest.getInstance("SHA-1").digest(authKey)
        return sum.copyOfRange(0, 8)
    }

    // ---- вывод salt/session_id из RRP session (зеркало wire.go сервера) ----

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** session_id конверта = SHA256("mtproto2:" + rrp_session_id)[0:8]. */
    fun sessionId8(rrpSessionId: String): ByteArray =
        sha256("mtproto2:".toByteArray(Charsets.UTF_8) + rrpSessionId.toByteArray(Charsets.UTF_8))
            .copyOfRange(0, 8)

    /** salt конверта = SHA256("mtproto2-salt:" + sid || g_a || g_b)[0:8]. */
    fun saltFor(rrpSessionId: String, gA: ByteArray, gB: ByteArray): ByteArray =
        sha256(
            "mtproto2-salt:".toByteArray(Charsets.UTF_8) +
                rrpSessionId.toByteArray(Charsets.UTF_8) + gA + gB,
        ).copyOfRange(0, 8)

    /** base64url без паддинга (канон обмена долями). */
    fun b64url(b: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    fun b64urlDecode(s: String): ByteArray {
        val v = s.trim()
        return try {
            java.util.Base64.getUrlDecoder().decode(v)
        } catch (_: IllegalArgumentException) {
            try {
                java.util.Base64.getDecoder().decode(v)
            } catch (e2: IllegalArgumentException) {
                throw MtProtoException("не base64: ${v.take(32)}")
            }
        }
    }

    // ---------------------------------------------------------------- IGE

    /** AES-256-IGE поверх ECB: идентично серверу (без JCE-провайдер-магии). */
    internal class Ige(key: ByteArray) {
        private val cipher: Cipher = Cipher.getInstance("AES/ECB/NoPadding")
        private val block = ByteArray(16)

        init {
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        }

        fun encrypt(data: ByteArray, iv: ByteArray): ByteArray {
            require(data.size % 16 == 0) { "IGE: длина не кратна блоку" }
            val x = iv.copyOfRange(0, 16) // c-цепочка
            val y = iv.copyOfRange(16, 32) // p-цепочка
            val out = ByteArray(data.size)
            var i = 0
            while (i < data.size) {
                for (j in 0 until 16) block[j] = (data[i + j].toInt() xor x[j].toInt()).toByte()
                val enc = cipher.doFinal(block)
                for (j in 0 until 16) out[i + j] = (enc[j].toInt() xor y[j].toInt()).toByte()
                System.arraycopy(out, i, x, 0, 16)
                System.arraycopy(data, i, y, 0, 16)
                i += 16
            }
            return out
        }

        fun decrypt(data: ByteArray, iv: ByteArray): ByteArray {
            require(data.size % 16 == 0) { "IGE: длина не кратна блоку" }
            val x = iv.copyOfRange(0, 16) // c-цепочка (c_{i-1})
            val y = iv.copyOfRange(16, 32) // p-цепочка (p_{i-1})
            val out = ByteArray(data.size)
            var i = 0
            while (i < data.size) {
                for (j in 0 until 16) block[j] = (data[i + j].toInt() xor y[j].toInt()).toByte()
                val dec = cipher.doFinal(block)
                for (j in 0 until 16) out[i + j] = (dec[j].toInt() xor x[j].toInt()).toByte()
                System.arraycopy(data, i, x, 0, 16)
                System.arraycopy(out, i, y, 0, 16)
                i += 16
            }
            return out
        }
    }

    // ---------------------------------------------------------------- KDF

    /** msg_key = SHA256(auth_key[88+x:120+x] + plaintext)[8:24] — канон 2.0. */
    fun msgKey(authKey: ByteArray, x: Int, plaintext: ByteArray): ByteArray {
        val acc = authKey.copyOfRange(88 + x, 120 + x) + plaintext
        val sum = MessageDigest.getInstance("SHA-256").digest(acc)
        return sum.copyOfRange(8, 24)
    }

    /** AES key/IV из канонической таблицы MTProto 2.0. */
    fun kdfParams(authKey: ByteArray, msgKey: ByteArray, x: Int): Pair<ByteArray, ByteArray> {
        val md = MessageDigest.getInstance("SHA-256")
        val shaA = md.digest(msgKey + authKey.copyOfRange(x, x + 36))
        val shaB = md.digest(authKey.copyOfRange(40 + x, 40 + x + 52) + msgKey)
        val key = ByteArray(32)
        System.arraycopy(shaA, 0, key, 0, 8)
        System.arraycopy(shaB, 8, key, 8, 16)
        System.arraycopy(shaA, 24, key, 24, 8)
        val iv = ByteArray(32)
        System.arraycopy(shaB, 0, iv, 0, 8)
        System.arraycopy(shaA, 8, iv, 8, 16)
        System.arraycopy(shaB, 24, iv, 24, 8)
        return key to iv
    }

    // ------------------------------------------------------------ Session

    /**
     * Крипто-контекст сессии mtproto2. Клиентская сторона: шифрует x=0,
     * расшифровывает x=8 (зеркало сервера).
     */
    class SessionCrypto(authKey: ByteArray, salt: ByteArray, sessionId: ByteArray) {
        val authKey: ByteArray = authKey.copyOf()
        val authKeyId: ByteArray = authKeyId(this.authKey)
        private val salt: ByteArray = salt.copyOf()
        private val sessionId: ByteArray = sessionId.copyOf()
        private var msgIdEnc: Long = 0

        init {
            require(authKey.size == 256) { "auth_key должен быть 256 байт" }
            require(salt.size == 8 && sessionId.size == 8) { "salt/session_id должны быть 8 байт" }
        }

        private fun encrypt(x: Int, payload: ByteArray): ByteArray {
            if (payload.size > MAX_PLAIN_DATA) throw MtProtoException("payload превышает лимит DATA")
            msgIdEnc++
            var msgId = msgIdEnc * 4
            if (x == X_SERVER) msgId += 1 // нечётный для сервер→клиент
            val seqNo = (msgIdEnc * 2).toInt()
            val total = 32 + payload.size
            var padLen = 16 - total % 16
            if (padLen < 16) padLen += 16
            val pad = ByteArray(padLen)
            SecureRandom().nextBytes(pad)
            val inner = java.io.ByteArrayOutputStream(total + padLen)
            inner.write(salt)
            inner.write(sessionId)
            val mid = ByteArray(8)
            for (i in 0 until 8) mid[i] = ((msgId ushr ((7 - i) * 8)) and 0xFF).toByte()
            inner.write(mid)
            val sq = ByteArray(4)
            for (i in 0 until 4) sq[i] = ((seqNo ushr ((3 - i) * 8)) and 0xFF).toByte()
            inner.write(sq)
            val ln = ByteArray(4)
            for (i in 0 until 4) ln[i] = ((payload.size ushr ((3 - i) * 8)) and 0xFF).toByte()
            inner.write(ln)
            inner.write(payload)
            inner.write(pad)
            val body = inner.toByteArray()
            val mk = msgKey(authKey, x, body)
            val (key, iv) = kdfParams(authKey, mk, x)
            val enc = Ige(key).encrypt(body, iv)
            return authKeyId + mk + enc
        }

        private fun decrypt(x: Int, env: ByteArray): ByteArray {
            if (env.size < 24 + 16 || (env.size - 24) % 16 != 0) throw MtProtoException("битый конверт")
            if (!java.security.MessageDigest.isEqual(authKeyId, env.copyOfRange(0, 8))) {
                throw MtProtoException("чужой auth_key_id")
            }
            val mk = env.copyOfRange(8, 24)
            val (key, iv) = kdfParams(authKey, mk, x)
            val body = Ige(key).decrypt(env.copyOfRange(24, env.size), iv)
            if (body.size < 32) throw MtProtoException("тело короче заголовка")
            if (!MessageDigest.isEqual(body.copyOfRange(0, 8), salt)) throw MtProtoException("salt не совпал")
            if (!MessageDigest.isEqual(body.copyOfRange(8, 16), sessionId)) throw MtProtoException("session_id не совпал")
            val msgLen = ((body[28].toInt() and 0xFF) shl 24) or ((body[29].toInt() and 0xFF) shl 16) or
                ((body[30].toInt() and 0xFF) shl 8) or (body[31].toInt() and 0xFF)
            val rest = body.size - 32
            if (msgLen < 0 || msgLen > rest) throw MtProtoException("msg_len > тела")
            val padLen = rest - msgLen
            if (padLen < 12 || padLen > 1024) throw MtProtoException("паддинг $padLen вне 12..1024")
            val expect = msgKey(authKey, x, body)
            if (!MessageDigest.isEqual(expect, mk)) throw MtProtoException("msg_key не сошёлся")
            return body.copyOfRange(32, 32 + msgLen)
        }

        /** Клиент шлёт (x=0). */
        fun encryptDown(payload: ByteArray): ByteArray = encrypt(X_CLIENT, payload)

        /** Клиент принимает от сервера (расшифровка x=8). */
        fun decryptUp(env: ByteArray): ByteArray = decrypt(X_SERVER, env)

        /** Зеркало сервера: расшифровка клиентского конверта (x=0) — для кросс-языковых тестов. */
        fun decryptDown(env: ByteArray): ByteArray = decrypt(X_CLIENT, env)

        companion object {
            /** Потолок открытого DATA-чанка (зеркало maxPlainData сервера). */
            const val MAX_PLAIN_DATA = 64 * 1024 - 128
        }
    }
}