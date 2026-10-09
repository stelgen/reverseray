package dev.stelgen.reverseray.core

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * WireGuard-крипто для протокола туннеля wireguard (v0.9.5, зеркало
 * server/internal/wg): НАСТОЯЩИЙ канон WireGuard whitepaper 2017
 * (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s), а не имитация:
 *
 *  - хендшейк WG msg1/msg2 (mac1, enc_static, enc_timestamp, TAI64N);
 *  - PSK-режим: preshared key = SHA256(token) — наш ключ доверия;
 *  - transport-пакеты [type=4][receiver][counter][ChaCha20-Poly1305];
 *  - sliding-window анти-реплей (2048), счётчики пакетов.
 *
 * Клиент — WG-инициатор; ключи приходят от сервера кадром KEY_REQ
 * ({"kind":"wireguard","spub":…}) после READY внутри приватного канала.
 * Pure BC 1.86 (x25519/blake2s/chacha20poly1305) — все Android 4+.
 */
object Wg {

    const val PROTO_ID = "wireguard"

    // ---- канон WireGuard ----
    const val CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    const val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com"
    const val LABEL_MAC1 = "mac1----"

    const val MSG_INIT_SIZE = 148
    const val MSG_RESP_SIZE = 92
    const val TRANSPORT_OVERHEAD = 16 + 16 // заголовок type4 + тег Poly1305
    const val KEY_SIZE = 32
    const val STAMP_SIZE = 12
    const val REPLAY_WINDOW = 2048

    /** Максимум ОТКРЫТОГО чанка в WG-конверте (зеркало Go). */
    const val MAX_PLAIN_DATA = 65535 - TRANSPORT_OVERHEAD + 1 // 65536-32

    private val rnd = SecureRandom()

    // ---- хеши/KDF (HMAC-BLAKE2s-256) ----

    private fun hmac(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = HMac(Blake2sDigest(256))
        mac.init(KeyParameter(key))
        mac.update(msg, 0, msg.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    fun hash2(a: ByteArray, b: ByteArray): ByteArray {
        val h = Blake2sDigest(256)
        h.update(a, 0, a.size)
        h.update(b, 0, b.size)
        val out = ByteArray(32)
        h.doFinal(out, 0)
        return out
    }

    /** KDF2 канона WG: t0 = HMAC(ck,ikm); t1 = HMAC(ck,t0‖0x01); ck' = HMAC(t1,0x02). */
    fun kdf2(ck: ByteArray, ikm: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val t0 = hmac(ck, ikm)
        val t1 = hmac(ck, t0 + byteArrayOf(1))
        val next = hmac(t1, byteArrayOf(2))
        return Triple(t0, t1, next)
    }

    /** KDF3 канона WG: …; ck' = HMAC(t2,0x03). Возвращает (t0, t1, t2). */
    fun kdf3(ck: ByteArray, ikm: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val t0 = hmac(ck, ikm)
        val t1 = hmac(ck, t0 + byteArrayOf(1))
        val t2 = hmac(ck, t1 + byteArrayOf(2))
        val next = hmac(t2, byteArrayOf(3))
        return Triple(t0, t1, next)
    }

    fun macKeyMac1(staticPub: ByteArray): ByteArray =
        hash2(LABEL_MAC1.toByteArray(Charsets.US_ASCII), staticPub)

    /** mac1 = keyed-BLAKE2s по префиксу кадра до поля mac1. */
    fun mac1(key: ByteArray, prefix: ByteArray): ByteArray {
        val h = Blake2sDigest(key) // keyed-BLAKE2s-256
        h.update(prefix, 0, prefix.size)
        val out = ByteArray(32)
        h.doFinal(out, 0)
        return out.copyOf(16)
    }

    /** TAI64N канона WG: 8Б секунд (смещение 2^62) BE + 4Б наносекунд BE. */
    fun tai64n(): ByteArray {
        val now = System.currentTimeMillis()
        val secs = (now / 1000) + (1L shl 62)
        val nanos = (now % 1000) * 1_000_000
        val out = ByteArray(STAMP_SIZE)
        putBe64(out, 0, secs)
        putBe32(out, 8, nanos)
        return out
    }

    fun tai64nAfter(a: ByteArray, b: ByteArray): Boolean {
        for (i in 0 until STAMP_SIZE) {
            val x = a[i].toInt() and 0xFF
            val y = b[i].toInt() and 0xFF
            if (x != y) return x > y
        }
        return false
    }

    private fun putBe64(b: ByteArray, off: Int, v: Long) {
        for (i in 0 until 8) b[off + i] = (v ushr ((7 - i) * 8)).toByte()
    }

    private fun putBe32(b: ByteArray, off: Int, v: Long) {
        for (i in 0 until 4) b[off + i] = (v ushr ((3 - i) * 8)).toByte()
    }

    fun be64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
        return v
    }

    // ---- X25519 ----

    class KeyPair(val priv: ByteArray, val pub: ByteArray)

    fun generatePair(): KeyPair {
        val priv = ByteArray(KEY_SIZE).also { rnd.nextBytes(it) }
        return KeyPair(priv, publicKey(priv))
    }

    fun publicKey(priv: ByteArray): ByteArray =
        X25519PrivateKeyParameters(priv, 0).generatePublicKey().encoded

    fun dh(priv: ByteArray, peerPub: ByteArray): ByteArray {
        val agree = X25519Agreement()
        agree.init(X25519PrivateKeyParameters(priv, 0))
        val out = ByteArray(KEY_SIZE)
        agree.calculateAgreement(X25519PublicKeyParameters(peerPub, 0), out, 0)
        return out
    }

    // ---- ChaCha20-Poly1305 (nonce [4 нуля][counter LE64]) ----

    private fun nonce96(counter: Long): ByteArray {
        val n = ByteArray(12)
        for (i in 0 until 8) n[4 + i] = (counter ushr (i * 8)).toByte() // LE
        return n
    }

    fun seal(key: ByteArray, counter: Long, aad: ByteArray?, plain: ByteArray): ByteArray {
        val c = ChaCha20Poly1305()
        c.init(true, AEADParameters(KeyParameter(key), 128, nonce96(counter), aad))
        val out = ByteArray(plain.size + 16)
        var len = c.processBytes(plain, 0, plain.size, out, 0)
        len += c.doFinal(out, len)
        return if (len == out.size) out else out.copyOf(len)
    }

    fun open(key: ByteArray, counter: Long, aad: ByteArray?, box: ByteArray): ByteArray {
        val c = ChaCha20Poly1305()
        c.init(false, AEADParameters(KeyParameter(key), 128, nonce96(counter), aad))
        val out = ByteArray(box.size)
        var len = c.processBytes(box, 0, box.size, out, 0)
        len += c.doFinal(out, len)
        return if (len == out.size) out else out.copyOf(len)
    }

    /** PSK хендшейка WG = SHA256(token) — наш ключ доверия (зеркало сервера). */
    fun tokenPsk(token: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.UTF_8))

    // ---- хендшейк: инициатор (клиент) ----

    class ClientHandshake internal constructor(
        val eph: KeyPair,
        val static: KeyPair,
        val sender: Long,
        val stamp: ByteArray,
    ) {
        var chainKey: ByteArray = ByteArray(KEY_SIZE)
        var hash: ByteArray = ByteArray(KEY_SIZE)
        var sendKey: ByteArray = ByteArray(KEY_SIZE) // клиент → сервер
        var recvKey: ByteArray = ByteArray(KEY_SIZE) // сервер → клиент
        var recvIdx: Long = 0

        /**
         * Обработка msg2 (92 Б) инициатором; после успеха активны ключи.
         * Бросает WgException при битом ответе.
         */
        fun consumeResponse(msg2: ByteArray, psk: ByteArray) {
            if (msg2.size != MSG_RESP_SIZE) throw WgException(Msgs.WG_MSG2_LEN.t(msg2.size, MSG_RESP_SIZE))
            if (le32(msg2, 0) != 2L) throw WgException(Msgs.WG_MSG2_TYPE.t())
            if (le32(msg2, 8) != sender) throw WgException(Msgs.WG_MSG2_RECEIVER.t())
            recvIdx = le32(msg2, 4)
            val mk = macKeyMac1(static.pub)
            val want = mac1(mk, msg2.copyOfRange(0, 60))
            if (!want.contentEquals(msg2.copyOfRange(60, 76))) {
                throw WgException(Msgs.WG_MSG2_MAC1.t())
            }
            hash = hash2(hash, msg2.copyOfRange(12, 44))
            val dhER = dh(static.priv, msg2.copyOfRange(12, 44))
            val (k, _, newCk) = kdf2(chainKey, dhER)
            chainKey = newCk
            try {
                open(k, 0, hash, msg2.copyOfRange(44, 60))
            } catch (e: Exception) {
                throw WgException("msg2 empty AEAD: ${e.message}")
            }
            hash = hash2(hash, msg2.copyOfRange(44, 60))
            val (t0, t1, _) = kdf3(chainKey, psk)
            sendKey = t0
            recvKey = t1
        }
    }

    class WgException(message: String) : Exception(message)

    /**
     * Построение msg1 (148 Б, wire-формат WG). serverPub — WG static
     * сервера из KEY_REQ; psk = SHA256(token). Параметры injectable —
     * для межъязыкового KAT (детерминированные векторы).
     */
    fun newClientHandshake(
        serverPub: ByteArray,
        psk: ByteArray,
        injectClientStatic: KeyPair? = null,
        injectEph: KeyPair? = null,
        injectSender: Long? = null,
        injectStamp: ByteArray? = null,
    ): Pair<ByteArray, ClientHandshake> {
        val ch = ClientHandshake(
            eph = injectEph ?: generatePair(),
            static = injectClientStatic ?: generatePair(),
            sender = injectSender ?: le32(ByteArray(4).also { rnd.nextBytes(it) }, 0),
            stamp = injectStamp ?: tai64n(),
        )
        ch.chainKey = blake2sOf(CONSTRUCTION.toByteArray(Charsets.US_ASCII))
        ch.hash = hash2(ch.chainKey, IDENTIFIER.toByteArray(Charsets.US_ASCII))

        val msg = ByteArray(MSG_INIT_SIZE)
        putLe32(msg, 0, 1)
        putLe32(msg, 4, ch.sender)
        ch.eph.pub.copyInto(msg, 8)
        ch.hash = hash2(ch.hash, ch.eph.pub)

        val dhES = dh(ch.eph.priv, serverPub)
        val (key, _, newCk) = kdf2(ch.chainKey, dhES)
        ch.chainKey = newCk
        ch.chainKey = newCk
        val staticBox = seal(key, 0, ch.hash, ch.static.pub)
        staticBox.copyInto(msg, 40)
        ch.hash = hash2(ch.hash, msg.copyOfRange(40, 88))

        val dhSS = dh(ch.static.priv, serverPub)
        val (key2, _, newCk2) = kdf2(ch.chainKey, dhSS)
        ch.chainKey = newCk2
        ch.chainKey = newCk2
        val stampBox = seal(key2, 0, ch.hash, ch.stamp)
        stampBox.copyInto(msg, 88)
        ch.hash = hash2(ch.hash, msg.copyOfRange(88, 116))

        val mk = macKeyMac1(serverPub)
        mac1(mk, msg.copyOfRange(0, 116)).copyInto(msg, 116)
        return msg to ch
    }

    // ---- transport (канон WG, type=4) ----

    /**
     * Транспортные конверты WG после хендшейка. Крипта обеих направлений
     * + sliding-window анти-реплей (2048) на приёме.
     */
    class Transport(
        private val sendKey: ByteArray,
        private val recvKey: ByteArray,
        private val sendIdx: Long, // наш sender_index
        private val recvIdx: Long, // sender_index пира
    ) {
        private val sendCtr = AtomicLong(0)
        private val window = ReplayWindow()

        /** Открытые данные → WG-пакет (type=4). */
        fun seal(plain: ByteArray): ByteArray {
            val ctr = sendCtr.incrementAndGet() - 1
            if (ctr >= (1L shl 60)) throw WgException(Msgs.WG_COUNTER.t())
            val pkt = ByteArray(16 + plain.size + 16)
            putLe32(pkt, 0, 4)
            putLe32(pkt, 4, recvIdx)
            for (i in 0 until 8) pkt[8 + i] = (ctr ushr (i * 8)).toByte()
            val box = sealKeyed(sendKey, ctr, plain)
            box.copyInto(pkt, 16)
            return pkt
        }

        /** WG-пакет → открытые данные (анти-реплей). */
        fun open(pkt: ByteArray): ByteArray {
            if (pkt.size < 16 + 16) throw WgException(Msgs.WG_PACKET_SHORT.t())
            if (le32(pkt, 0) != 4L) throw WgException(Msgs.WG_PACKET_TYPE.t())
            val ctr = le64(pkt, 8)
            if (!window.check(ctr)) throw WgException(Msgs.WG_REPLAY.t())
            return try {
                openKeyed(recvKey, ctr, pkt.copyOfRange(16, pkt.size))
            } catch (e: Exception) {
                window.rollback(ctr)
                throw WgException("AEAD: ${e.message}")
            }
        }

        private fun sealKeyed(key: ByteArray, ctr: Long, plain: ByteArray) = seal(key, ctr, null, plain)
        private fun openKeyed(key: ByteArray, ctr: Long, box: ByteArray) = open(key, ctr, null, box)
    }

    /** Строит клиентский транспорт из хендшейка. */
    fun clientTransport(ch: ClientHandshake): Transport = Transport(ch.sendKey, ch.recvKey, ch.sender, ch.recvIdx)

    // ---- sliding window (канон WG §5.4.7) ----

    class ReplayWindow {
        private var base: Long = 0
        private val bitmap = LongArray(REPLAY_WINDOW / 64)

        fun check(ctr: Long): Boolean {
            if (ctr < base) return false
            if (ctr >= base + REPLAY_WINDOW) {
                val shift = ctr - base - REPLAY_WINDOW + 1
                advance(shift)
                set(ctr)
                return true
            }
            val bit = ctr - base
            val word = (bit / 64).toInt()
            val mask = 1L shl (bit % 64).toInt()
            if (bitmap[word] and mask != 0L) return false
            bitmap[word] = bitmap[word] or mask
            return true
        }

        fun rollback(ctr: Long) {
            if (ctr < base) return
            val bit = ctr - base
            if (bit >= REPLAY_WINDOW) return
            val word = (bit / 64).toInt()
            val mask = 1L shl (bit % 64).toInt()
            bitmap[word] = bitmap[word] and mask.inv()
        }

        private fun set(ctr: Long) {
            val bit = ctr - base
            val word = (bit / 64).toInt()
            val mask = 1L shl (bit % 64).toInt()
            bitmap[word] = bitmap[word] or mask
        }

        private fun advance(shift: Long) {
            if (shift >= REPLAY_WINDOW) {
                java.util.Arrays.fill(bitmap, 0)
                base += shift
                return
            }
            val wIdx = (shift / 64).toInt()
            val bShift = (shift % 64).toInt()
            val newBitmap = LongArray(bitmap.size)
            for (i in bitmap.indices) {
                val src = i + wIdx
                if (src < bitmap.size) {
                    newBitmap[i] = bitmap[src] ushr bShift
                    if (bShift > 0 && src + 1 < bitmap.size) {
                        newBitmap[i] = newBitmap[i] or (bitmap[src + 1] shl (64 - bShift))
                    }
                }
            }
            System.arraycopy(newBitmap, 0, bitmap, 0, bitmap.size)
            base += shift
        }
    }

    // ---- little-endian helpers ----

    fun putLe32(b: ByteArray, off: Int, v: Long) {
        for (i in 0 until 4) b[off + i] = (v ushr (i * 8)).toByte()
    }

    fun le32(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = v or ((b[off + i].toLong() and 0xFF) shl (i * 8))
        return v
    }

    fun le64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[off + i].toLong() and 0xFF) shl (i * 8))
        return v
    }
}

private fun blake2sOf(input: ByteArray): ByteArray {
    val h = Blake2sDigest(256)
    h.update(input, 0, input.size)
    val out = ByteArray(32)
    h.doFinal(out, 0)
    return out
}
