package dev.stelgen.reverseray.core

import org.bouncycastle.crypto.engines.RC4Engine
import org.bouncycastle.crypto.params.KeyParameter
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * BitTorrent MSE/PE-крипто для протокола туннеля bittorrent (v0.10, зеркало
 * server/internal/bt): канон Message Stream Encryption / Protocol Encryption —
 * тот самый профиль, что у реальных клиентов (libtorrent/qBittorrent/Deluge):
 *
 *  - DH 768-битная группа (RFC 2409 group 1), G = 2, приватный 160 бит;
 *  - SKEY = SHA1("reverseray-bt:" + SHA256(token)) — «инфо-хеш торрента»;
 *  - packet1 = Ya(96Б)+pad, packet3 = req1 + req2⊕req3 + RC4(VC+provide+...);
 *  - packet4 = RC4(VC+select+len(PadD)+PadD), VC = 8 нулей;
 *  - RC4-ключи: SHA1("keyA"+S+SKEY) / SHA1("keyB"+S+SKEY), drop 1024;
 *  - транспорт: peer-wire piece-сообщения [len BE4][type 7][index][begin][block].
 *
 * Клиент — MSE-инициатор (A); Yb сервера приходит кадром KEY_REQ
 * ({"kind":"bittorrent","yb":…}) после READY. Хендшейк внутри приватного
 * канала (TLS 1.3 + SPKI-pin) — для DPI payload'ы выглядят как BitTorrent.
 * Pure BC (RC4Engine/SHA-1/BigInteger) — Android 4+.
 */
object Torrent {

    const val PROTO_ID = "bittorrent"

    // ---- канон MSE ----
    const val KEY_SIZE = 96          // Ya/Yb/S — 96 байт BE (768 бит)
    const val VC_LEN = 8             // verification constant
    const val KEY_DROP = 1024        // RC4-drop1024 (канон)
    const val CRYPTO_PLAIN = 0x01L
    const val CRYPTO_RC4 = 0x02L
    const val PAD_MIN = 16
    const val PAD_MAX = 512
    const val MSG_PIECE = 0x07
    const val PIECE_OVERHEAD = 4 + 1 + 4 + 4 // len + type + index + begin
    const val BLOCK_LEN = 0x4000     // канонный блок 16 KiB
    const val PIECE_LEN = 128 * BLOCK_LEN

    /** Максимум ОТКРЫТОГО чанка в BT-конверте (зеркало Go). */
    const val MAX_PLAIN_DATA = 65536 - PIECE_OVERHEAD

    /** Канонное простое MSE (RFC 2409 group 1; C23B — канон libtorrent). */
    val P: BigInteger = BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C23BC4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A63A36210000000000090563",
        16,
    )
    private val G = BigInteger.TWO

    private val rnd = SecureRandom()

    private fun sha1(vararg parts: ByteArray): ByteArray {
        val h = MessageDigest.getInstance("SHA-1")
        for (p in parts) h.update(p)
        return h.digest()
    }

    /** SKEY — «инфо-хеш торрента»: SHA1("reverseray-bt:" + tokenHash). */
    fun skey(tokenHash: ByteArray): ByteArray =
        sha1(skeyLabel.toByteArray(Charsets.US_ASCII), tokenHash)

    private const val skeyLabel = "reverseray-bt:"

    /** PSK клиента = SHA256(token) (зеркало TokenHash сервера). */
    fun tokenHash(token: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.UTF_8))

    // ---- RC4 с канонным drop ----

    private class Rc4Stream(key: ByteArray, drop: Int) {
        private val enc = RC4Engine()
        private val dec = RC4Engine()

        init {
            enc.init(true, KeyParameter(key))
            dec.init(false, KeyParameter(key))
            if (drop > 0) {
                val sink = ByteArray(drop)
                xorEnc(sink, sink)
                xorDec(sink, sink)
            }
        }

        fun xorEnc(dst: ByteArray, src: ByteArray) {
            enc.processBytes(src, 0, src.size, dst, 0)
        }

        fun xorDec(dst: ByteArray, src: ByteArray) {
            dec.processBytes(src, 0, src.size, dst, 0)
        }
    }

    private fun rc4Key(label: String, s: ByteArray, skey: ByteArray): ByteArray =
        sha1(label.toByteArray(Charsets.US_ASCII) + s + skey)

    private fun be96(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        val out = ByteArray(KEY_SIZE)
        // toByteArray может дать ведущий 0 — снимаем
        val mag = if (b.size > KEY_SIZE) b.copyOfRange(b.size - KEY_SIZE, b.size) else b
        mag.copyInto(out, KEY_SIZE - mag.size)
        return out
    }

    // ---- хендшейк: инициатор (клиент) ----

    class ClientHandshake internal constructor(
        val xa: BigInteger,
        val ya: ByteArray,
        val pad1: ByteArray,
        val skey: ByteArray,
    ) {
        var s: ByteArray = ByteArray(KEY_SIZE) // DH-секрет (после Yb)
            internal set
        internal var out: Rc4Stream? = null // keyA: клиент → сервер
        internal var inR: Rc4Stream? = null // keyB: сервер → клиент
        internal var consumed = false

        /**
         * packet3 = req1(20) + req2⊕req3(20) + RC4(keyA)(VC8 + provide4 +
         * len(PadC)2 + PadC(0) + len(IA)2 + IA(0)). Вызывается после KEY_REQ.
         */
        fun buildPacket3(yb: ByteArray): ByteArray {
            check(out == null) { "bt: packet3 already built" }
            require(yb.size == KEY_SIZE) { "bt: Yb len ${yb.size} != $KEY_SIZE" }
            val peerY = BigInteger(1, yb)
            s = be96(peerY.modPow(xa, P))
            val keyA = rc4Key("keyA", s, skey)
            val keyB = rc4Key("keyB", s, skey)
            out = Rc4Stream(keyA, KEY_DROP)
            inR = Rc4Stream(keyB, KEY_DROP)

            val req1 = sha1("req1".toByteArray(Charsets.US_ASCII), s)
            val req2 = sha1("req2".toByteArray(Charsets.US_ASCII), skey)
            val req3 = sha1("req3".toByteArray(Charsets.US_ASCII), s)
            val x = ByteArray(20) { i -> (req2[i].toInt() xor req3[i].toInt()).toByte() }

            val plain = ByteArray(VC_LEN + 4 + 2 + 2)
            val prov = ByteArray(4)
            var v = CRYPTO_RC4
            for (i in 0 until 4) {
                prov[3 - i] = (v and 0xFF).toByte()
                v = v shr 8
            }
            prov.copyInto(plain, VC_LEN) // crypto_provide = RC4
            // len(PadC)=0, len(IA)=0 — уже нули

            val enc = ByteArray(plain.size)
            out!!.xorEnc(enc, plain)
            return req1 + x + enc
        }

        /** Канонная конкатенация packet1||packet3 — payload кадра BT_INIT. */
        fun init(packet3: ByteArray): ByteArray = ya + pad1 + packet3

        /**
         * Обработка packet4 (BT_RESP): RC4(keyB) открыть VC(8 нулей) +
         * crypto_select(4) + len(PadD)(2) + PadD. После успеха транспорт активен.
         */
        fun consumeResponse(resp: ByteArray) {
            val stream = inR ?: throw TorrentException("bt: packet3 не строился")
            check(!consumed) { "bt: packet4 уже обработан" }
            val minLen = VC_LEN + 4 + 2
            if (resp.size < minLen) {
                throw TorrentException("bt: packet4 len ${resp.size} < $minLen")
            }
            val dec = ByteArray(resp.size)
            stream.xorDec(dec, resp)
            for (i in 0 until VC_LEN) {
                if (dec[i].toInt() != 0) throw TorrentException("bt: VC mismatch")
            }
            var sel = 0L
            for (i in 0 until 4) sel = (sel shl 8) or (dec[VC_LEN + i].toLong() and 0xFF)
            if (sel != CRYPTO_RC4) throw TorrentException("bt: crypto_select=0x${sel.toString(16)}")
            val padD = ((dec[VC_LEN + 4].toInt() and 0xFF) shl 8) or (dec[VC_LEN + 5].toInt() and 0xFF)
            if (VC_LEN + 6 + padD > dec.size) throw TorrentException("bt: PadD overflow")
            consumed = true
        }

        /** Транспорт после успешного consumeResponse. */
        fun transport(): Transport {
            val o = out ?: throw TorrentException("bt: хендшейк не завершён")
            val i = inR ?: throw TorrentException("bt: хендшейк не завершён")
            return Transport(o, i)
        }
    }

    class TorrentException(message: String) : Exception(message)

    /**
     * packet1 = Ya(96Б BE) + pad(rand 16..512). xaHex/padInject — для KAT
     * (детерминированные векторы); в проде null.
     */
    fun newClientInit(
        skey: ByteArray,
        injectXaHex: String? = null,
        injectPad: ByteArray? = null,
    ): Pair<ByteArray, ClientHandshake> {
        val xa = if (injectXaHex != null) BigInteger(injectXaHex, 16) else {
            var x: BigInteger
            do {
                val b = ByteArray(20)
                rnd.nextBytes(b)
                x = BigInteger(1, b)
            } while (x.signum() == 0)
            x
        }
        val ya = be96(G.modPow(xa, P))
        val pad = injectPad ?: ByteArray(PAD_MIN + rnd.nextInt(PAD_MAX - PAD_MIN + 1)).also { rnd.nextBytes(it) }
        return (ya + pad) to ClientHandshake(xa, ya, pad, skey)
    }

    // ---- транспорт (канон peer-wire, piece type=7) ----

    /**
     * Конверты MSE после хендшейка: каждое DATA/UDP_DATA-сообщение — полный
     * peer-wire пакет [len BE4][type 7][index BE4][begin BE4][block], весь
     * пакет (включая length-префикс) шифруется продолжением RC4-кейстрима
     * хендшейка (канон MSE: кейстрим не реинициализируется).
     */
    class Transport(private val outS: Rc4Stream, private val inS: Rc4Stream) {
        private val ctr = AtomicLong(0)

        /** Открытые данные → зашифрованное piece-сообщение. */
        fun seal(plain: ByteArray): ByteArray {
            if (plain.size > MAX_PLAIN_DATA) {
                throw TorrentException("bt: plain ${plain.size} > $MAX_PLAIN_DATA")
            }
            val c = ctr.getAndIncrement()
            val msg = ByteArray(PIECE_OVERHEAD + plain.size)
            putBe32(msg, 0, (msg.size).toLong())
            msg[4] = MSG_PIECE.toByte()
            val idx = c / (PIECE_LEN / BLOCK_LEN)
            val begin = (c % (PIECE_LEN / BLOCK_LEN)) * BLOCK_LEN
            putBe32(msg, 5, idx)
            putBe32(msg, 9, begin)
            plain.copyInto(msg, PIECE_OVERHEAD)
            val box = ByteArray(msg.size)
            outS.xorEnc(box, msg)
            return box
        }

        /** piece-сообщение → открытые данные (проверка канонной формы). */
        fun open(box: ByteArray): ByteArray {
            if (box.size < PIECE_OVERHEAD) {
                throw TorrentException("bt: len ${box.size} < $PIECE_OVERHEAD")
            }
            val msg = ByteArray(box.size)
            inS.xorDec(msg, box)
            val ml = be32(msg, 0)
            if (ml != box.size.toLong()) {
                throw TorrentException("bt: msg len $ml != frame ${box.size}")
            }
            if (msg[4].toInt() and 0xFF != MSG_PIECE) {
                throw TorrentException("bt: msg type 0x${(msg[4].toInt() and 0xFF).toString(16)}")
            }
            return msg.copyOfRange(PIECE_OVERHEAD, msg.size)
        }
    }

    // ---- big-endian helpers ----

    private fun putBe32(b: ByteArray, off: Int, v: Long) {
        for (i in 0 until 4) b[off + i] = (v ushr ((3 - i) * 8)).toByte()
    }

    private fun be32(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
        return v
    }
}
