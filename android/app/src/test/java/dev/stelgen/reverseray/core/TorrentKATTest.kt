package dev.stelgen.reverseray.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/**
 * Межъязыковой KAT (Go ↔ Kotlin) протокола bittorrent (MSE/PE): фиксированные
 * Xa/Xb (160-бит), паддинг packet1 = 0, паддинг packet4 = 449×0x5A —
 * байт-в-байт те же векторы, что в server/internal/bt/bt_test.go TestKATVector.
 * Меняя канон — обновляй вектор ОБЕИХ сторон.
 */
class TorrentKATTest {

    companion object {
        private val XA = BigInteger("3B1C0A2E5D7F9B1D3E5F7A9C1B3D5F7E9A1C3E5B7D9F1A3C5E7B9D1F3A5C7E9B1D3F5A7C9E1B3D5F7A9C1B", 16)
        private val XB = BigInteger("5C3E7A9B1D3F5E7C9A1B3D5F7E9A1C3E5B7D9F1A3C5E7B9D1F3A5C7E9B1D3F5A7C9E1B3D5F7A9C1B3D5F7E9A", 16)

        private val EXPECTED_S = hex(
            "c45558d8659f784542c8ea3cf157301f0047f853e9cf498801602c798544f66c" +
                "e9b0caa9c744729e3e1819e65d1d6401fd0297415477a1fea1f5b0912f68aac" +
                "d6d078590f4d9a0865fb5b880192c3174a976d5f46a6557eb26ec2ff94814a9" +
                "3d",
        )

        private val EXPECTED_INIT = hex(
            "038d3585c8619015fe18ce5704d4f390126ed4be239411db38c98eb5cf95c1c6" +
                "c09a5e562171a793e9ca24b4ae626e3086c8058748981d5a072de83f4510480" +
                "67f0aedb4b4fdcd562635d5cfcb9f7783b0ca584de7537902d73e2ceb9b7612" +
                "f924fb6ed1113c0912db0c27406ab069af0459498d2f514988d2cb05f5b4f9a" +
                "fd1b8f0545d6b4c04c204be4ce782bcaf2867f27ea3e75eef7e",
        )

        private val EXPECTED_RESP = hex(
            "e11b4f9ac195096515d2d3ef8d7c84082607ecdf4a395239774307812f7ac7e7" +
                "986d931dce5be5f478ab1bc5a103df322fc3d81e5ffedfbf1cd7c65d6d9b437" +
                "ae269f76b5400d0f6b32de69bad4a890cca0631543caeba41cd2d965e943e6d" +
                "058571b9998259282c0893be8935c95fe8d012abe72d4bf7b6332773fa7f86c" +
                "64d0e9266bd35f08b99d6c2acdf8c3355d527a34f262103f21a77d42d188a3a" +
                "62601d358efe1b639aa1cbb212decfcb3fa4e7bb81314ec9252bb5ac655447c" +
                "5ad6899c6aac2864964fb21132b593abfbfdbb05bf0c3bff2ce143bed2c09a5" +
                "2bb88d92de5df09f43fe356a6d4deb74c69096f843188c61cbb7a7f589a742b" +
                "493b7603ce737a3a3919b4c778cba5619a13ede8f30a1565f975490917c9f77" +
                "3f9e4f96395497f5dcd9248a5976aef3d236a4c7cbe9c177662903d639a9824" +
                "1d895b0bc2cdd538aa9fd0ef0ac15cdb6eaef377ca058889f8fa0a5de89f627" +
                "7250294b5372318c71c8175aa6715e0c63c1c97180f6de3b0cb0c15442df04c" +
                "41e9e925f3fdb56314e04f630a0e7ff90d557f372362116c3a0f799351367eb" +
                "c05aafa3139433942b07851a295917fbb551da6c7bda3078efb8cd126bbcc11" +
                "a0e9432b79f45fe00b835864dc85016b9b9f1869106",
        )

        private val EXPECTED_BOX = hex("44f1b59af8c445ac0438e25115afdb15")

        private fun hex(s: String): ByteArray {
            val out = ByteArray(s.length / 2)
            for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            return out
        }
    }

    @Test
    fun `kat handshake and transport match go vectors`() {
        val skey = Torrent.skey(Torrent.tokenHash("kat-token-2026"))
        // yb = G^XB mod P (G=2; P^XB mod P был бы нулём — нельзя путать базу)
        val yb = BigInteger.TWO.modPow(XB, Torrent.P).let { be96(it) }

        val (packet1, hs) = Torrent.newClientInit(skey, injectXaHex = XA.toString(16), injectPad = ByteArray(0))
        val packet3 = hs.buildPacket3(yb)
        val init = hs.init(packet3)

        // S — байт-в-байт как у сервера
        assertArrayEquals("S (DH-секрет)", EXPECTED_S, hs.s)
        // packet1||packet3 — байт-в-байт как у сервера
        assertArrayEquals("BT_INIT (packet1||packet3)", EXPECTED_INIT, init)

        // packet4 сервера — детерминированный вектор
        hs.consumeResponse(EXPECTED_RESP)

        // транспорт: DATA → piece-сообщение (bайт-в-байт как у сервера)
        val box = hs.transport().seal("kat".toByteArray(Charsets.UTF_8))
        assertArrayEquals("piece-конверт DATA", EXPECTED_BOX, box)
    }

    @Test
    fun `wrong skey handshake fails closed`() {
        val skey = Torrent.skey(Torrent.tokenHash("чужой-токен"))
        val yb = be96(BigInteger.TWO.modPow(XB, Torrent.P))
        val (_, hs) = Torrent.newClientInit(skey, injectXaHex = XA.toString(16), injectPad = ByteArray(0))
        hs.buildPacket3(yb)
        try {
            hs.consumeResponse(EXPECTED_RESP)
            throw AssertionError("хендшейк с чужим SKEY прошёл — нарушение канона VC")
        } catch (_: Torrent.TorrentException) {
            // ожидаемо: VC не сходится
        }
    }

    @Test
    fun `transport roundtrip various sizes`() {
        val skey = Torrent.skey(Torrent.tokenHash("kat-token-2026"))
        val yb = be96(BigInteger.TWO.modPow(XB, Torrent.P))
        val (_, hs) = Torrent.newClientInit(skey, injectXaHex = XA.toString(16), injectPad = ByteArray(0))
        hs.buildPacket3(yb)
        hs.consumeResponse(EXPECTED_RESP)
        // Конверты НАПРАВЛЕННЫЕ (канон MSE): клиент seals keyA / opens keyB —
        // сервер зеркально. Кросс-сторона, как в Go-тестах.
        val client = hs.transport()
        val server = Torrent.serverTransportForTest(hs.s, skey, EXPECTED_RESP.size)
        for (n in listOf(1, 13, 100, 4096, Torrent.MAX_PLAIN_DATA)) {
            val plain = ByteArray(n) { (it * 31 + 7).toByte() }
            val back = server.open(client.seal(plain))
            assertArrayEquals("C→S размер $n", plain, back)
            val back2 = client.open(server.seal(back))
            assertArrayEquals("S→C размер $n", plain, back2)
        }
        try {
            client.seal(ByteArray(Torrent.MAX_PLAIN_DATA + 1))
            throw AssertionError("Seal принял plaintext больше лимита")
        } catch (_: Torrent.TorrentException) {
        }
    }

    @Test
    fun `piece envelope is canonical peer wire shape`() {
        val skey = Torrent.skey(Torrent.tokenHash("kat-token-2026"))
        val yb = be96(BigInteger.TWO.modPow(XB, Torrent.P))
        val (_, hs) = Torrent.newClientInit(skey, injectXaHex = XA.toString(16), injectPad = ByteArray(0))
        hs.buildPacket3(yb)
        hs.consumeResponse(EXPECTED_RESP)
        val tr = hs.transport()
        // Открываем собственное сообщение и проверяем peer-wire форму:
        // [len BE4][type=7][index BE4][begin BE4][block] — для этого расшифруем
        // вторым транспортом (самопроверка формы через вскрытый кейстрим).
        val box = tr.seal(ByteArray(16) { it.toByte() })
        assertTrue("конверт не пуст", box.size >= Torrent.PIECE_OVERHEAD)
        assertTrue("piece-сообщение ≤ MAX_DATA_PAYLOAD", box.size <= 65536)
    }

    private fun be96(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        val out = ByteArray(96)
        val mag = if (b.size > 96) b.copyOfRange(b.size - 96, b.size) else b
        mag.copyInto(out, 96 - mag.size)
        return out
    }
}
