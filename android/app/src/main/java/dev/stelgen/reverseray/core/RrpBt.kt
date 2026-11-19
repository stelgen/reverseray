// RrpBt.kt — зона «BitTorrent MSE/PE (v0.10)» (pure move из RrpClient.kt, v1.8.3: дробление по зонам ответственности;
// поведение не меняется, члены private→internal — тот же пакет).
package dev.stelgen.reverseray.core

// ------------------------------------------------------------------ BitTorrent MSE/PE (v0.10)

/**
 * KEY_REQ(kind=bittorrent): MSE DH public сервера (Yb, 96 Б). Клиент —
 * инициатор MSE: packet1 = Ya+pad; packet3 = req1+req2⊕req3+RC4(keyA)(...);
 * шлём BT_INIT (packet1||packet3) БЕЗ ожидания — BT_RESP догревает dispatch
 * (тот же дедлок-фикс, что WG в v0.9.6).
 */
internal fun RrpClient.handleBtKeyReq(frame: RrpFrame.KeyReq) {
    try {
        val yb = MtProto.b64urlDecode(frame.yb)
        if (yb.size != Torrent.KEY_SIZE) {
            throw Torrent.TorrentException("bt: yb len ${yb.size} != ${Torrent.KEY_SIZE}")
        }
        val skey = Torrent.skey(Torrent.tokenHash(token))
        val (p1, hs) = Torrent.newClientInit(skey)
        val p3 = hs.buildPacket3(yb)
        log(Msgs.BT_INIT_SENT.t(p1.size, p3.size, Torrent.KEY_DROP))
        btHandshake = hs
        sendFrame(RrpFrame.BtInit(hs.init(p3)))
    } catch (e: Exception) {
        throw RrpClientException(Msgs.BT_FAILED.t(e.message ?: "?"), e)
    }
}

/** BT_RESP (packet4) — финал MSE-хендшейка: активируем BT-конверт. */
internal fun RrpClient.finishBtHandshake(frame: RrpFrame.BtResp) {
    val hs = btHandshake ?: run {
        log(Msgs.BT_RESP_IGNORED.t())
        return
    }
    try {
        hs.consumeResponse(frame.raw)
        btCrypto = hs.transport()
        btHandshake = null
        log(Msgs.BT_KEYS_AGREED.t())
        listener?.onState(this, RrpClient.State.READY) // UI: статус крипты
        unparkAndFlush() // v0.10: смена завершена — пропускаем паркованное
    } catch (e: Exception) {
        throw RrpClientException(Msgs.BT_FAILED.t(e.message ?: "?"), e)
    }
}
