// RrpWg.kt — зона «WireGuard Noise-IK (v0.9.5)» (pure move из RrpClient.kt, v1.8.3: дробление по зонам ответственности;
// поведение не меняется, члены private→internal — тот же пакет).
package dev.stelgen.reverseray.core

/**
 * WG-хендшейк (v0.9.5): KEY_REQ несёт WG static public сервера
 * ({"kind":"wireguard","spub":…}). Клиент — WG-инициатор: строит
 * НАСТОЯЩИЙ msg1 (Noise_IKpsk2, PSK = SHA256(token)), шлёт WG_INIT.
 *
 * v0.9.6: БЕЗ ожидания WG_RESP на reader-потоке (self-deadlock —
 * WG_RESP придёт через тот же поток; см. dispatch → finishWgHandshake).
 */
internal fun RrpClient.handleWgKeyReq(frame: RrpFrame.KeyReq) {
    try {
        val serverPub = MtProto.b64urlDecode(frame.sPub)
        if (serverPub.size != Wg.KEY_SIZE) {
            throw Wg.WgException(Msgs.WG_BAD_SPUB.t(frame.sPub.length))
        }
        val psk = Wg.tokenPsk(token)
        val (msg1, hs) = Wg.newClientHandshake(serverPub, psk)
        log(Msgs.WG_INIT_SENT.t(Wg.MSG_INIT_SIZE))
        wgHandshake = hs
        wgPsk = psk
        sendFrame(RrpFrame.WgInit(msg1))
    } catch (e: Exception) {
        // ридер умирает честной причиной (серверный key-timer параллельно закроет сессию)
        throw RrpClientException(Msgs.WG_FAILED.t(e.message ?: "?"), e)
    }
}

/**
 * v0.9.6: WG_RESP (msg2) — финал WG-хендшейка. Вызывается из dispatch
 * (reader-поток): consumeResponse чисто локальный (без чтения кадров),
 * поэтому здесь deadlock невозможен по построению.
 */
internal fun RrpClient.finishWgHandshake(frame: RrpFrame.WgResp) {
    val hs = wgHandshake ?: run {
        log(Msgs.WG_INIT_UNEXPECTED.t())
        return
    }
    val psk = wgPsk
    try {
        hs.consumeResponse(frame.raw, psk ?: throw Wg.WgException(Msgs.WG_RESP_TIMEOUT.t()))
        // v1.8.4: атомарная подмена конверта — старые крипты гасим до снятия
        // паркинга (см. RrpMproto.handleKeyReq), свитч завершён.
        mtCrypto = null
        btCrypto = null
        wgCrypto = Wg.clientTransport(hs)
        wgHandshake = null
        wgPsk = null
        negotiatedProto = Wg.PROTO_ID // v1.8.4: финал свитча — актуальный протокол
        pendingSwitchTarget = null
        log(Msgs.WG_KEYS_AGREED.t())
        listener?.onState(this, RrpClient.State.READY) // UI: статус крипты
        unparkAndFlush() // v0.10: смена завершена — пропускаем паркованное
    } catch (e: Exception) {
        // битый msg2 — нарушение протокола: сессия закрыта честной причиной
        throw RrpClientException(Msgs.WG_FAILED.t(e.message ?: "?"), e)
    }
}
