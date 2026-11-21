// RrpMproto.kt — зона «MTProto/2 (v0.8)» (pure move из RrpClient.kt, v1.8.3: дробление по зонам ответственности;
// поведение не меняется, члены private→internal — тот же пакет).
package dev.stelgen.reverseray.core

/**
 * KEY_REQ от сервера (после READY при согласованном proto=mtproto2):
 * валидируем p (anti-logjam — обязан равняться каноническому dh_prime
 * Telegram) и g=3, проверяем g_a по канону guidelines, генерируем свою
 * долю, шлём KEY_RESP и включаем MTProto-конверт на DATA/UDP_DATA.
 */
internal fun RrpClient.handleKeyReq(frame: RrpFrame.KeyReq) {
    // v1.9.3: бесшовные свитчи 0x2C удалены — обмен ключами живёт ТОЛЬКО
    // при первичном подключении (крипта ещё пуста). Повторный KEY_REQ при
    // активной крипте — игнор (анти-мусор).
    if (mtCrypto != null || wgCrypto != null || btCrypto != null) {
        log(Msgs.KEY_REQ_IGNORED.t())
        return
    }
    if (frame.kind == Torrent.PROTO_ID) {
        handleBtKeyReq(frame)
        return
    }
    if (frame.kind.isNotBlank() && frame.kind != MtProto.PROTO_ID) {
        handleWgKeyReq(frame)
        return
    }
    try {
        val pBytes = MtProto.b64urlDecode(frame.p)
        if (!pBytes.contentEquals(MtProto.P.toByteArray().let { bytes ->
                // BigInteger.toByteArray() может дать 257 байт с ведущим 0
                if (bytes.size == 257) bytes.copyOfRange(1, 257) else bytes
            })
        ) {
            throw MtProto.MtProtoException(Msgs.DH_PRIME_MISMATCH.t())
        }
        if (frame.g != MtProto.G.toInt()) {
            throw MtProto.MtProtoException(Msgs.DH_G_UNEXPECTED.t(frame.g))
        }
        val gA = MtProto.publicFromBytes(MtProto.b64urlDecode(frame.gA))
        MtProto.validatePublic(gA)
        val dh = MtProto.ClientDh()
        dh.generatePrivate()
        val gB = MtProto.publicBytes(dh.public)
        val gABytes = MtProto.b64urlDecode(frame.gA)
        val authKey = dh.shared(gA)
        val sid = sessionId ?: throw MtProto.MtProtoException(Msgs.NO_SESSION_ID.t())
        // v1.8.4: атомарная подмена конверта — старые крипты гасим ДО ответа,
        // иначе первый DATA уйдёт старым конвертом после включения новой.
        wgCrypto = null
        btCrypto = null
        mtCrypto = MtProto.SessionCrypto(
            authKey,
            MtProto.saltFor(sid, gABytes, gB),
            MtProto.sessionId8(sid),
        )
        negotiatedProto = MtProto.PROTO_ID // актуальный протокол после поднятия крипты
        log(Msgs.MTPROTO_KEYS_OK.t())
        listener?.onState(this, RrpClient.State.READY) // уведомить UI о включении крипто
        sendFrame(RrpFrame.KeyResp(MtProto.b64url(gB)))
    } catch (e: Exception) {
        log(Msgs.MTPROTO_EXCHANGE_FAILED.t(e.message))
        close()
    }
}
