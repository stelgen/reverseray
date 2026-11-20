// v1.8.10: зона «бесшовная смена протокола» вынесена из RrpClient.kt
// (дробление по зонам ответственности, атомы/молекулы). Pure refactor:
// private → internal у задетых членов, поведение не меняется.
// Тот же пакет — вызовы из RrpClient без импортов.
package dev.stelgen.reverseray.core

import dev.stelgen.reverseray.core.Msgs
import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.RrpFrame
import dev.stelgen.reverseray.core.RrpProtocols
import java.util.Locale

// ------------------------------------------------------------------ бесшовная смена протокола (v0.10)


/**
 * Бесшовная смена протокола в живой сессии (кадр 0x2C): просим сервер,
 * ждём ok, паркуем payload-кадры до завершения перехендшейка.
 * @return true — сервер согласился (крипта сменится после обмена ключами);
 *         false — отказ/таймаут (паркинг снят, старая крипта жива).
 */
fun RrpClient.switchProto(target: String): Boolean {
    if (state != RrpClient.State.READY) return false
    if (pendingSwitchTarget != null) return false // v1.8.4: свитч уже в полёте
    val nonce = ByteArray(8).also { rnd.nextBytes(it) }
        .joinToString("") { String.format(Locale.ROOT, "%02x", it) }
    protoSwitchNonce = nonce
    protoSwitchAck = null
    pendingSwitchTarget = target
    log(Msgs.PSW_REQUEST.t(RrpProtocols.labelWithVer(target), nonce))
    sendFrame(RrpFrame.ProtoSwitch(target, nonce))
    val deadline = System.currentTimeMillis() + 15_000
    while (System.currentTimeMillis() < deadline) {
        protoSwitchAck?.let { ack ->
            if (ack.nonce != nonce) return@let // чужой/старый ответ
            if (!ack.ok) {
                log(Msgs.PSW_DENIED.t(ack.reason.ifEmpty { "?" }), LogKind.WARN)
                pendingSwitchTarget = null
                return false
            }
            log(Msgs.PSW_GRANTED.t(RrpProtocols.labelWithVer(ack.proto)))
            parkForSwitch()
            return true
        }
        try { Thread.sleep(50) } catch (_: InterruptedException) { break }
    }
    log(Msgs.PSW_TIMEOUT.t(), LogKind.WARN)
    pendingSwitchTarget = null
    return false
}

/** Ответ сервера на наш 0x2C (или серверный запрос — не поддерживаем: клиент инициатор). */
internal fun RrpClient.handleProtoSwitchAck(frame: RrpFrame.ProtoSwitch) {
    protoSwitchAck = frame
    if (!frame.ok) {
        // отказ сервера — ничего не паркуем (парковки ещё нет)
        pendingSwitchTarget = null
    }
}

/** Паркинг payload-кадров на время перехендшейка (контрольные — свободно). */
internal fun RrpClient.parkForSwitch() {
    switchParking.park()
}

/** Снятие паркинга + отправка накопленных payload-кадров (уже новым конвертом).
 * v1.8.10: конверт сменился — последний исход E2E-пробника относится к
 * СТАРОМУ пути; обнуляем, чтобы балансер ждал свежего доказательства,
 * а не молотил свитчами по просроченному dead-вердикту. */
internal fun RrpClient.unparkAndFlush() {
    lastE2e = null
    val queued = switchParking.unpark()
    if (queued.isNotEmpty()) log(Msgs.PSW_FLUSHED.t(queued.size))
    for (f in queued) sendFrame(f)
}

