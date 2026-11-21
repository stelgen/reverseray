// v1.8.0: зона режима «Ротация» вынесена из TunnelService.kt (дробление по
// зонам ответственности). Тот же пакет — вызовы из TunnelService без импортов.
//
// v1.9.3: бесшовная смена протокола (0x2C) удалена. Смена = ОБЫЧНЫЙ
// РЕКОННЕКТ клиента на новом протоколе (killRunnersOf + spawnRunnersFor):
// без спец-кадров, без паркинга, без перехендшейков посреди сессии.
package dev.stelgen.reverseray.service

import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.ProtoRotator
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpProtocols

internal fun TunnelService.rotationEnabled(): Boolean = prefs().getBoolean(TunnelService.KEY_PROTO_ROTATE, false)

/**
 * Реконнект-смена протокола одной сессии (v1.9.3): цель кладётся в
 * [Sess.protoOverride] (ссылка НЕ мутируется — AUTO остаётся AUTO), раннеры
 * убиваются и поднимаются заново с новым proto. false — реконнект не запущен
 * (сервис останавливается).
 */
internal fun TunnelService.reconnectSwitchOf(sess: TunnelService.Sess, target: String): Boolean {
    sess.protoOverride = target
    return try {
        if (stopping) return false
        killRunnersOf(sess)
        spawnRunnersFor(sess)
        true
    } catch (_: Exception) {
        false
    }
}

/**
 * Ротация-тик: расписание ([ProtoRotator]) → обычный реконнект на следующий
 * протокол + запись причины в журнал. Кандидаты — ROTATABLE ∩ манифест
 * сервера (v1.9.7; манифест не пришёл — чисто локальный реестр, v1.9.4);
 * строго следующий после текущего. Провал реконнекта НЕ карается памятью
 * провалов (это не авто) — следующий тик попробует снова по расписанию.
 */
internal fun TunnelService.rotateTick() {
    if (stopping || !rotationEnabled()) return
    val now = System.currentTimeMillis()
    for (s in sessById.values.toList()) {
        // Ручная валидационная смена этой сессии — не вмешиваемся.
        if (s.id == switchingSessionId) continue
        val client = firstClientOf(s) ?: continue
        if (client.state != RrpClient.State.READY) continue
        // v1.9.7: кандидаты = ROTATABLE ∩ манифест сервера (client.serverProtocols
        // из HELLO_OK; известен для любого живого клиента). Цель вне манифеста
        // гарантированно провалила бы реконнект — красная ERROR-строка на
        // мониторе каждые 30 минут. Манифест не пришёл — локальный реестр
        // (v1.9.4). Ссылка НЕ мутируется.
        val known = client.serverProtocols
        val candidates = if (known.isEmpty()) RrpProtocols.ROTATABLE
            else RrpProtocols.ROTATABLE.filter { it in known }
        val rot = rotators.computeIfAbsent(s.id) { ProtoRotator() }
        val from = client.negotiatedProto
        val target = rot.onTick(now, from, candidates) ?: continue
        TunnelService.pushLog(
            getString(
                R.string.log_proto_rotation,
                RrpProtocols.labelWithVer(from),
                RrpProtocols.labelWithVer(target),
                TunnelService.ROTATE_INTERVAL_MS / 60_000,
            ),
            LogKind.INFO,
        )
        reconnectSwitchOf(s, target)
        manager?.byId(s.id)?.protoSwitches?.incrementAndGet()
    }
}

internal fun TunnelService.startRotateTick() {
    if (rotateTask != null) return
    rotateTask = try {
        rotateExecutor.scheduleWithFixedDelay(
            { try { rotateTick() } catch (_: Exception) {} },
            TunnelService.ROTATE_TICK_MS, TunnelService.ROTATE_TICK_MS, java.util.concurrent.TimeUnit.MILLISECONDS,
        )
    } catch (_: Exception) {
        null
    }
}

internal fun TunnelService.stopRotateTick() {
    rotateTask?.cancel(false)
    rotateTask = null
    rotators.clear()
}
