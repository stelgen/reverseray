// v1.8.0: зона режима «Ротация» вынесена из TunnelService.kt (дробление по
// зонам ответственности). Pure refactor: private → internal у задетых членов,
// поведение не меняется. Тот же пакет — вызовы из TunnelService без импортов.
package dev.stelgen.reverseray.service

import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.ProtoRotator
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpProtocols

internal fun TunnelService.rotationEnabled(): Boolean = prefs().getBoolean(TunnelService.KEY_PROTO_ROTATE, false)

/**
 * Тик ротации: расписание ([ProtoRotator]) → бесшовная смена (0x2C)
 * + запись причины в журнал. Кандидаты — executable ∩ реестру сервера;
 * строго следующий после текущего. Провал смены НЕ карается памятью
 * провалов (это не авто) — следующий тик попробует снова по расписанию.
 */
internal fun TunnelService.rotateTick() {
    if (stopping || !rotationEnabled()) return
    val now = System.currentTimeMillis()
    for (s in sessById.values.toList()) {
        val client = firstClientOf(s) ?: continue
        if (client.state != RrpClient.State.READY) continue
        val candidates = RrpProtocols.EXECUTABLE.filter {
            it != RrpProtocols.DEFAULT && client.serverProtocols.contains(it)
        }
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
        switchProtoLiveOf(s, target)
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
