// v1.8.10: зона «здоровье линка» (PING-планировщик, PROBE/E2E-пробер,
// health-снимки для AutoBalancer) вынесена из RrpClient.kt — атомы/молекулы.
// Pure refactor: private → internal у задетых членов, поведение не меняется.
package dev.stelgen.reverseray.core

import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.Msgs
import java.io.IOException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

// ------------------------------------------------------------------ PING

internal fun RrpClient.scheduleNextPing() {
    if (!running.get()) return
    try {
        pingExecutor.schedule({
            if (!running.get()) return@schedule
            try {
                lastPingSentAt.set(System.currentTimeMillis())
                sendFrame(RrpFrame.Ping(ByteArray(RrpClient.NONCE_SIZE).also { rnd.nextBytes(it) }))
            } catch (e: IOException) {
                log(Msgs.PING_SEND_FAILED.t(e.message), LogKind.WARN)
            }
            scheduleNextPing()
        }, RrpClient.pingIntervalMs(rnd, lastRttMs.get()), TimeUnit.MILLISECONDS)
    } catch (_: RejectedExecutionException) {
    }
}

// ------------------------------------------------------------------ prober (v0.10)

internal fun RrpClient.recordPingResult(ok: Boolean) {
    synchronized(pingResults) {
        pingResults.addLast(System.currentTimeMillis() to ok)
        val horizon = System.currentTimeMillis() - RrpClient.HEALTH_WINDOW_MS
        while (pingResults.isNotEmpty() && pingResults.first().first < horizon) pingResults.removeFirst()
    }
}

/**
 * Пробник качества — «тестирование скважности, соединения постоянно»:
 * тик каждые 5с (потери по unanswered PING), PROBE каждые 30с (реальный
 * egress до реального хоста). Данные НЕ рвут сессию и НЕ меняют протокол
 * сами — решение (с гистерезисом/кулдауном) принимает AutoBalancer.
 */
internal fun RrpClient.scheduleProber() {
    if (!running.get()) return
    try {
        pingExecutor.schedule({
            if (!running.get()) return@schedule
            val now = System.currentTimeMillis()
            // 1) потери: пинг висит дольше RrpClient.PING_LOSS_AFTER_MS без Pong
            val sentAt = lastPingSentAt.get()
            if (sentAt > 0 && !lastPingCounted && now - sentAt >= RrpClient.PING_LOSS_AFTER_MS) {
                lastPingCounted = true
                recordPingResult(false)
            }
            // 2) PROBE — раз в RrpClient.PROBER_INTERVAL_MS (скважность ~90/10)
            if (now - lastProberTickMs >= RrpClient.PROBER_INTERVAL_MS) {
                lastProberTickMs = now
                val target = validateProbeTarget ?: RrpClient.DEFAULT_PROBE_TARGET
                val pr = try { probeOnce(target, RrpClient.PROBE_TIMEOUT_MS) } catch (_: Exception) { null }
                lastProbeOk = pr?.ok
                val (loss, rtt) = healthWindow()
                log(Msgs.PROBE_LOSS.t(loss * 100.0, rtt, 60), LogKind.WARN)
            }
            // 3) v1.8.0: E2E-пробник полезной нагрузки — сквозной путь
            // (OPEN→DATA→ответ) в отдельном потоке relayExecutor: чтение
            // до timeoutMs НЕ задерживает пинги (pingExecutor однопоточный).
            val e2eTarget = e2eProbeTarget
            if (now - lastE2eTickMs >= RrpClient.E2E_INTERVAL_MS && e2eTarget != null) {
                lastE2eTickMs = now
                if (e2eBusy.compareAndSet(false, true)) {
                    relayExecutor.execute {
                        try {
                            val outcome = e2eProbeOnce(e2eTarget, E2eProbe.timeoutFor(rttEwmaMs))
                            if (outcome != null) {
                                lastE2e = System.currentTimeMillis() to outcome
                                debug("E2E probe: $outcome")
                            }
                        } catch (_: Exception) {
                        } finally {
                            e2eBusy.set(false)
                        }
                    }
                }
            }
            scheduleProber()
        }, RrpClient.MONITOR_TICK_MS, TimeUnit.MILLISECONDS)
    } catch (_: RejectedExecutionException) {
    }
}

/** Снимок окна качества: (доля потерь 0..1 за 60с, EWMA RTT). */
fun RrpClient.healthWindow(): Pair<Double, Long> {
    val now = System.currentTimeMillis()
    synchronized(pingResults) {
        val horizon = now - RrpClient.HEALTH_WINDOW_MS
        while (pingResults.isNotEmpty() && pingResults.first().first < horizon) pingResults.removeFirst()
        val total = pingResults.size
        val fails = pingResults.count { !it.second }
        val loss = if (total == 0) 0.0 else fails.toDouble() / total
        return loss to rttEwmaMs
    }
}

/** Снимок для AutoBalancer.onSample. */
fun RrpClient.healthSample(): AutoBalancer.Sample {
    val (loss, rtt) = healthWindow()
    // v1.8.0: исход E2E-пробника учитываем, пока он свеж (иначе — null:
    // старое поведение, решение только по PING/EWMA/PROBE).
    // v1.8.10: с пробой идёт её момент (e2eAtMs) — балансер отличает
    // свежий dead-вердикт от просроченного (анти-молотьба свитчей).
    val e2e = lastE2e?.let { (at, o) ->
        if (System.currentTimeMillis() - at < RrpClient.E2E_STALE_MS) o else null
    }
    return AutoBalancer.Sample(
        atMs = System.currentTimeMillis(),
        rttMs = if (rtt > 0) rtt else null,
        lossRatio = loss,
        probeOk = lastProbeOk,
        e2e = e2e,
        e2eAtMs = lastE2e?.first?.takeIf { e2e != null },
    )
}

