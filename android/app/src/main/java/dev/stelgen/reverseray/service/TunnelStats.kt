// v1.9.0: зона «статистика» вынесена из TunnelService.kt (транш-2):
// реалтайм-луп байт/с + пакетные счётчики + JSON-снапшот сессий для дашборда.
// Pure refactor: private → internal у задетых членов, поведение не меняется.
package dev.stelgen.reverseray.service

import android.content.Intent
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.ConnectionManager
import dev.stelgen.reverseray.core.LogKind

// ------------------------------------------------------------------ статистика (реалтайм-луп, снапшот сессий)

    /** Реалтайм-статистика трафика: раз в 500 мс шлёт TunnelService.ACTION_STATS (байт/с). */
    internal fun TunnelService.startStatsLoop() {
        if (statsThread?.isAlive == true) return
        lastTx = 0
        lastRx = 0
        val t = Thread({
            var persistTick = 0
            while (!stopping) {
                try {
                    Thread.sleep(TunnelService.STATS_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                var tx = 0L
                var rx = 0L
                var pk = longArrayOf(0, 0, 0, 0)
                var kind = ""
                synchronized(runners) {
                    runners.forEach { r ->
                        r.client?.bytesSnapshot()?.let { (a, b) -> tx += a; rx += b }
                        r.client?.packetsSnapshot()?.let { p ->
                            pk[0] += p[0]; pk[1] += p[1]; pk[2] = p[2]; pk[3] = p[3]
                        }
                        if (r.client?.lastPacketKind?.isNotEmpty() == true) kind = r.client!!.lastPacketKind
                    }
                }
                val dtx = tx - lastTx
                val drx = rx - lastRx
                lastTx = tx
                lastRx = rx
                // v1.5.0: per-сессионный снапшот для дашборда (JSON в extra)
                val sessionsJson = sessionsJson()
                // v0.9.2 (R4): история графика живёт в сервисе — переживает recreate

                // v0.8: счётчик за всё время (канон: RAM, запись на диск пореже)
                prefs().edit()
                    .putLong(TunnelService.KEY_TRAFFIC_LIFETIME, lifetime.addAndGet(drx + dtx)).apply()
                // v0.7.4/v0.8: учёт лимита трафика (сумма вход+выход за период)
                val usage = accountTraffic(drx + dtx)

                sendBroadcast(
                    Intent(TunnelService.ACTION_STATS)
                        .setPackage(packageName)
                        .putExtra(TunnelService.EXTRA_TX_RATE, dtx * 1000L / TunnelService.STATS_INTERVAL_MS)
                        .putExtra(TunnelService.EXTRA_RX_RATE, drx * 1000L / TunnelService.STATS_INTERVAL_MS)
                        .putExtra(TunnelService.EXTRA_TX_TOTAL, tx)
                        .putExtra(TunnelService.EXTRA_RX_TOTAL, rx)
                        .putExtra(TunnelService.EXTRA_SESSIONS, sessionsJson)
                        .putExtra(TunnelService.EXTRA_PKT_TX_COUNT, pk[0])
                        .putExtra(TunnelService.EXTRA_PKT_RX_COUNT, pk[1])
                        .putExtra(TunnelService.EXTRA_PKT_TX_SIZE, pk[2])
                        .putExtra(TunnelService.EXTRA_PKT_RX_SIZE, pk[3])
                        .putExtra(TunnelService.EXTRA_PKT_KIND, kind)
                        .putExtra(TunnelService.EXTRA_USAGE_BYTES, usage.used)
                        .putExtra(TunnelService.EXTRA_USAGE_LIMIT, usage.limit)
                )
                if (usage.limit > 0 && usage.used >= usage.limit) {
                    // КАНОН «ЛИМИТ — КОРОЛЬ»: ровно ноль байт от нас.
                    updateStatus(TunnelService.STATE_ERROR, getString(R.string.status_limit_reached))
                    TunnelService.pushLog(getString(R.string.status_limit_reached), LogKind.ERROR)
                    sendBroadcast(
                        Intent(TunnelService.ACTION_STATUS).setPackage(packageName)
                            .putExtra(TunnelService.EXTRA_STATE, TunnelService.STATE_LIMIT_REACHED)
                            .putExtra(TunnelService.EXTRA_STATUS, getString(R.string.status_limit_reached))
                            .putExtra(TunnelService.EXTRA_USAGE_BYTES, usage.used)
                            .putExtra(TunnelService.EXTRA_USAGE_LIMIT, usage.limit)
                    )
                    stopTunnel() // туннель и все коннекты умирают — ноль байт
                    maybeWaitLimitReset()
                    return@Thread
                }
                // персистим счётчик РАЗ В МИНУТУ (дисциплина SSD/памяти, v0.8)
                if (++persistTick >= TunnelService.PERSIST_EVERY_TICKS) {
                    persistTick = 0
                    persistUsage()
                }
            }
        }, "rrp-stats").apply { isDaemon = true; start() }
        statsThread = t
    }

    /**
     * v1.5.0: JSON-снапшот всех сессий для дашборда (TunnelService.EXTRA_SESSIONS):
     * state/rates/totals/proto/rtt/реконнекты/ошибки/аптайм — по сессии.
     */
    internal fun TunnelService.sessionsJson(): String {
        val mgr = manager ?: return "[]"
        val now = System.currentTimeMillis()
        val arr = org.json.JSONArray()
        for (s in mgr.all()) {
            val proto = try { s.worker.negotiatedProto() } catch (_: Exception) { "" }
            arr.put(
                org.json.JSONObject()
                    .put("id", s.id)
                    .put("name", s.profile.name)
                    .put("state", s.state)
                    .put("rx_rate", s.rxRate)
                    .put("tx_rate", s.txRate)
                    .put("rx_total", s.rxTotal)
                    .put("tx_total", s.txTotal)
                    .put("proto", proto)
                    .put("rtt_ms", s.lastRttMs)
                    .put("reconnects", s.reconnects.get())
                    .put("errors", s.errors.get())
                    .put("switches", s.protoSwitches.get())
                    .put("uptime_ms", if (s.startedAtMs.get() > 0) now - s.startedAtMs.get() else 0)
                    .put("primary", s.id == sessionStore.activeId()),
            )
        }
        return arr.toString()
    }

    /**
     * Обновить URI PRIMARY-профиля + зеркало KEY_CONFIG (единая точка для
     * всех legacy-писателей конфига: accept-pin, вставка ссылки в UI).
     */
