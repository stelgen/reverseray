@file:Suppress("MatchingDeclarationName") // файл держит также top-level-хелперы рядом с главным типом
// TunnelLimit.kt — зона «Лимит трафика: ожидание сброса, учёт, Wi-Fi-гейт» (pure move из TunnelService.kt, v1.8.3: дробление по зонам ответственности;
// поведение не меняется, члены private→internal — тот же пакет).
package dev.stelgen.reverseray.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import dev.stelgen.reverseray.R
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
// ---------- лимит трафика ----------

internal data class Usage(val used: Long, val limit: Long)

/**
 * Ожидание сброса лимита (авто-реконнект вкл): вычисляем дату следующего
 * сброса и ждём её, не тратя батарейку/трафик (грубые проверки раз в
 * минуту). По сбросу — реконнект. Выключаемо нитью stopTunnel().
 */
internal fun TunnelService.maybeWaitLimitReset() {
    if (!prefs().getBoolean(TunnelService.KEY_AUTO_RECONNECT, false)) return
    if (limitWaitThread?.isAlive == true) return
    val period = prefs().getString(TunnelService.KEY_LIMIT_PERIOD, TunnelService.PERIOD_DAY) ?: TunnelService.PERIOD_DAY
    val day = prefs().getInt(TunnelService.KEY_LIMIT_RESET_DAY, 1)
    val at = nextResetAtMs(period, day)
    val hours = ((at - System.currentTimeMillis()) / 3_600_000L).coerceAtLeast(0)
    TunnelService.pushLog(getString(R.string.status_limit_wait, hours), LogKind.WARN)
    updateStatus(TunnelService.STATE_LIMIT_REACHED, getString(R.string.status_limit_reached))
    val t = Thread {
        while (!stopping) {
            val usage = accountTraffic(0)
            if (usage.limit <= 0) {
                TunnelService.pushLog(getString(R.string.log_limit_removed), LogKind.OK)
                startTunnel()
                return@Thread
            }
            if (System.currentTimeMillis() >= at) {
                TunnelService.pushLog(getString(R.string.log_limit_period), LogKind.OK)
                startTunnel()
                return@Thread
            }
            try {
                Thread.sleep(TunnelService.LIMIT_POLL_MS)
            } catch (_: InterruptedException) {
                return@Thread
            }
        }
    }
    t.isDaemon = true
    limitWaitThread = t
    t.start()
}

/** Следующая дата сброса: сутки — завтра в это же время; месяц — день сброса. */
internal fun nextResetAtMs(period: String, day: Int): Long {
    val cal = Calendar.getInstance()
    if (period == TunnelService.PERIOD_MONTH) {
        cal.add(Calendar.MONTH, 1)
        cal.set(Calendar.DAY_OF_MONTH, day.coerceIn(1, 28))
    } else {
        cal.add(Calendar.DAY_OF_YEAR, 1)
    }
    cal.set(Calendar.HOUR_OF_DAY, 0)
    cal.set(Calendar.MINUTE, 0)
    cal.set(Calendar.SECOND, 0)
    cal.set(Calendar.MILLISECOND, 0)
    return cal.timeInMillis
}

/** Сбрасывает счётчик при смене периода, возвращает [used, limit]. */
internal fun TunnelService.accountTraffic(delta: Long): Usage {
    val p = prefs()
    val limit = p.getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
    val period = p.getString(TunnelService.KEY_LIMIT_PERIOD, TunnelService.PERIOD_DAY) ?: TunnelService.PERIOD_DAY
    val key = usagePeriodKey(period)
    var used = p.getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
    if (p.getString(TunnelService.KEY_USAGE_PERIOD, null) != key) {
        used = 0
        p.edit().putString(TunnelService.KEY_USAGE_PERIOD, key).apply()
    }
    if (delta > 0) used += delta
    return Usage(used, limit)
}

internal fun TunnelService.persistUsage() {
    val usage = accountTraffic(0)
    prefs().edit().putLong(TunnelService.KEY_TRAFFIC_USED, usage.used).apply()
}

/** Ключ периода: "2026-10-08" для суток, "2026-10" для месяца. */
internal fun TunnelService.usagePeriodKey(period: String): String {
    val fmt = if (period == TunnelService.PERIOD_MONTH) "yyyy-MM" else "yyyy-MM-dd"
    return SimpleDateFormat(fmt, Locale.ROOT).format(Date())
}

internal fun TunnelService.wifiOnly(): Boolean = prefs().getBoolean(TunnelService.KEY_WIFI_ONLY, false)

/** Подключение сейчас по Wi-Fi? (API 21+: capabilities; 14–20: legacy тип). */
@Suppress("DEPRECATION")
internal fun TunnelService.isOnWifi(): Boolean {
    val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    return try {
        if (Build.VERSION.SDK_INT >= 23) {
            val net = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(net) ?: return false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        } else {
            val info = cm.activeNetworkInfo
            info != null && info.type == ConnectivityManager.TYPE_WIFI && info.isConnected
        }
    } catch (_: Exception) {
        false
    }
}
