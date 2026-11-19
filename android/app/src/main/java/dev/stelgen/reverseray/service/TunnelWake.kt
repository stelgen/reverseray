// TunnelWake.kt — зона «Wake lock (PowerManager/WifiManager)» (pure move из TunnelService.kt, v1.8.3: дробление по зонам ответственности;
// поведение не меняется, члены private→internal — тот же пакет).
package dev.stelgen.reverseray.service

import android.annotation.SuppressLint
import android.content.Context
import android.os.PowerManager
import dev.stelgen.reverseray.core.Msgs
// ---------- wake lock ----------

@SuppressLint("WakelockTimeout")
internal fun TunnelService.acquireWakeLock() {
    val pm = applicationContext.getSystemService(Context.POWER_SERVICE) as PowerManager
    wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "reverseray:tunnel").apply {
        setReferenceCounted(false)
        acquire()
    }
    // v0.9.6: Wi-Fi-lock HIGH_PERF — туннель живёт в фоне без сна радио.
    // Держится только пока поднят туннель; доп. разрешений не требует.
    try {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
        @Suppress("DEPRECATION")
        val mode = android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF
        wifiLock = wm.createWifiLock(mode, "reverseray:wifi").apply {
            setReferenceCounted(false)
            acquire()
        }
    } catch (e: Exception) {
        TunnelService.pushLog(Msgs.WIFI_LOCK_FAILED.t(e.message ?: "?"), LogKind.WARN)
    }
}

internal fun TunnelService.releaseWakeLock() {
    try {
        wakeLock?.takeIf { it.isHeld }?.release()
    } catch (_: Exception) {
    }
    wakeLock = null
    try {
        wifiLock?.takeIf { it.isHeld }?.release()
    } catch (_: Exception) {
    }
    wifiLock = null
}
