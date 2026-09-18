package dev.stelgen.reverseray.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

/**
 * Автостарт (заглушка): после BOOT_COMPLETED поднимает туннель,
 * если автостарт включён в настройках (prefs KEY_AUTOSTART).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences(TunnelService.PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(TunnelService.KEY_AUTOSTART, false)) return
        val i = Intent(context, TunnelService::class.java).setAction(TunnelService.ACTION_START)
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(i)
        } else {
            context.startService(i)
        }
    }
}
