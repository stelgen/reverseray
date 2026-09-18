package dev.stelgen.reverseray.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restarts the tunnel after reboot when it was active (OS persists stickiness too). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED &&
            context.getSharedPreferences("rrp", Context.MODE_PRIVATE)
                .getBoolean("autostart", false) &&
            !TunnelService.isRunning
        ) {
            val uri = context.getSharedPreferences("rrp", Context.MODE_PRIVATE)
                .getString("last_uri", null) ?: return
            val i = Intent(context, TunnelService::class.java)
            i.putExtra(TunnelService.EXTRA_URI, uri)
            context.startService(i)
        }
    }
}
