// TunnelNotif.kt — зона «Foreground / уведомления»: startForegroundCompat,
// buildNotification (канал LOW, канон v0.8), sessionStateShort, createChannel.
// Pure move из TunnelService.kt (v1.8.3: дробление по зонам ответственности;
// поведение не меняется).
package dev.stelgen.reverseray.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.content.pm.ServiceInfo
import dev.stelgen.reverseray.MainActivity
import dev.stelgen.reverseray.R

// ---------- foreground / уведомления ----------

internal fun TunnelService.startForegroundCompat(text: String) {
    val notification = buildNotification(text)
    if (Build.VERSION.SDK_INT >= 34) {
        startForeground(TunnelService.NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
    } else {
        startForeground(TunnelService.NOTIF_ID, notification)
    }
}

@Suppress("DEPRECATION")
internal fun TunnelService.buildNotification(text: String): Notification {
    val contentIntent = PendingIntent.getActivity(
        this, 0,
        Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
    val builder = if (Build.VERSION.SDK_INT >= 26) {
        Notification.Builder(this, TunnelService.CHANNEL_ID)
    } else {
        Notification.Builder(this)
    }
    builder
        .setSmallIcon(R.drawable.ic_stat_reverseray)
        .setContentTitle(getString(R.string.notif_title))
        .setContentText(text)
        .setContentIntent(contentIntent)
        .setOngoing(true)
    // v1.5.0: групповая нотификация — построчное состояние сессий (канал один)
    val lines = manager?.all().orEmpty()
    if (lines.size > 1 && Build.VERSION.SDK_INT >= 16) {
        val style = Notification.InboxStyle()
        for (s in lines) {
            val mark = when (s.state) {
                TunnelService.STATE_CONNECTED, TunnelService.STATE_PROTO -> "●"
                TunnelService.STATE_CONNECTING, TunnelService.STATE_RETRY -> "◌"
                TunnelService.STATE_STOPPED -> "–"
                else -> "✕"
            }
            style.addLine("$mark ${s.profile.name}: ${sessionStateShort(s.state)}")
        }
        builder.setStyle(style)
    }
    return if (Build.VERSION.SDK_INT >= 16) {
        builder.build()
    } else {
        @Suppress("DEPRECATION")
        builder.getNotification() // API 14-15: build() ещё нет
    }
}

/** Короткая метка состояния сессии для строки уведомления. */
internal fun TunnelService.sessionStateShort(state: String): String = when (state) {
    TunnelService.STATE_CONNECTED, TunnelService.STATE_PROTO -> getString(R.string.notif_session_up)
    TunnelService.STATE_CONNECTING, TunnelService.STATE_RETRY -> getString(R.string.notif_session_connecting)
    TunnelService.STATE_STOPPED -> getString(R.string.notif_session_off)
    else -> getString(R.string.notif_session_error)
}

internal fun TunnelService.createChannel() {
    if (Build.VERSION.SDK_INT >= 26) {
        val nm = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(
                TunnelService.CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            )
        )
    }
}
