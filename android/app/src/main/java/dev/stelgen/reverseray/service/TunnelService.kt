package dev.stelgen.reverseray.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpUri

/**
 * Foreground service keeping N tunnel sessions alive.
 * API-gated code paths: notifications (26+), FGS type (29+/34+).
 */
class TunnelService : Service(), RrpClient.Listener {

    companion object {
        const val CHANNEL_ID = "tunnel"
        const val NOTIFICATION_ID = 42
        const val EXTRA_URI = "uri"
        var isRunning = false
    }

    private var client: RrpClient? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        isRunning = true
        startForegroundWithType()
        registerNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val uri = intent?.getStringExtra(EXTRA_URI) ?: return START_NOT_STICKY
        val profile = try {
            RrpUri.parse(uri)
        } catch (e: Exception) {
            stopSelf()
            return START_NOT_STICKY
        }
        client?.disconnect()
        RrpClient(this).let {
            client = it
            it.connect(profile)
        }
        notify(getString(R.string.status_connecting))
        return START_STICKY
    }

    override fun onDestroy() {
        isRunning = false
        client?.disconnect()
        unregisterNetworkCallback()
        super.onDestroy()
    }

    // ---- RrpClient.Listener ----

    override fun onState(state: RrpClient.State, info: String) {
        val text = when (state) {
            RrpClient.State.READY -> getString(R.string.status_connected)
            RrpClient.State.CONNECTING -> getString(R.string.status_connecting)
            RrpClient.State.HANDSHAKE -> getString(R.string.status_handshake)
            RrpClient.State.CLOSED -> getString(R.string.status_disconnected) + " ($info)"
        }
        notify(text)
    }

    override fun onOpenRequest(host: String, port: Int): java.net.Socket? =
        try {
            java.net.Socket().apply { connect(java.net.InetSocketAddress(host, port), 10_000) }
        } catch (e: Exception) {
            null
        }

    // ---- notifications (API-gated) ----

    private fun notify(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            val ch = NotificationChannel(CHANNEL_ID, getString(R.string.channel_name),
                NotificationManager.IMPORTANCE_LOW)
            nm.createNotificationChannel(ch)
        }
        val n: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_reverseray)
            .setContentTitle("ReverseRay")
            .setContentText(text)
            .setOngoing(true)
            .build()
        nm.notify(NOTIFICATION_ID, n)
    }

    private fun startForegroundWithType() {
        val n = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_reverseray)
            .setContentTitle("ReverseRay")
            .setContentText(getString(R.string.status_connecting))
            .build()
        when {
            Build.VERSION.SDK_INT >= 34 ->
                startForeground(NOTIFICATION_ID, n,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            Build.VERSION.SDK_INT >= 29 ->
                startForeground(NOTIFICATION_ID, n,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            else -> startForeground(NOTIFICATION_ID, n)
        }
    }

    // ---- network tracking (21+ NetworkCallback, airplane-off fast retry) ----

    private var registered = false
    private val cm by lazy { getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager }

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            // Fast reconnect on network change (cooldown handled in RrpClient backoff).
            client?.let { c -> if (c.state == RrpClient.State.CLOSED) c.disconnect() }
        }
    }

    private fun registerNetworkCallback() {
        if (Build.VERSION.SDK_INT >= 21 && !registered) {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            runCatching { cm.registerNetworkCallback(req, callback) }
            registered = true
        }
    }

    private fun unregisterNetworkCallback() {
        if (registered) {
            runCatching { cm.unregisterNetworkCallback(callback) }
            registered = false
        }
    }
}
