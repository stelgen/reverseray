package dev.stelgen.reverseray.service

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import dev.stelgen.reverseray.MainActivity
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.RrpUriConfig
import java.util.Random
import java.util.concurrent.atomic.AtomicLong

/**
 * Foreground-сервис: держит пул RrpClient (по одному на порт из конфига).
 *
 * - уведомления: channels на 26+, просто Notification на старых;
 * - startForeground: тип specialUse на 34+ (FOREGROUND_SERVICE_TYPE_SPECIAL_USE),
 *   на 29..33 и старше — перегрузка без типа;
 * - сеть: NetworkCallback на 21+, CONNECTIVITY_ACTION — фолбэк для <21;
 * - при появлении сети — мгновенный retry всех коннектов с cooldown 3 c;
 * - между попытками — экспоненциальный backoff 1→60 c ±30 % (RrpClient.backoffDelayMs).
 */
class TunnelService : Service() {

    private class Target(val host: String, val port: Int)

    private inner class Runner(val target: Target) {
        @Volatile var kick = false
    }

    private val runners = mutableListOf<Runner>()
    private val rnd = Random()
    private val lastNetKick = AtomicLong(0)

    @Volatile private var config: RrpUriConfig? = null
    @Volatile private var stopping = true
    private var wakeLock: PowerManager.WakeLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var legacyReceiver: BroadcastReceiver? = null

    private val clientListener = object : RrpClient.Listener {
        override fun onLog(client: RrpClient, message: String) {
            Log.d(TAG, "${client.host}:${client.port}: $message")
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        // ACTION_START или рестарт системой после убийства (intent == null, START_STICKY)
        startTunnel()
        return START_STICKY
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    // ---------- туннель ----------

    private fun startTunnel() {
        if (!stopping && runners.isNotEmpty()) {
            updateStatus(getString(R.string.status_already_running))
            return
        }
        val cfg = try {
            prefs().getString(KEY_CONFIG, null)?.let { RrpUri.parse(it) }
        } catch (e: Exception) {
            Log.w(TAG, "конфиг не разобран: ${e.message}")
            null
        }
        if (cfg == null) {
            updateStatus(getString(R.string.status_no_config))
            stopSelf()
            return
        }
        config = cfg
        stopping = false
        startForegroundCompat(getString(R.string.notif_starting))
        acquireWakeLock()
        for (port in cfg.ports) {
            val r = Runner(Target(cfg.host, port))
            runners.add(r)
            Thread({ runLoop(r) }, "rrp-conn-$port").start()
        }
        registerNetworkWatching()
        updateStatus(getString(R.string.status_connecting, cfg.host))
    }

    private fun runLoop(r: Runner) {
        var attempt = 0
        while (!stopping) {
            val cfg = config ?: break
            val client = RrpClient(
                host = r.target.host,
                port = r.target.port,
                token = cfg.token,
                pin = cfg.pin,
                allowLan = allowLan(),
                listener = clientListener,
            )
            try {
                client.connect()
                attempt = 0
                updateStatus(getString(R.string.status_connected, r.target.port))
                while (!stopping && client.state == RrpClient.State.READY) {
                    try {
                        Thread.sleep(500)
                    } catch (_: InterruptedException) {
                        break
                    }
                }
            } catch (e: Exception) {
                updateStatus(getString(R.string.status_error, r.target.port, e.message ?: "?"))
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
            if (stopping) break
            attempt++
            val delay = RrpClient.backoffDelayMs(attempt - 1, rnd)
            updateStatus(getString(R.string.status_retry, r.target.port, delay / 1000))
            sleepWithKick(r, delay)
        }
    }

    /** Сон с прерыванием по kick (мгновенный retry после появления сети). */
    private fun sleepWithKick(r: Runner, ms: Long) {
        val deadline = System.currentTimeMillis() + ms
        while (!stopping) {
            if (r.kick) {
                r.kick = false
                return
            }
            val now = System.currentTimeMillis()
            if (now >= deadline) return
            try {
                Thread.sleep(minOf(250L, deadline - now))
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun stopTunnel() {
        stopping = true
        runners.clear()
        unregisterNetworkWatching()
        releaseWakeLock()
        updateStatus(getString(R.string.status_stopped))
    }

    // ---------- сеть ----------

    private fun registerNetworkWatching() {
        val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (Build.VERSION.SDK_INT >= 21) {
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    kickAll()
                }
            }
            try {
                cm.registerNetworkCallback(NetworkRequest.Builder().build(), cb)
                networkCallback = cb
            } catch (e: Exception) {
                Log.w(TAG, "NetworkCallback не зарегистрирован: ${e.message}")
            }
        } else {
            // Фолбэк для API 14..20: легаси-броадкаст
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent?.action == ConnectivityManager.CONNECTIVITY_ACTION) kickAll()
                }
            }
            registerReceiver(receiver, IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION))
            legacyReceiver = receiver
        }
    }

    /** Мгновенный retry всех коннектов с cooldown 3 c. */
    private fun kickAll() {
        val now = System.currentTimeMillis()
        val last = lastNetKick.get()
        if (now - last < NET_RETRY_COOLDOWN_MS) return
        if (!lastNetKick.compareAndSet(last, now)) return
        Log.d(TAG, "сеть появилась — мгновенный retry")
        synchronized(runners) { runners.forEach { it.kick = true } }
    }

    private fun unregisterNetworkWatching() {
        networkCallback?.let {
            try {
                (applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(it)
            } catch (_: Exception) {
            }
        }
        networkCallback = null
        legacyReceiver?.let { try { unregisterReceiver(it) } catch (_: Exception) {} }
        legacyReceiver = null
    }

    // ---------- foreground / уведомления ----------

    private fun startForegroundCompat(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            // 29..33: константы specialUse ещё нет; <29: перегрузки с типом не существует
            startForeground(NOTIF_ID, notification)
        }
    }

    @Suppress("DEPRECATION")
    private fun buildNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }
        return builder
            // android.R.*: системная иконка безопасна для notification small icon на всех API
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .build()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.notif_channel_name),
                    NotificationManager.IMPORTANCE_LOW,
                )
            )
        }
    }

    // ---------- wake lock ----------

    @SuppressLint("WakelockTimeout")
    private fun acquireWakeLock() {
        val pm = applicationContext.getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "reverseray:tunnel").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.takeIf { it.isHeld }?.release()
        } catch (_: Exception) {
        }
        wakeLock = null
    }

    // ---------- статус ----------

    private fun updateStatus(text: String) {
        lastStatus = text
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName).putExtra(EXTRA_STATUS, text))
        try {
            (applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIF_ID, buildNotification(text))
        } catch (_: Exception) {
        }
    }

    private fun prefs(): SharedPreferences = getSharedPreferences(PREFS, MODE_PRIVATE)

    private fun allowLan(): Boolean = prefs().getBoolean(KEY_ALLOW_LAN, false)

    companion object {
        private const val TAG = "ReverseRay"

        const val PREFS = "reverseray"
        const val KEY_CONFIG = "config"
        const val KEY_AUTOSTART = "autostart"
        const val KEY_ALLOW_LAN = "allow_lan"

        const val ACTION_START = "dev.stelgen.reverseray.action.START"
        const val ACTION_STOP = "dev.stelgen.reverseray.action.STOP"
        const val ACTION_STATUS = "dev.stelgen.reverseray.action.STATUS"
        const val EXTRA_STATUS = "status"

        private const val CHANNEL_ID = "tunnel"
        private const val NOTIF_ID = 1
        private const val NET_RETRY_COOLDOWN_MS = 3_000L

        @Volatile var lastStatus: String = ""
    }
}
