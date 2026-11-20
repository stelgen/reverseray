package dev.stelgen.reverseray.service

// v1.8.8: сетевая зона TunnelService вынесена в отдельный файл (дробление по
// зонам ответственности; private → internal у задетых членов, поведение
// не меняется). Наблюдение за сетью + kick переподключений.

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.util.Log
import dev.stelgen.reverseray.core.ConnectionManager
import dev.stelgen.reverseray.R

internal fun TunnelService.registerNetworkWatching() {
        val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (Build.VERSION.SDK_INT >= 21) {
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    kickAll()
                }
            }
            try {
                val req = if (Build.VERSION.SDK_INT >= 23 && wifiOnly()) {
                    NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                        .build()
                } else {
                    NetworkRequest.Builder().build()
                }
                cm.registerNetworkCallback(req, cb)
                networkCallback = cb
            } catch (e: Exception) {
                Log.w(TunnelService.TAG, getString(R.string.log_netcallback_failed, e.message))
            }
        } else {
            // Фолбэк для API 14..20: легаси-броадкаст.
            // CONNECTIVITY_ACTION deprecated с API 24, но ветка живёт ТОЛЬКО на
            // API 14..20 (где он единственный канал) — осознанный митигейт.
            @Suppress("DEPRECATION")
            val action = ConnectivityManager.CONNECTIVITY_ACTION
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent?.action == action) kickAll()
                }
            }
            @Suppress("DEPRECATION")
            registerReceiver(receiver, IntentFilter(action))
            legacyReceiver = receiver
        }
    }

    /** Мгновенный retry всех коннектов с cooldown 3 c. */

internal fun TunnelService.kickAll() {
        val now = System.currentTimeMillis()
        val last = lastNetKick.get()
        if (now - last < TunnelService.NET_RETRY_COOLDOWN_MS) return
        if (!lastNetKick.compareAndSet(last, now)) return
        Log.d(TunnelService.TAG, getString(R.string.log_network_back))
        // wifi-only: kick только если мы на Wi-Fi
        if (wifiOnly() && !isOnWifi()) {
            updateStatus(TunnelService.STATE_INFO, getString(R.string.status_wait_wifi))
            return
        }
        manager?.kickAll()
        // если туннель ещё не поднимался из-за отсутствия Wi-Fi — поднимаем
        if (manager == null && sessById.isEmpty() && !stopping) {
            manager = ConnectionManager(sessionOwner)
            startAllSessions()
        }
    }


internal fun TunnelService.unregisterNetworkWatching() {
        networkCallback?.let {
            if (Build.VERSION.SDK_INT >= 21) {
                try {
                    (applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                        .unregisterNetworkCallback(it)
                } catch (_: Exception) {
                }
            }
        }
        networkCallback = null
        legacyReceiver?.let { try { unregisterReceiver(it) } catch (_: Exception) {} }
        legacyReceiver = null
    }
