package dev.stelgen.reverseray

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.service.TunnelService

/**
 * Минимальный dashboard: статус, поле конфига rrp://, кнопки старт/стоп.
 * UI собран кодом, без layout-XML и без Material-виджетов (тема — AppCompat).
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusView: TextView
    private lateinit var configView: EditText

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            intent?.getStringExtra(TunnelService.EXTRA_STATUS)?.let { statusView.text = it }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        buildUi()
        statusView.text = TunnelService.lastStatus.ifEmpty { getString(R.string.status_idle) }
    }

    override fun onStart() {
        super.onStart()
        ContextCompat.registerReceiver(
            this,
            statusReceiver,
            IntentFilter(TunnelService.ACTION_STATUS),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun onStop() {
        super.onStop()
        try { unregisterReceiver(statusReceiver) } catch (_: Exception) {}
    }

    private fun buildUi() {
        val dp = resources.displayMetrics.density
        val pad = (16 * dp).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        val title = TextView(this).apply {
            setText(R.string.app_name)
            textSize = 22f
        }
        statusView = TextView(this).apply { setText(R.string.status_idle) }
        configView = EditText(this).apply {
            hint = getString(R.string.config_hint)
            setText(prefs().getString(TunnelService.KEY_CONFIG, ""))
            minLines = 2
        }
        val startBtn = Button(this).apply {
            setText(R.string.btn_start)
            setOnClickListener { startTunnel() }
        }
        val stopBtn = Button(this).apply {
            setText(R.string.btn_stop)
            setOnClickListener {
                startService(
                    Intent(this@MainActivity, TunnelService::class.java)
                        .setAction(TunnelService.ACTION_STOP)
                )
            }
        }
        listOf(title, statusView, configView, startBtn, stopBtn).forEach { root.addView(it) }
        setContentView(root)
    }

    private fun startTunnel() {
        val raw = configView.text.toString().trim()
        try {
            RrpUri.parse(raw)
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
            return
        }
        prefs().edit().putString(TunnelService.KEY_CONFIG, raw).apply()
        val i = Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_START)
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(i)
        } else {
            startService(i)
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    private fun prefs() = getSharedPreferences(TunnelService.PREFS, MODE_PRIVATE)
}
