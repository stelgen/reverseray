package dev.stelgen.reverseray

import android.annotation.SuppressLint
import android.Manifest
import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.service.TunnelService

/**
 * Dashboard: статус, конфиг rrp:// (ввод/скан QR/экспорт QR), старт/стоп.
 * UI собран кодом (layout-XML нет — один источник правды).
 *
 * QR-скан: zxing-embedded декларирует minSdk 19 (overrideLibrary в манифесте),
 * поэтому кнопка скана видна только на API >= 19; на 14–18 — ручной ввод.
 * Экспорт QR: генерация локальная (BarcodeEncoder), диалог помечен FLAG_SECURE.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusView: TextView
    private lateinit var configView: EditText

    /** zxing-embedded требует API 19+ (декларация библиотеки, overrideLibrary в манифесте). */
    private val qrSupported: Boolean get() = Build.VERSION.SDK_INT >= 19

    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val content = result.contents ?: return@registerForActivityResult
        try {
            RrpUri.parse(content) // валидация до вставки
            configView.setText(content.trim())
            Toast.makeText(this, R.string.qr_imported, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(
                this,
                getString(R.string.invalid_config, e.message ?: ""),
                Toast.LENGTH_LONG,
            ).show()
        }
    }

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
        val filter = IntentFilter(TunnelService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 34) {
            // 34+: флаг обязателен; кастомный permission объявлен в манифесте
            ContextCompat.registerReceiver(
                this, statusReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED,
            )
        } else {
            // <34: система не требует флагов; broadcast адресован setPackage(packageName)
            // и отправляется только собственным сервисом
            @SuppressLint("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusReceiver, filter)
        }
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
        val rows = mutableListOf(title, statusView, configView)
        if (qrSupported) {
            rows.add(Button(this).apply {
                setText(R.string.qr_scan)
                setOnClickListener { launchScan() }
            })
        }
        rows.add(Button(this).apply {
            setText(R.string.qr_show)
            setOnClickListener { showQr() }
        })
        rows.add(startBtn)
        rows.add(stopBtn)
        rows.forEach { root.addView(it) }
        setContentView(root)
    }

    private fun launchScan() {
        if (!qrSupported) return
        val opts = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt(getString(R.string.qr_prompt))
            setBeepEnabled(false)
            setOrientationLocked(true)
        }
        try {
            scanLauncher.launch(opts)
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, R.string.qr_error, Toast.LENGTH_SHORT).show()
        }
    }

    private fun showQr() {
        val raw = configView.text.toString().trim()
        try {
            RrpUri.parse(raw) // экспортируем только валидный конфиг
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
            return
        }
        val bitmap: Bitmap = try {
            BarcodeEncoder().encodeBitmap(raw, com.google.zxing.BarcodeFormat.QR_CODE, 640, 640)
        } catch (e: Exception) {
            Toast.makeText(this, R.string.qr_error, Toast.LENGTH_SHORT).show()
            return
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.qr_show)
            .setView(ImageView(this).apply {
                setImageBitmap(bitmap)
                setPadding(24, 24, 24, 24)
            })
            .setPositiveButton(android.R.string.ok, null)
            .create()
        // конфиг содержит токен — запрещаем скриншоты/запись экрана диалога
        dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
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
