package dev.stelgen.reverseray

import android.Manifest
import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.service.TunnelService
import dev.stelgen.reverseray.update.UpdateChecker
import java.io.File

/**
 * Dashboard: Material 3 (карточка статуса, outlined-поле конфига, кнопки),
 * импорт конфига строкой/QR, экспорт QR, авто-обновление с GitHub Releases.
 * Вся разметка собирается кодом — один источник правды.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusView: TextView
    private lateinit var configView: TextInputEditText

    /** zxing-embedded требует API 19+ (overrideLibrary в манифесте). */
    private val qrSupported: Boolean get() = Build.VERSION.SDK_INT >= 19

    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val content = result.contents ?: return@registerForActivityResult
        try {
            RrpUri.parse(content)
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
        checkForUpdateAsync(showIfUpToDate = false)
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(TunnelService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 34) {
            ContextCompat.registerReceiver(
                this, statusReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED,
            )
        } else {
            // <34: система не требует флагов; broadcast адресован setPackage(packageName)
            @SuppressLint("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusReceiver, filter)
        }
    }

    override fun onStop() {
        super.onStop()
        try { unregisterReceiver(statusReceiver) } catch (_: Exception) {}
    }

    // ---------- UI ----------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }

        val title = TextView(this).apply {
            setText(R.string.app_name)
            textSize = 24f
            setTypeface(typeface, Typeface.BOLD)
        }
        root.addView(title)

        // Карточка статуса
        val card = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { setMargins(0, dp(12), 0, dp(12)) }
            radius = dp(16).toFloat()
            cardElevation = dp(2).toFloat()
        }
        val cardInner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        statusView = TextView(this@MainActivity).apply { setText(R.string.status_idle) }
        cardInner.addView(statusView)
        card.addView(cardInner)
        root.addView(card)

        // Конфигурация
        val layout = TextInputLayout(this).apply {
            hint = getString(R.string.config_hint)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { setMargins(0, dp(8), 0, dp(8)) }
        }
        configView = TextInputEditText(this@MainActivity).apply {
            setText(prefs().getString(TunnelService.KEY_CONFIG, ""))
            minLines = 2
        }
        layout.addView(configView)
        root.addView(layout)

        // Кнопки управления
        fun row(vararg buttons: MaterialButton) {
            val l = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                )
            }
            buttons.forEachIndexed { i, b ->
                b.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    .apply { setMargins(0, dp(6), if (i == buttons.size - 1) 0 else dp(6), dp(6)) }
                l.addView(b)
            }
            root.addView(l)
        }

        if (qrSupported) {
            row(
                MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    setText(R.string.qr_scan)
                    setOnClickListener { launchScan() }
                },
                MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    setText(R.string.qr_show)
                    setOnClickListener { showQr() }
                },
            )
        } else {
            row(
                MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    setText(R.string.qr_show)
                    setOnClickListener { showQr() }
                },
            )
        }
        row(
            MaterialButton(this).apply {
                setText(R.string.btn_start)
                setOnClickListener { startTunnel() }
            },
        )
        row(
            MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                setText(R.string.btn_stop)
                setOnClickListener {
                    startService(
                        Intent(this@MainActivity, TunnelService::class.java)
                            .setAction(TunnelService.ACTION_STOP)
                    )
                }
            },
        )
        root.addView(Button(this).apply {
            setText(R.string.logs_title)
            setOnClickListener { showLogs() }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            background = null
        })

        setContentView(root)
    }

    // ---------- QR ----------

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
            RrpUri.parse(raw)
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
            return
        }
        val bitmap: android.graphics.Bitmap = try {
            BarcodeEncoder().encodeBitmap(raw, com.google.zxing.BarcodeFormat.QR_CODE, 640, 640)
        } catch (e: Exception) {
            Toast.makeText(this, R.string.qr_error, Toast.LENGTH_SHORT).show()
            return
        }
        val iv = android.widget.ImageView(this).apply {
            setImageBitmap(bitmap)
            setPadding(24, 24, 24, 24)
        }
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.qr_show)
            .setView(iv)
            .setPositiveButton(android.R.string.ok, null)
            .create()
        // конфиг содержит токен — запрещаем скриншоты
        dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
    }

    // ---------- логи ----------

    private fun showLogs() {
        val logText = TunnelService.snapshotLogs()
            .ifEmpty { listOf(getString(R.string.logs_empty)) }
            .joinToString("\n")
        val tv = TextView(this).apply {
            setTextIsSelectable(true)
            typeface = Typeface.MONOSPACE
            textSize = 13f
            setPadding(24, 24, 24, 24)
            text = logText
        }
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.logs_title)
            .setView(tv)
            .setPositiveButton(android.R.string.ok, null)
            .setNeutralButton(R.string.logs_copy) { _, _ ->
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("ReverseRay log", logText))
                Toast.makeText(this, R.string.logs_copied, Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    // ---------- обновление ----------

    private fun currentVersion(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: ""
    } catch (_: Exception) {
        ""
    }

    private fun checkForUpdateAsync(showIfUpToDate: Boolean) {
        val current = currentVersion()
        Thread {
            val info = UpdateChecker().check(current) ?: run {
                if (showIfUpToDate) {
                    runOnUiThread { Toast.makeText(this, R.string.update_latest, Toast.LENGTH_SHORT).show() }
                }
                return@Thread
            }
            runOnUiThread {
                MaterialAlertDialogBuilder(this)
                    .setTitle(getString(R.string.update_title, info.latestTag))
                    .setMessage(getString(R.string.update_question))
                    .setPositiveButton(R.string.update_download) { _, _ -> downloadUpdate(info) }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }.apply { isDaemon = true }.start()
    }

    private fun downloadUpdate(info: dev.stelgen.reverseray.update.UpdateInfo) {
        val dir = File(cacheDir, "apk").apply { mkdirs() }
        val dest = File(dir, "update-${info.latestTag}.apk")
        val status = Toast.makeText(this, R.string.update_downloading, Toast.LENGTH_LONG)
        status.show()
        Thread {
            try {
                UpdateChecker().downloadApk(info, dest)
                runOnUiThread {
                    status.cancel()
                    installApk(dest)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    status.cancel()
                    Toast.makeText(this, getString(R.string.update_error, e.message ?: ""), Toast.LENGTH_LONG).show()
                }
            }
        }.apply { isDaemon = true }.start()
    }

    private fun installApk(file: File) {
        val uri: Uri = FileProvider.getUriForFile(this, "$packageName.files", file)
        val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
            data = uri
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, R.string.update_error, Toast.LENGTH_SHORT).show()
        }
    }

    // ---------- туннель ----------

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

