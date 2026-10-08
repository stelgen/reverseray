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
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.activity.result.contract.ActivityResultContracts
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.shape.MaterialShapeDrawable
import com.google.android.material.shape.ShapeAppearanceModel
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import android.os.Handler
import android.os.Looper
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.net.NetInfo
import dev.stelgen.reverseray.net.NetInfoFetcher
import dev.stelgen.reverseray.service.TunnelService
import dev.stelgen.reverseray.ui.TrafficGraphView
import dev.stelgen.reverseray.update.UpdateChecker
import java.io.File

/**
 * Dashboard: Material 3. Сверху — большая круглая кнопка «Старт» (главное
 * действие, v0.7), под ней «Стоп», далее статус-карточка с реалтайм-графиком
 * трафика, конфиг (строка/QR/файл), обновление, журнал.
 * Вся разметка собирается кодом — один источник правды.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusView: TextView
    private lateinit var statusIcon: TextView
    private lateinit var statusSpinner: android.widget.ProgressBar
    private lateinit var configView: TextInputEditText
    private lateinit var trafficGraph: TrafficGraphView
    private lateinit var trafficLabel: TextView
    private lateinit var netFlag: TextView
    private lateinit var netInfoView: TextView
    private val uiHandler = Handler(Looper.getMainLooper())
    private val netInfoRunnable = object : Runnable {
        override fun run() {
            refreshNetInfoAsync()
            uiHandler.postDelayed(this, NETINFO_REFRESH_MS)
        }
    }

    /** zxing-embedded требует API 19+ (overrideLibrary в манифесте). */
    private val qrSupported: Boolean get() = Build.VERSION.SDK_INT >= 19

    /** SAF (файлы конфига) доступен с API 19. */
    private val fileIoSupported: Boolean get() = Build.VERSION.SDK_INT >= 19

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

    private val exportFileLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            if (uri != null) writeConfigToFile(uri)
        }

    private val importFileLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) readConfigFromFile(uri)
        }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            intent ?: return
            when (intent.action) {
                TunnelService.ACTION_STATS -> {
                    val rx = intent.getLongExtra(TunnelService.EXTRA_RX_RATE, 0L)
                    val tx = intent.getLongExtra(TunnelService.EXTRA_TX_RATE, 0L)
                    trafficGraph.addSample(rx.toFloat(), tx.toFloat())
                    trafficLabel.text = getString(
                        R.string.traffic_rates,
                        fmtRate(rx), fmtRate(tx),
                    )
                }
                else -> {
                    intent.getStringExtra(TunnelService.EXTRA_STATUS)?.let { statusView.text = it }
                    val state = intent.getStringExtra(TunnelService.EXTRA_STATE) ?: TunnelService.STATE_INFO
                    applyStatusVisual(state)
                    if (state == TunnelService.STATE_STOPPED || state == TunnelService.STATE_ERROR) {
                        trafficGraph.reset()
                        trafficLabel.text = getString(R.string.traffic_idle)
                    }
                }
            }
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
        uiHandler.post(netInfoRunnable)
        val filter = IntentFilter().apply {
            addAction(TunnelService.ACTION_STATUS)
            addAction(TunnelService.ACTION_STATS)
        }
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
        uiHandler.removeCallbacks(netInfoRunnable)
        try { unregisterReceiver(statusReceiver) } catch (_: Exception) {}
    }

    // ---------- UI ----------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(16))
        }

        // Шапка: иконка приложения вместо старого баннера
        root.addView(ImageView(this).apply {
            setImageResource(R.mipmap.ic_launcher)
            layoutParams = LinearLayout.LayoutParams(dp(84), dp(84)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                setMargins(0, dp(8), 0, dp(4))
            }
            contentDescription = getString(R.string.app_name)
        })
        root.addView(TextView(this).apply {
            setText(R.string.app_name)
            textSize = 24f
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER_HORIZONTAL
        })

        // ГЛАВНАЯ кнопка: большая круглая «Старт» — самое верхнее действие
        val startButton = MaterialButton(this).apply {
            setText(R.string.btn_start_short)
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
            shapeAppearanceModel = ShapeAppearanceModel.builder()
                .setAllCornerSizes(dp(110).toFloat()) // круг при 220dp
                .build()
            layoutParams = LinearLayout.LayoutParams(dp(220), dp(220)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                setMargins(0, dp(16), 0, dp(8))
            }
            setOnClickListener { startTunnel() }
        }
        root.addView(startButton)

        // Стоп — под Стартом, широкая outlined
        root.addView(
            MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                setText(R.string.btn_stop)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { setMargins(0, dp(4), 0, dp(4)) }
                setOnClickListener {
                    startService(
                        Intent(this@MainActivity, TunnelService::class.java)
                            .setAction(TunnelService.ACTION_STOP)
                    )
                }
            }
        )

        // Карточка статуса + график трафика
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
        val statusRow = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = dp(40) // фикс. высота: интерфейс не прыгает
        }
        statusSpinner = android.widget.ProgressBar(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(22), dp(22)).apply { setMargins(0, 0, dp(10), 0) }
            isIndeterminate = true
            indeterminateTintList = android.content.res.ColorStateList.valueOf(0xFFF9A825.toInt())
            visibility = android.view.View.GONE
        }
        statusRow.addView(statusSpinner)
        statusIcon = TextView(this@MainActivity).apply {
            textSize = 18f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, 0, dp(10), 0)
        }
        statusRow.addView(statusIcon)
        statusView = TextView(this@MainActivity).apply { setText(R.string.status_idle) }
        baseStatusColor = currentTextColor()
        statusRow.addView(statusView)
        cardInner.addView(statusRow)

        trafficGraph = TrafficGraphView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(96),
            ).apply { setMargins(0, dp(8), 0, dp(2)) }
        }
        cardInner.addView(trafficGraph)
        trafficLabel = TextView(this@MainActivity).apply {
            setText(R.string.traffic_idle)
            textSize = 12f
            setPadding(0, dp(2), 0, 0)
        }
        cardInner.addView(trafficLabel)

        // v0.7.2: сеть телефона — флаг страны (в размер текста) + IP/страна/оператор
        val netRow = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(6), 0, 0)
        }
        netFlag = TextView(this@MainActivity).apply {
            textSize = 13f
            setPadding(0, 0, dp(6), 0)
            visibility = android.view.View.GONE
        }
        netRow.addView(netFlag)
        netInfoView = TextView(this@MainActivity).apply {
            setText(R.string.netinfo_loading)
            textSize = 12f
        }
        netRow.addView(netInfoView)
        cardInner.addView(netRow)
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
            minHeight = dp(72) // фиксированная высота поля: кнопки не двигаются
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

        // Файл-импорт/экспорт конфига (SAF, API 19+; на 14–18 кнопки скрыты)
        if (fileIoSupported) {
            row(
                MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    setText(R.string.export_config)
                    setOnClickListener {
                        exportFileLauncher.launch("reverseray-config.txt")
                    }
                },
                MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    setText(R.string.import_config)
                    setOnClickListener {
                        try {
                            importFileLauncher.launch(arrayOf("text/*", "application/octet-stream"))
                        } catch (e: ActivityNotFoundException) {
                            Toast.makeText(this@MainActivity, R.string.file_error_no_picker, Toast.LENGTH_SHORT).show()
                        }
                    }
                },
            )
        }

        row(
            MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                setText(R.string.update_check)
                setOnClickListener { checkForUpdateAsync(showIfUpToDate = true) }
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

        setContentView(android.widget.ScrollView(this).apply { addView(root); setFillViewport(true) })
    }

    // ---------- статусная визуализация ----------

    private val colorGreen = 0xFF2E7D32.toInt()
    private val colorYellow = 0xFFF9A825.toInt()
    private val colorRed = 0xFFC62828.toInt()
    private val colorGray = 0xFF8A8F98.toInt()
    private var baseStatusColor = 0xFF212121.toInt()

    /** CONNECTING/RETRY — жёлтый спиннер; CONNECTED — зелёная галочка; ошибка/стоп — красный крест. */
    private fun applyStatusVisual(state: String) {
        val (icon: String?, color: Int, spinning: Boolean) = when (state) {
            TunnelService.STATE_CONNECTED -> Triple("✓", colorGreen, false)
            TunnelService.STATE_CONNECTING, TunnelService.STATE_RETRY -> Triple("", colorYellow, true)
            TunnelService.STATE_ERROR, TunnelService.STATE_STOPPED -> Triple("✕", colorRed, false)
            else -> Triple("●", colorGray, false)
        }
        statusSpinner.visibility = if (spinning) android.view.View.VISIBLE else android.view.View.GONE
        statusIcon.visibility = if (spinning) android.view.View.GONE else android.view.View.VISIBLE
        if (icon != null) statusIcon.text = icon
        statusIcon.setTextColor(color)
        statusView.setTextColor(
            when (state) {
                TunnelService.STATE_CONNECTED -> colorGreen
                TunnelService.STATE_ERROR, TunnelService.STATE_STOPPED -> colorRed
                TunnelService.STATE_CONNECTING, TunnelService.STATE_RETRY -> colorYellow
                else -> baseStatusColor
            }
        )
    }

    private fun currentTextColor(): Int = statusView.currentTextColor

    // ---------- сеть телефона (IP/страна/оператор) ----------

    private fun refreshNetInfoAsync() {
        Thread {
            val info: NetInfo? = try {
                NetInfoFetcher.fetch()
            } catch (_: Exception) {
                null
            }
            runOnUiThread {
                if (info == null) {
                    netFlag.visibility = android.view.View.GONE
                    netInfoView.setText(R.string.netinfo_failed)
                    return@runOnUiThread
                }
                val flag = info.flagEmoji() ?: NetInfoFetcher.emojiOf(info.countryCode)
                if (flag.isNullOrEmpty()) {
                    netFlag.visibility = android.view.View.GONE
                } else {
                    netFlag.text = flag
                    netFlag.visibility = android.view.View.VISIBLE
                }
                netInfoView.text = buildString {
                    append(getString(R.string.netinfo_ip, info.ip))
                    info.country?.let { c ->
                        append(" · ").append(c)
                        info.countryCode?.let { cc -> append(" (").append(cc).append(")") }
                    }
                    info.isp?.let { append(" · ").append(it) }
                }
            }
        }.apply { isDaemon = true }.start()
    }

    // ---------- формат скорости ----------

    /** «12,3 КБ/с» / «1,2 МБ/с» — компактный формат для графика. */
    private fun fmtRate(bytesPerSec: Long): String {
        val b = bytesPerSec.coerceAtLeast(0)
        return when {
            b >= 1 shl 20 -> getString(R.string.rate_mb, b / (1024f * 1024f))
            b >= 1 shl 10 -> getString(R.string.rate_kb, b / 1024f)
            else -> getString(R.string.rate_b, b)
        }
    }

    // ---------- файлы конфига (SAF, API 19+) ----------

    private fun writeConfigToFile(uri: Uri) {
        try {
            val raw = configView.text.toString().trim()
            RrpUri.parse(raw) // не экспортируем мусор
            contentResolver.openOutputStream(uri)?.use { out ->
                out.write(raw.toByteArray(Charsets.UTF_8))
                out.flush()
            }
            Toast.makeText(this, R.string.config_saved, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.file_error, e.message ?: ""), Toast.LENGTH_LONG).show()
        }
    }

    private fun readConfigFromFile(uri: Uri) {
        try {
            val text = contentResolver.openInputStream(uri)?.use { input ->
                input.readBytes().toString(Charsets.UTF_8).trim()
            } ?: ""
            val cfg = RrpUri.parse(text)
            configView.setText(cfg.serialize())
            prefs().edit().putString(TunnelService.KEY_CONFIG, cfg.serialize()).apply()
            Toast.makeText(this, R.string.config_imported, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
        }
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
            .setNegativeButton(R.string.logs_share) { _, _ ->
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, logText)
                    putExtra(Intent.EXTRA_SUBJECT, "ReverseRay log")
                }
                try {
                    startActivity(Intent.createChooser(send, getString(R.string.logs_share)))
                } catch (_: Exception) {}
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

    private companion object {
        const val NETINFO_REFRESH_MS = 60_000L
    }
}
