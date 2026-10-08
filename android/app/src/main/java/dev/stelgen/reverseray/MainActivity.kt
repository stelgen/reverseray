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
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.activity.result.contract.ActivityResultContracts
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.shape.ShapeAppearanceModel
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.tabs.TabLayout
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.net.NetInfo
import dev.stelgen.reverseray.net.NetInfoFetcher
import dev.stelgen.reverseray.service.TunnelService
import dev.stelgen.reverseray.ui.TrafficGraphView
import dev.stelgen.reverseray.update.UpdateChecker
import dev.stelgen.reverseray.update.UpdateInfo
import dev.stelgen.reverseray.update.UpdateLogger
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * ReverseRay v0.7.4 — Dashboard с четырьмя вкладками:
 *  1. Главная: большая круглая кнопка Старт/Стоп, окно трафика (скорость,
 *     пакеты «стрелками», внешний/локальный IP, страна/оператор), короткий лог.
 *  2. Связь: строка ссылки (бронепарсер чинит мусор сам), QR, файлы, смена протокола.
 *  3. Обновление: версия, авто-проверка раз в 24 ч, тех-лог обновления (для гиков).
 *  4. Настройки: инфо об устройстве (как в «О телефоне»), лимит трафика,
 *     только-Wi-Fi, цель PROBE, разрешить LAN.
 *
 * Вся разметка собирается кодом — один источник правды. Стиль: аккуратный
 * «девопс-терминал» — тёмные моно-окна логов на светлом Material-каркасе.
 */
class MainActivity : AppCompatActivity() {

    // ---------- вкладки ----------
    private lateinit var tabLayout: TabLayout
    private lateinit var pageHome: LinearLayout
    private lateinit var pageLink: LinearLayout
    private lateinit var pageUpdate: LinearLayout
    private lateinit var pageSettings: LinearLayout

    // ---------- главная ----------
    private lateinit var statusView: TextView
    private lateinit var statusIcon: TextView
    private lateinit var statusSpinner: android.widget.ProgressBar
    private lateinit var trafficGraph: TrafficGraphView
    private lateinit var trafficLabel: TextView
    private lateinit var packetsLabel: TextView
    private lateinit var netFlag: ImageView
    private lateinit var netInfoView: TextView
    private lateinit var localIpView: TextView
    private lateinit var miniLog: TextView
    private lateinit var bigButton: MaterialButton
    private lateinit var stopButton: MaterialButton
    private var bigButtonIsStart = true

    /** Строки «текущий протокол» живут на двух вкладках — обновляем все. */
    private val protoLineViews = mutableListOf<TextView>()
    /** Сводка лимита трафика — на главной и в настройках. */
    private val usageViews = mutableListOf<TextView>()

    // ---------- связь ----------
    private lateinit var configView: TextInputEditText

    // ---------- обновление ----------
    private lateinit var updateLog: TextView
    private lateinit var versionView: TextView

    // ---------- настройки ----------
    private lateinit var deviceInfoBox: LinearLayout
    private lateinit var usageSummaryView: TextView

    private val uiHandler = Handler(Looper.getMainLooper())
    private val netInfoRunnable = object : Runnable {
        override fun run() {
            refreshNetInfoAsync()
            uiHandler.postDelayed(this, NETINFO_REFRESH_MS)
        }
    }

    private var lastExternalIp: String? = null

    /** zxing-embedded требует API 19+ (overrideLibrary в манифесте). */
    private val qrSupported: Boolean get() = Build.VERSION.SDK_INT >= 19

    /** SAF (файлы конфига) доступен с API 19. */
    private val fileIoSupported: Boolean get() = Build.VERSION.SDK_INT >= 19

    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val content = result.contents ?: return@registerForActivityResult
        try {
            val cfg = RrpUri.parse(content) // бронепарсер сам чинит мусор
            configView.setText(cfg.serialize())
            Toast.makeText(this, R.string.qr_imported, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
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
                    trafficLabel.text = getString(R.string.traffic_rates, fmtRate(rx), fmtRate(tx))
                    // строка «стрелок»: тип, последний размер, пакеты туда/сюда
                    val pkTx = intent.getLongExtra(TunnelService.EXTRA_PKT_TX_COUNT, 0L)
                    val pkRx = intent.getLongExtra(TunnelService.EXTRA_PKT_RX_COUNT, 0L)
                    val szTx = intent.getLongExtra(TunnelService.EXTRA_PKT_TX_SIZE, 0L)
                    val szRx = intent.getLongExtra(TunnelService.EXTRA_PKT_RX_SIZE, 0L)
                    val kind = intent.getStringExtra(TunnelService.EXTRA_PKT_KIND) ?: ""
                    packetsLabel.text = getString(
                        R.string.packets_line,
                        kind.ifEmpty { "TCP" },
                        fmtBytes(szTx), fmtBytes(szRx), pkTx, pkRx,
                    )
                    val used = intent.getLongExtra(TunnelService.EXTRA_USAGE_BYTES, 0L)
                    val limit = intent.getLongExtra(TunnelService.EXTRA_USAGE_LIMIT, 0L)
                    setUsageText(usageSummaryText(used, limit))
                }
                TunnelService.ACTION_STATUS -> {
                    intent.getStringExtra(TunnelService.EXTRA_STATUS)?.let { statusView.text = it }
                    val state = intent.getStringExtra(TunnelService.EXTRA_STATE) ?: TunnelService.STATE_INFO
                    applyStatusVisual(state)
                    when (state) {
                        TunnelService.STATE_STOPPED, TunnelService.STATE_ERROR -> {
                            trafficGraph.reset()
                            trafficLabel.setText(R.string.traffic_idle)
                            packetsLabel.text = ""
                        }
                        TunnelService.STATE_CONNECTED, TunnelService.STATE_RETRY -> {
                            intent.getStringExtra(TunnelService.EXTRA_PROTO)?.let { p ->
                                setProtoText(getString(R.string.proto_current, p))
                            }
                            setRunningUi(true)
                        }
                        TunnelService.STATE_PROTO_ROLLBACK -> {
                            intent.getStringExtra(TunnelService.EXTRA_PROTO)?.let { old ->
                                setProtoText(getString(R.string.proto_current, old))
                                Toast.makeText(this@MainActivity, R.string.proto_rollback_toast, Toast.LENGTH_LONG).show()
                            }
                        }
                        TunnelService.STATE_STOPPED -> setRunningUi(false)
                    }
                    refreshMiniLog()
                }
                else -> {}
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        buildUi()
        statusView.text = TunnelService.lastStatus.ifEmpty { getString(R.string.status_idle) }
        refreshMiniLog()
        refreshVersionRow()
        refreshDevicePanel()
        refreshUsageSummary()
        maybeAutoCheckUpdate()
    }

    override fun onStart() {
        super.onStart()
        uiHandler.post(netInfoRunnable)
        val filter = IntentFilter().apply {
            addAction(TunnelService.ACTION_STATUS)
            addAction(TunnelService.ACTION_STATS)
        }
        if (Build.VERSION.SDK_INT >= 34) {
            ContextCompat.registerReceiver(this, statusReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        } else {
            @SuppressLint("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusReceiver, filter)
        }
    }

    override fun onStop() {
        super.onStop()
        uiHandler.removeCallbacks(netInfoRunnable)
        try { unregisterReceiver(statusReceiver) } catch (_: Exception) {}
    }

    // ================================================================= UI

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun buildUi() {
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        // Вкладки
        tabLayout = TabLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            addTab(newTab().setText(R.string.tab_home))
            addTab(newTab().setText(R.string.tab_link))
            addTab(newTab().setText(R.string.tab_update))
            addTab(newTab().setText(R.string.tab_settings))
            addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
                override fun onTabSelected(tab: TabLayout.Tab) { showPage(tab.position) }
                override fun onTabUnselected(tab: TabLayout.Tab) {}
                override fun onTabReselected(tab: TabLayout.Tab) {}
            })
        }
        root.addView(tabLayout)

        val pages = android.widget.FrameLayout(this)
        pageHome = buildHomePage()
        pageLink = buildLinkPage()
        pageUpdate = buildUpdatePage()
        pageSettings = buildSettingsPage()
        listOf(pageHome, pageLink, pageUpdate, pageSettings).forEach {
            it.visibility = View.GONE
            pages.addView(it)
        }
        pageHome.visibility = View.VISIBLE
        root.addView(
            pages,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f,
            ),
        )
        setContentView(root)
        showPage(0)
    }

    private fun showPage(index: Int) {
        listOf(pageHome, pageLink, pageUpdate, pageSettings).forEachIndexed { i, p ->
            p.visibility = if (i == index) View.VISIBLE else View.GONE
        }
        if (index == 3) { refreshDevicePanel(); refreshUsageSummary() }
        if (index == 2) { refreshVersionRow(); refreshUpdateLog() }
        if (index == 1) refreshProtoLine()
    }

    private fun page(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(12), dp(16), dp(16))
    }

    private fun card(content: LinearLayout): MaterialCardView = MaterialCardView(this).apply {
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { setMargins(0, dp(12), 0, dp(12)) }
        radius = dp(16).toFloat()
        cardElevation = dp(2).toFloat()
        addView(content.apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        })
    }

    /** Моно-окно лога в стиле «девопс-терминала»: тёмный фон, зелёный текст. */
    private fun terminalView(heightDp: Int): TextView = TextView(this).apply {
        typeface = Typeface.MONOSPACE
        textSize = 12f
        setTextColor(0xFF8BD17C.toInt())
        setBackgroundColor(0xFF0B1020.toInt())
        setPadding(dp(12), dp(10), dp(12), dp(10))
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(heightDp),
        )
        setTextIsSelectable(true)
    }

    private fun row(vararg buttons: MaterialButton): LinearLayout {
        val l = LinearLayout(this).apply {
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
        return l
    }

    // ---------- Вкладка 1: Главная ----------

    private fun buildHomePage(): LinearLayout {
        val p = page()

        p.addView(ImageView(this).apply {
            setImageResource(R.mipmap.ic_launcher)
            layoutParams = LinearLayout.LayoutParams(dp(64), dp(64)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                setMargins(0, dp(4), 0, dp(2))
            }
            contentDescription = getString(R.string.app_name)
        })
        p.addView(TextView(this).apply {
            setText(R.string.app_name)
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER_HORIZONTAL
        })

        // Большая круглая кнопка Старт/Стоп
        bigButton = MaterialButton(this).apply {
            setText(R.string.btn_start_short)
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
            shapeAppearanceModel = ShapeAppearanceModel.builder()
                .setAllCornerSizes(dp(110).toFloat()).build()
            layoutParams = LinearLayout.LayoutParams(dp(200), dp(200)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                setMargins(0, dp(14), 0, dp(8))
            }
            setOnClickListener {
                if (bigButtonIsStart) startTunnel() else stopTunnel()
            }
        }
        p.addView(bigButton)
        stopButton = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(R.string.btn_stop)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { setMargins(0, dp(2), 0, dp(4)) }
            setOnClickListener { stopTunnel() }
        }
        p.addView(stopButton)

        // Карточка трафика
        val inner = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val statusRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = dp(40)
        }
        statusSpinner = android.widget.ProgressBar(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(22), dp(22)).apply { setMargins(0, 0, dp(10), 0) }
            isIndeterminate = true
            indeterminateTintList = android.content.res.ColorStateList.valueOf(0xFFF9A825.toInt())
            visibility = View.GONE
        }
        statusRow.addView(statusSpinner)
        statusIcon = TextView(this).apply {
            textSize = 18f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, 0, dp(10), 0)
        }
        statusRow.addView(statusIcon)
        statusView = TextView(this).apply {
            setText(R.string.status_idle)
            maxLines = 3
        }
        baseStatusColor = currentTextColor()
        statusRow.addView(statusView)
        inner.addView(statusRow)

        trafficGraph = TrafficGraphView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(96),
            ).apply { setMargins(0, dp(8), 0, dp(2)) }
        }
        inner.addView(trafficGraph)
        trafficLabel = TextView(this).apply {
            setText(R.string.traffic_idle)
            textSize = 12f
            setPadding(0, dp(2), 0, 0)
        }
        inner.addView(trafficLabel)
        packetsLabel = TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(2), 0, 0)
            setTextColor(0xFF6B7280.toInt())
        }
        inner.addView(packetsLabel)

        // Сеть телефона: флаг + внешний IP/страна/оператор + локальный IP
        val netRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(6), 0, 0)
        }
        netFlag = ImageView(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(22), dp(15)).apply { setMargins(0, 0, dp(6), 0) }
            scaleType = ImageView.ScaleType.FIT_CENTER
            visibility = View.GONE
        }
        netRow.addView(netFlag)
        netInfoView = TextView(this).apply {
            setText(R.string.netinfo_loading)
            textSize = 12f
        }
        netRow.addView(netInfoView)
        inner.addView(netRow)
        localIpView = TextView(this).apply {
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
        }
        inner.addView(localIpView)
        protoLineViews.add(TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(2), 0, 0)
        })
        inner.addView(protoLineViews.last())
        p.addView(card(inner))

        // Короткий лог подключения — тоже «терминал»
        p.addView(TextView(this).apply {
            setText(R.string.logs_title)
            textSize = 13f
            setTypeface(typeface, Typeface.BOLD)
        })
        miniLog = terminalView(150)
        p.addView(miniLog)

        usageViews.add(TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(8), 0, 0)
            setTextColor(0xFF6B7280.toInt())
        })
        p.addView(usageViews.last())
        return p
    }

    // ---------- Вкладка 2: Связь ----------

    private fun buildLinkPage(): LinearLayout {
        val p = page()
        p.addView(TextView(this).apply {
            setText(R.string.link_tab_hint)
            textSize = 13f
            setPadding(0, dp(4), 0, dp(4))
        })
        val layout = TextInputLayout(this).apply {
            hint = getString(R.string.config_hint)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { setMargins(0, dp(8), 0, dp(8)) }
        }
        configView = TextInputEditText(this).apply {
            setText(prefs().getString(TunnelService.KEY_CONFIG, ""))
            minLines = 2
            minHeight = dp(88)
        }
        layout.addView(configView)
        p.addView(layout)

        val bFix = outlined(R.string.link_fix)
        bFix.setOnClickListener {
            try {
                val cfg = RrpUri.parse(configView.text.toString())
                configView.setText(cfg.serialize())
                Toast.makeText(this, getString(R.string.link_fixed, cfg.host), Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
            }
        }
        val bScan = outlined(R.string.qr_scan)
        bScan.setOnClickListener { launchScan() }
        val bShow = outlined(R.string.qr_show)
        bShow.setOnClickListener { showQr() }
        p.addView(if (qrSupported) row(bFix, bScan) else row(bFix, bShow))
        p.addView(row(bShow))

        if (fileIoSupported) {
            p.addView(
                row(
                    outlined(R.string.export_config).also {
                        it.setOnClickListener { exportFileLauncher.launch("reverseray-config.txt") }
                    },
                    outlined(R.string.import_config).also {
                        it.setOnClickListener {
                            try {
                                importFileLauncher.launch(arrayOf("text/*", "application/octet-stream"))
                            } catch (e: ActivityNotFoundException) {
                                Toast.makeText(this, R.string.file_error_no_picker, Toast.LENGTH_SHORT).show()
                            }
                        }
                    },
                )
            )
        }

        // Протоколы
        val protoCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        protoCard.addView(TextView(this).apply {
            setText(R.string.proto_section)
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
        })
        protoLineViews.add(TextView(this).apply {
            textSize = 13f
            setPadding(0, dp(4), 0, dp(4))
            setText(R.string.proto_unknown)
        })
        protoCard.addView(protoLineViews.last())
        protoCard.addView(outlined(R.string.proto_switch).apply {
            setOnClickListener { showProtocolPicker() }
        })
        p.addView(card(protoCard))
        return p
    }

    // ---------- Вкладка 3: Обновление ----------

    private fun buildUpdatePage(): LinearLayout {
        val p = page()
        versionView = TextView(this).apply {
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(4), 0, dp(4))
        }
        p.addView(versionView)

        val autoSwitch = SwitchMaterial(this).apply {
            setText(R.string.update_auto)
            isChecked = prefs().getBoolean(TunnelService.KEY_AUTO_UPDATE, true)
            setOnCheckedChangeListener { _, checked ->
                val old = prefs().getBoolean(TunnelService.KEY_AUTO_UPDATE, true)
                if (old != checked) {
                    prefs().edit().putBoolean(TunnelService.KEY_AUTO_UPDATE, checked).apply()
                    TunnelService.logSettingChange(getString(R.string.set_auto_update), old.toString(), checked.toString())
                    refreshMiniLog()
                }
            }
        }
        p.addView(autoSwitch)

        p.addView(
            row(
                filled(R.string.update_check).apply {
                    setOnClickListener { checkForUpdateAsync(showIfUpToDate = true) }
                },
            )
        )
        p.addView(TextView(this).apply {
            setText(R.string.update_log_hint)
            textSize = 13f
            setPadding(0, dp(4), 0, dp(4))
        })
        updateLog = terminalView(260)
        p.addView(updateLog)

        val share = outlined(R.string.logs_copy)
        share.setOnClickListener { copyUpdateLog() }
        p.addView(row(share))
        return p
    }

    // ---------- Вкладка 4: Настройки ----------

    private fun buildSettingsPage(): LinearLayout {
        val p = page()

        // «О телефоне»-панель
        p.addView(TextView(this).apply {
            setText(R.string.settings_device)
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
        })
        deviceInfoBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        p.addView(card(deviceInfoBox))

        // Только Wi-Fi
        p.addView(card(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(SwitchMaterial(this@MainActivity).apply {
                setText(R.string.set_wifi_only)
                isChecked = prefs().getBoolean(TunnelService.KEY_WIFI_ONLY, false)
                setOnCheckedChangeListener { _, checked ->
                    val old = prefs().getBoolean(TunnelService.KEY_WIFI_ONLY, false)
                    if (old != checked) {
                        prefs().edit().putBoolean(TunnelService.KEY_WIFI_ONLY, checked).apply()
                        TunnelService.logSettingChange(getString(R.string.set_wifi_only), old.toString(), checked.toString())
                        refreshMiniLog()
                    }
                }
            })
        }))

        // Разрешить LAN
        p.addView(card(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(SwitchMaterial(this@MainActivity).apply {
                setText(R.string.set_allow_lan)
                isChecked = prefs().getBoolean(TunnelService.KEY_ALLOW_LAN, false)
                setOnCheckedChangeListener { _, checked ->
                    val old = prefs().getBoolean(TunnelService.KEY_ALLOW_LAN, false)
                    if (old != checked) {
                        prefs().edit().putBoolean(TunnelService.KEY_ALLOW_LAN, checked).apply()
                        TunnelService.logSettingChange(getString(R.string.set_allow_lan), old.toString(), checked.toString())
                        refreshMiniLog()
                    }
                }
            })
        }))

        // Лимит трафика
        val lim = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        lim.addView(TextView(this).apply {
            setText(R.string.set_limit_title)
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
        })
        usageViews.add(TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(4), 0, dp(4))
            setTextColor(0xFF6B7280.toInt())
        })
        lim.addView(usageViews.last())
        val limitSwitch = SwitchMaterial(this).apply {
            setText(R.string.set_limit_switch)
            isChecked = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L) > 0
        }
        lim.addView(limitSwitch)
        val limitEdit = EditText(this).apply {
            hint = getString(R.string.set_limit_gb_hint)
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL
            setText(limitGb())
            textSize = 14f
        }
        lim.addView(limitEdit)
        val periodEdit = EditText(this).apply {
            hint = getString(R.string.set_limit_period_hint)
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(prefs().getInt(TunnelService.KEY_LIMIT_RESET_DAY, 1).toString())
            textSize = 14f
        }
        lim.addView(periodEdit)
        lim.addView(
            row(
                filled(R.string.set_limit_apply).apply {
                    setOnClickListener {
                        val oldLimit = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
                        val oldPeriod = prefs().getString(TunnelService.KEY_LIMIT_PERIOD, TunnelService.PERIOD_DAY)
                        val oldDay = prefs().getInt(TunnelService.KEY_LIMIT_RESET_DAY, 1)
                        val on = limitSwitch.isChecked
                        val gb = limitEdit.text.toString().replace(',', '.').toDoubleOrNull()
                        if (on && (gb == null || gb <= 0)) {
                            Toast.makeText(this@MainActivity, R.string.set_limit_bad_value, Toast.LENGTH_SHORT).show()
                            return@setOnClickListener
                        }
                        val bytes = if (on) (gb!! * 1024 * 1024 * 1024).toLong() else 0L
                        val period = if (bytes > 0) TunnelService.PERIOD_MONTH else TunnelService.PERIOD_DAY
                        val day = (periodEdit.text.toString().toIntOrNull() ?: 1).coerceIn(1, 28)
                        prefs().edit()
                            .putLong(TunnelService.KEY_TRAFFIC_LIMIT, bytes)
                            .putString(TunnelService.KEY_LIMIT_PERIOD, period)
                            .putInt(TunnelService.KEY_LIMIT_RESET_DAY, day)
                            .apply()
                        TunnelService.logSettingChange(
                            getString(R.string.set_limit_title),
                            describeLimit(oldLimit, oldPeriod ?: TunnelService.PERIOD_DAY, oldDay),
                            describeLimit(bytes, period, day),
                        )
                        refreshMiniLog(); refreshUsageSummary()
                        Toast.makeText(this@MainActivity, R.string.set_limit_applied, Toast.LENGTH_SHORT).show()
                    }
                },
                outlined(R.string.set_limit_reset).apply {
                    setOnClickListener {
                        prefs().edit().putLong(TunnelService.KEY_TRAFFIC_USED, 0L).apply()
                        TunnelService.logSettingChange(
                            getString(R.string.set_limit_counter),
                            usageViews.firstOrNull()?.text.toString(), "0",
                        )
                        refreshUsageSummary()
                        Toast.makeText(this@MainActivity, R.string.set_limit_reset_done, Toast.LENGTH_SHORT).show()
                    }
                },
            )
        )
        p.addView(card(lim))

        // PROBE-цель
        val probe = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        probe.addView(TextView(this).apply {
            setText(R.string.set_probe_title)
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
        })
        probe.addView(TextView(this).apply {
            setText(R.string.set_probe_hint)
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
        })
        val probeEdit = EditText(this).apply {
            inputType = InputType.TYPE_TEXT_VARIATION_URI
            setText(prefs().getString(TunnelService.KEY_PROBE_TARGET, TunnelService.DEFAULT_PROBE_TARGET))
            textSize = 14f
            setSingleLine(true)
        }
        probe.addView(probeEdit)
        probe.addView(filled(R.string.set_probe_apply).apply {
            setOnClickListener {
                val raw = probeEdit.text.toString().trim()
                val host = raw.substringBeforeLast(':')
                val port = raw.substringAfterLast(':', "").toIntOrNull()
                if (host.isEmpty() || port == null || port !in 1..65535) {
                    Toast.makeText(this@MainActivity, R.string.set_probe_bad, Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                val old = prefs().getString(TunnelService.KEY_PROBE_TARGET, TunnelService.DEFAULT_PROBE_TARGET) ?: ""
                val norm = "$host:$port"
                prefs().edit().putString(TunnelService.KEY_PROBE_TARGET, norm).apply()
                TunnelService.logSettingChange(getString(R.string.set_probe_title), old, norm)
                refreshMiniLog()
            }
        })
        p.addView(card(probe))
        return p
    }

    private fun outlined(textRes: Int) =
        MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(textRes)
        }

    private fun filled(textRes: Int) = MaterialButton(this).apply { setText(textRes) }

    private fun describeLimit(bytes: Long, period: String, day: Int): String {
        if (bytes <= 0) return "без ограничений"
        val p = if (period == TunnelService.PERIOD_MONTH) "месяц (сброс $day)" else "сутки"
        return "${fmtBytes(bytes)}/$p"
    }

    private fun limitGb(): String {
        val l = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
        return if (l <= 0) "10" else String.format(Locale.US, "%.0f", l / 1024.0 / 1024.0 / 1024.0)
    }

    // ================================================================= Действия

    private fun startTunnel() {
        val raw = configView.text.toString()
        val cfg = try {
            RrpUri.parse(raw) // бронепарсер чинит мусор; по итогу — канонический вид
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
            return
        }
        // сохраняем нормализованную ссылку (proto= всегда явный)
        configView.setText(cfg.serialize())
        prefs().edit().putString(TunnelService.KEY_CONFIG, cfg.serialize()).apply()
        val i = Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_START)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
        setRunningUi(true)
    }

    private fun stopTunnel() {
        startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_STOP))
        setRunningUi(false)
    }

    private fun setRunningUi(running: Boolean) {
        bigButtonIsStart = !running
        if (running) {
            bigButton.setText(R.string.btn_stop_short)
            bigButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFFC62828.toInt())
        } else {
            bigButton.setText(R.string.btn_start_short)
            bigButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF2E7D32.toInt())
        }
    }

    private fun showProtocolPicker() {
        val ids = RrpProtocols.displayList()
        if (ids.isEmpty()) {
            Toast.makeText(this, R.string.proto_unknown, Toast.LENGTH_SHORT).show()
            return
        }
        val current = try {
            RrpUri.parse(prefs().getString(TunnelService.KEY_CONFIG, "") ?: "").proto
        } catch (_: Exception) {
            RrpProtocols.DEFAULT
        }
        val names = ids.map { RrpProtocols.displayName(it) }.toTypedArray()
        val checked = ids.indexOfFirst { it == current }.coerceAtLeast(0)
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.proto_switch)
            .setSingleChoiceItems(names, checked) { dialog, which ->
                dialog.dismiss()
                val picked = ids[which]
                if (picked != current) requestProtoSwitch(picked)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun requestProtoSwitch(proto: String) {
        setProtoText(getString(R.string.proto_switching, proto))
        statusView.text = getString(R.string.status_switch_trying, proto)
        applyStatusVisual(TunnelService.STATE_CONNECTING)
        val i = Intent(this, TunnelService::class.java)
            .setAction(TunnelService.ACTION_SWITCH_PROTO)
            .putExtra(TunnelService.EXTRA_PROTO, proto)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
    }

    // ================================================================= Сеть/статус

    private val colorGreen = 0xFF2E7D32.toInt()
    private val colorYellow = 0xFFF9A825.toInt()
    private val colorRed = 0xFFC62828.toInt()
    private val colorGray = 0xFF8A8F98.toInt()
    private var baseStatusColor = 0xFF212121.toInt()

    private fun applyStatusVisual(state: String) {
        val (icon: String?, color: Int, spinning: Boolean) = when (state) {
            TunnelService.STATE_CONNECTED -> Triple("✓", colorGreen, false)
            TunnelService.STATE_CONNECTING, TunnelService.STATE_RETRY -> Triple("", colorYellow, true)
            TunnelService.STATE_ERROR -> Triple("✕", colorRed, false)
            TunnelService.STATE_STOPPED -> Triple("✕", colorRed, false)
            else -> Triple("●", colorGray, false)
        }
        statusSpinner.visibility = if (spinning) View.VISIBLE else View.GONE
        statusIcon.visibility = if (spinning) View.GONE else View.VISIBLE
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

    private fun refreshMiniLog() {
        val lines = TunnelService.snapshotLogs().take(40)
        miniLog.text = lines.joinToString("\n").ifEmpty { getString(R.string.logs_empty) }
    }

    private fun refreshUpdateLog() {
        updateLog.text = UpdateLogger.snapshot().joinToString("\n").ifEmpty { getString(R.string.update_log_empty) }
    }

    private fun copyUpdateLog() {
        val text = UpdateLogger.snapshot().joinToString("\n").ifEmpty { getString(R.string.update_log_empty) }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("ReverseRay update log", text))
        Toast.makeText(this, R.string.logs_copied, Toast.LENGTH_SHORT).show()
    }

    private fun usageSummaryText(used: Long, limit: Long): String {
        val usedStr = fmtBytes(used)
        return if (limit > 0) {
            val pct = (used * 100 / limit).coerceAtMost(999)
            getString(R.string.usage_with_limit, usedStr, fmtBytes(limit), pct)
        } else {
            getString(R.string.usage_no_limit, usedStr)
        }
    }

    private fun refreshUsageSummary() {
        val p = prefs()
        val used = p.getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
        val limit = p.getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
        setUsageText(usageSummaryText(used, limit))
    }

    /** Обновляет все сводные строки лимита (главная + настройки). */
    private fun setUsageText(text: String) {
        usageViews.forEach { it.text = text }
    }

    /** Обновляет все строки «текущий протокол» (главная + связь). */
    private fun setProtoText(text: String) {
        protoLineViews.forEach { it.text = text }
    }

    /** Внешний IP/страна/оператор + локальный IP. */
    private fun refreshNetInfoAsync() {
        Thread {
            val info: NetInfo? = try {
                NetInfoFetcher.fetch()
            } catch (_: Exception) {
                null
            }
            val local = TunnelService.localIp()
            runOnUiThread {
                if (info == null) {
                    netFlag.visibility = View.GONE
                    netInfoView.setText(R.string.netinfo_failed)
                } else {
                    lastExternalIp = info.ip
                    val cc = info.countryCode
                    val drawableId = if (cc != null && cc.length == 2)
                        resources.getIdentifier("flag_" + cc.lowercase(), "drawable", packageName) else 0
                    if (drawableId != 0) {
                        netFlag.setImageResource(drawableId)
                        netFlag.visibility = View.VISIBLE
                    } else {
                        netFlag.visibility = View.GONE
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
                localIpView.text = getString(R.string.local_ip, local ?: "—")
            }
        }.apply { isDaemon = true }.start()
    }

    // ================================================================= Формат

    private fun fmtRate(bytesPerSec: Long): String {
        val b = bytesPerSec.coerceAtLeast(0)
        return when {
            b >= 1 shl 20 -> getString(R.string.rate_mb, b / (1024f * 1024f))
            b >= 1 shl 10 -> getString(R.string.rate_kb, b / 1024f)
            else -> getString(R.string.rate_b, b)
        }
    }

    private fun fmtBytes(b: Long): String = when {
        b >= 1L shl 30 -> String.format(Locale.US, "%.2f ГБ", b / 1073741824.0)
        b >= 1L shl 20 -> String.format(Locale.US, "%.1f МБ", b / 1048576.0)
        b >= 1L shl 10 -> String.format(Locale.US, "%.1f КБ", b / 1024.0)
        else -> "$b Б"
    }

    // ================================================================= Файлы

    private fun writeConfigToFile(uri: Uri) {
        try {
            val raw = configView.text.toString().trim()
            val cfg = RrpUri.parse(raw) // не экспортируем мусор
            contentResolver.openOutputStream(uri)?.use { out ->
                out.write(cfg.serialize().toByteArray(Charsets.UTF_8))
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
                input.readBytes().toString(Charsets.UTF_8)
            } ?: ""
            val cfg = RrpUri.parse(text) // чинит мусор сам
            configView.setText(cfg.serialize())
            prefs().edit().putString(TunnelService.KEY_CONFIG, cfg.serialize()).apply()
            Toast.makeText(this, R.string.config_imported, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
        }
    }

    // ================================================================= QR

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
        val raw = try {
            RrpUri.parse(configView.text.toString()).serialize() // QR всегда канонический
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
        dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
    }

    // ================================================================= Обновление

    private fun currentVersion(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: ""
    } catch (_: Exception) {
        ""
    }

    private fun refreshVersionRow() {
        val code = try {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0).versionCode
        } catch (_: Exception) {
            0
        }
        versionView.text = getString(R.string.version_row, currentVersion(), code)
    }

    private fun refreshProtoLine() {
        val current = try {
            RrpUri.parse(prefs().getString(TunnelService.KEY_CONFIG, "") ?: "").proto
        } catch (_: Exception) {
            RrpProtocols.DEFAULT
        }
        val known = RrpProtocols.serverProtocols()
        setProtoText(
            if (known.isEmpty()) {
                getString(R.string.proto_current, current)
            } else {
                getString(R.string.proto_current_list, current, known.joinToString(", "))
            }
        )
    }

    /** Автопроверка обновлений раз в 24 ч (вкл. по умолчанию, закрываемое окно). */
    private fun maybeAutoCheckUpdate() {
        val p = prefs()
        if (!p.getBoolean(TunnelService.KEY_AUTO_UPDATE, true)) return
        val last = p.getLong(KEY_LAST_UPDATE_CHECK, 0L)
        val now = System.currentTimeMillis()
        if (now - last < UPDATE_CHECK_INTERVAL_MS) return
        p.edit().putLong(KEY_LAST_UPDATE_CHECK, now).apply()
        checkForUpdateAsync(showIfUpToDate = false)
    }

    private fun checkForUpdateAsync(showIfUpToDate: Boolean) {
        val current = currentVersion()
        UpdateLogger.add("проверка обновлений: текущая версия $current")
        Thread {
            val info = UpdateChecker().check(current)
            if (info == null) {
                UpdateLogger.add("обновлений нет (или GitHub недоступен)")
                if (showIfUpToDate) {
                    runOnUiThread { Toast.makeText(this, R.string.update_latest, Toast.LENGTH_SHORT).show() }
                }
                return@Thread
            }
            UpdateLogger.add("доступно: ${info.latestTag} → ${info.apkUrl.substringAfterLast('/')}")
            runOnUiThread {
                refreshUpdateLog()
                MaterialAlertDialogBuilder(this)
                    .setTitle(getString(R.string.update_title, info.latestTag))
                    .setMessage(getString(R.string.update_question))
                    .setPositiveButton(R.string.update_download) { _, _ -> downloadUpdate(info) }
                    .setNegativeButton(android.R.string.cancel, null) // окно закрывается
                    .show()
            }
        }.apply { isDaemon = true }.start()
    }

    private fun downloadUpdate(info: UpdateInfo) {
        val dir = File(cacheDir, "apk").apply { mkdirs() }
        val dest = File(dir, "update-${info.latestTag}.apk")
        val status = Toast.makeText(this, R.string.update_downloading, Toast.LENGTH_LONG)
        status.show()
        val started = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        UpdateLogger.add("[$started] скачивание ${info.latestTag}…")
        Thread {
            try {
                UpdateChecker().downloadApk(info, dest)
                UpdateLogger.add("скачано: ${dest.name} (${fmtBytes(dest.length())}) → установка")
                runOnUiThread {
                    status.cancel()
                    refreshUpdateLog()
                    installApk(dest)
                }
            } catch (e: Exception) {
                UpdateLogger.add("ошибка скачивания: ${e.message}")
                runOnUiThread {
                    status.cancel()
                    refreshUpdateLog()
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
            UpdateLogger.add("установка не начата: нет установщика APK")
            Toast.makeText(this, R.string.update_error, Toast.LENGTH_SHORT).show()
        }
    }

    // ================================================================= Устройство

    /** Панель «О системе» — как в стоковых настройках Android. */
    private fun refreshDevicePanel() {
        deviceInfoBox.removeAllViews()
        fun rowOf(k: String, v: String) {
            val l = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, dp(4), 0, dp(4))
            }
            l.addView(TextView(this).apply {
                text = k
                textSize = 13f
                setTextColor(0xFF6B7280.toInt())
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.45f)
            })
            l.addView(TextView(this).apply {
                text = v
                textSize = 13f
                setTypeface(typeface, Typeface.BOLD)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.55f)
            })
            deviceInfoBox.addView(l)
        }
        val kernel = try { System.getProperty("os.version") ?: "—" } catch (_: Exception) { "—" }
        val abis = try { Build.SUPPORTED_ABIS.firstOrNull() ?: "—" } catch (_: Exception) { "—" }
        val sec = try {
            if (Build.VERSION.SDK_INT >= 22) {
                @Suppress("DEPRECATION")
                Build.VERSION.SECURITY_PATCH
            } else {
                "—"
            }
        } catch (_: Throwable) {
            "—"
        }
        val m = resources.displayMetrics
        rowOf(getString(R.string.dev_model), "${Build.MANUFACTURER} ${Build.MODEL}")
        rowOf(getString(R.string.dev_android), "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        rowOf(getString(R.string.dev_build), Build.DISPLAY)
        rowOf(getString(R.string.dev_patch), sec)
        rowOf(getString(R.string.dev_kernel), kernel)
        rowOf(getString(R.string.dev_cpu), abis)
        rowOf(getString(R.string.dev_screen), "${m.widthPixels}×${m.heightPixels} @${m.density}x")
        val rt = Runtime.getRuntime()
        val mem = fmtBytes(rt.totalMemory() - rt.freeMemory())
        rowOf(getString(R.string.dev_mem), "${mem} / ${fmtBytes(rt.maxMemory())}")
        rowOf(getString(R.string.dev_version), "${currentVersion()} (${getString(R.string.app_name)})")
        deviceInfoBox.addView(
            Button(this).apply {
                setText(R.string.dev_copy)
                background = null
                setOnClickListener {
                    val sb = StringBuilder()
                    for (i in 0 until deviceInfoBox.childCount) {
                        val rowL = deviceInfoBox.getChildAt(i) as? LinearLayout ?: continue
                        if (rowL.childCount == 2) {
                            sb.append((rowL.getChildAt(0) as TextView).text).append(": ")
                                .append((rowL.getChildAt(1) as TextView).text).append('\n')
                        }
                    }
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("ReverseRay device", sb.toString()))
                    Toast.makeText(this@MainActivity, R.string.logs_copied, Toast.LENGTH_SHORT).show()
                }
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { gravity = Gravity.END }
            }
        )
    }

    // ================================================================= Разное

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
        const val UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val KEY_LAST_UPDATE_CHECK = "last_update_check"
    }
}