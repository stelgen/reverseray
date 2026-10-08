package dev.stelgen.reverseray

import android.Manifest
import android.annotation.SuppressLint
import android.app.ActivityManager
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
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
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
import dev.stelgen.reverseray.core.Modules
import dev.stelgen.reverseray.core.MtProto
import dev.stelgen.reverseray.core.ProtoFallback
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.SecurityFacts
import dev.stelgen.reverseray.core.ThemeMode
import dev.stelgen.reverseray.net.DnsProbe
import dev.stelgen.reverseray.net.NetInfo
import dev.stelgen.reverseray.net.NetInfoFetcher
import dev.stelgen.reverseray.service.LogKind
import dev.stelgen.reverseray.service.TunnelService
import dev.stelgen.reverseray.ui.StatusConsole
import dev.stelgen.reverseray.ui.TrafficGraphView
import dev.stelgen.reverseray.update.UpdateChecker
import dev.stelgen.reverseray.update.UpdateInfo
import dev.stelgen.reverseray.update.UpdateLogger
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/**
 * ReverseRay v0.8 — Dashboard с пятью вкладками:
 *  1. Главная: ОДНА круглая кнопка Старт/Стоп с пульсацией, окно трафика
 *     (скорость, пакеты, внешний/локальный IP, DNS, страна/оператор,
 *     спидтест), ЕДИНОЕ консольное окно статуса (листается, live-кнопка
 *     внутри бара, цветовые роли строк).
 *  2. Связь: ссылка с авто-починкой при вставке + Очистить (с
 *     подтверждением) + «Сохранено» зелёным + тост, QR, файлы, протоколы
 *     (в т.ч. mtproto2 из модулей), «Поделиться приложением» (ссылка/APK).
 *  3. Обновление: версия, авто-проверка 24 ч, модули без переустановки APK
 *     (тот же манифест, что у сервера), прогресс % и скорость.
 *  4. Лог: полный журнал сервиса в том же консольном окне + копирование
 *     всего лога и «Поделиться».
 *  5. Настройки: О приложении (версии/модули/RAM/диск/трафик за всё
 *     время/протокол), О устройстве (CPU/RAM/Android/SDK/Java), О сети
 *     (что приложение узнало — ВСЁ честно: DNS, реальный резолвер,
 *     DoT/DoH/DNSSEC/ECS/SNI), лимит трафика («лимит — король»),
 *     автоподключение (выкл по умолчанию), только-Wi-Fi, LAN, PROBE.
 *
 * Канон приватности: мы не прячем НИЧЕГО из того, что делаем с сетью и
 * данными пользователя — всё пишется в консоль и вкладку «О сети».
 *
 * Вся разметка собирается кодом — один источник правды. Совместимость:
 * Android 4.0+ (API 14) — без java.time, без новее-API вызовов вне guard.
 */
class MainActivity : AppCompatActivity() {

    // ---------- вкладки ----------
    private lateinit var tabLayout: TabLayout
    // v0.8.2: каждая вкладка — ScrollView (контент листается ВСЕГДА,
    // включая ландшафт и крупные шрифты — UX-канон скроллинга)
    private lateinit var pageHome: View
    private lateinit var pageLink: View
    private lateinit var pageUpdate: View
    private lateinit var pageLog: View
    private lateinit var pageSettings: View

    // ---------- главная ----------
    private lateinit var bigButton: MaterialButton
    private lateinit var pulseRing: View
    private var bigButtonIsStart = true
    private lateinit var trafficGraph: TrafficGraphView
    private lateinit var trafficLabel: TextView
    private lateinit var packetsLabel: TextView
    private lateinit var netFlag: ImageView
    private lateinit var netInfoView: TextView
    private lateinit var localIpView: TextView
    private lateinit var dnsLineView: TextView
    private lateinit var speedTestView: TextView
    private lateinit var homeConsole: StatusConsole

    /** Строки «текущий протокол» живут на двух вкладках — обновляем все. */
    private val protoLineViews = mutableListOf<TextView>()
    /** Сводка лимита трафика — на главной и в настройках. */
    private val usageViews = mutableListOf<TextView>()

    // ---------- связь ----------
    private lateinit var configView: TextInputEditText
    private lateinit var linkStatusView: TextView
    private var configEditDebounce = 0L

    // ---------- обновление ----------
    private lateinit var versionView: TextView
    private lateinit var modulesInfoView: TextView
    private lateinit var updateConsole: StatusConsole

    // ---------- лог ----------
    private lateinit var logConsole: StatusConsole

    // ---------- настройки ----------
    private lateinit var deviceInfoBox: LinearLayout
    private lateinit var appInfoBox: LinearLayout
    private lateinit var netInfoBox: LinearLayout
    private lateinit var usageSummaryView: TextView
    private lateinit var limitNextView: TextView

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
        applyPastedConfig(content, announce = true)
    }

    private val exportFileLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            if (uri != null) writeConfigToFile(uri)
        }

    private val importFileLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) readConfigFromFile(uri)
        }

    /** SAF-приёмник для «Поделиться APK» (пишем копию в выбранное место). */
    private val shareApkLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri ->
            if (uri != null) copyApkTo(uri)
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
                    intent.getStringExtra(TunnelService.EXTRA_SPEEDTEST_TEXT)?.let {
                        speedTestView.text = getString(R.string.speedtest_line, it)
                    }
                    val used = intent.getLongExtra(TunnelService.EXTRA_USAGE_BYTES, 0L)
                    val limit = intent.getLongExtra(TunnelService.EXTRA_USAGE_LIMIT, 0L)
                    setUsageText(usageSummaryText(used, limit))
                }
                TunnelService.ACTION_STATUS -> {
                    val state = intent.getStringExtra(TunnelService.EXTRA_STATE)
                        ?: TunnelService.STATE_INFO
                    intent.getStringExtra(TunnelService.EXTRA_STATUS)?.let { statusText ->
                        renderServiceLogs()
                        if (state == TunnelService.STATE_LIMIT_REACHED) {
                            showLimitDialog(statusText)
                        }
                    }
                    when (state) {
                        TunnelService.STATE_CONNECTED, TunnelService.STATE_RETRY -> {
                            intent.getStringExtra(TunnelService.EXTRA_PROTO)?.let { p ->
                                setProtoText(getString(R.string.proto_current, RrpProtocols.labelWithVer(p)))
                            }
                            setRunningUi(true)
                        }
                        TunnelService.STATE_PROTO_ROLLBACK -> {
                            intent.getStringExtra(TunnelService.EXTRA_PROTO)?.let { old ->
                                setProtoText(getString(R.string.proto_current, RrpProtocols.labelWithVer(old)))
                                Toast.makeText(
                                    this@MainActivity,
                                    R.string.proto_rollback_toast,
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                        }
                        TunnelService.STATE_STOPPED, TunnelService.STATE_ERROR -> setRunningUi(false)
                    }
                }
                else -> {}
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        // v0.8: применить сохранённые модули до сборки UI (реестр протоколов)
        loadCachedModules()
        buildUi()
        // v0.8.2: журнал обновлений льётся в консоль СРАЗУ (реалтайм),
        // а не только при перерендере вкладки
        UpdateLogger.onLine = { line ->
            runOnUiThread {
                updateConsole.append(
                    StatusConsole.Line(
                        line.text,
                        when (line.kind) {
                            LogKind.OK -> StatusConsole.Role.OK
                            LogKind.WARN -> StatusConsole.Role.WARN
                            LogKind.ERR -> StatusConsole.Role.ERR
                            else -> StatusConsole.Role.INFO
                        },
                    )
                )
            }
        }
        renderServiceLogs()
        refreshVersionRow()
        refreshAppPanel()
        refreshDevicePanel()
        refreshUsageSummary()
        refreshLimitNext()
        maybeAutoCheckUpdate()
        maybeAutoConnect()
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

        tabLayout = TabLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            // UX-канон: 5 вкладок — скроллируемые (текст не сжимается на узких
            // экранах), индикатор по ширине текста (современный M3-вид)
            tabMode = TabLayout.MODE_SCROLLABLE
            tabGravity = TabLayout.GRAVITY_START
            isTabIndicatorFullWidth = false
            addTab(newTab().setText(R.string.tab_home))
            addTab(newTab().setText(R.string.tab_link))
            addTab(newTab().setText(R.string.tab_update))
            addTab(newTab().setText(R.string.tab_log))
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
        pageLog = buildLogPage()
        pageSettings = buildSettingsPage()
        listOf(pageHome, pageLink, pageUpdate, pageLog, pageSettings).forEach {
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
        listOf(pageHome, pageLink, pageUpdate, pageLog, pageSettings).forEachIndexed { i, p ->
            p.visibility = if (i == index) View.VISIBLE else View.GONE
        }
        when (index) {
            2 -> { refreshVersionRow(); refreshModulesInfo(); refreshUpdateConsole() }
            3 -> renderServiceLogs()
            4 -> { refreshDevicePanel(); refreshAppPanel(); refreshNetPanel(); refreshUsageSummary(); refreshLimitNext() }
            1 -> refreshProtoLine()
        }
    }

    private fun page(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(12), dp(16), dp(16))
    }

    /**
     * v0.8.2 (UX-канон): оборачивает содержимое вкладки в ScrollView —
     * ЛЮБАЯ вкладка скроллится, когда контент не влезает (портрет/ландшафт,
     * крупные шрифты). fillViewport — фон тянется до низа без «рваных» краёв.
     */
    private fun scrollWrap(content: LinearLayout): View = android.widget.ScrollView(this).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = true
        addView(
            content,
            ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
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

    private fun sectionTitle(textRes: Int, hint: String? = null): LinearLayout {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        box.addView(TextView(this).apply {
            setText(textRes)
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
        })
        hint?.let {
            box.addView(TextView(this).apply {
                text = it
                textSize = 11f
                setTextColor(0xFF6B7280.toInt())
                setPadding(0, dp(2), 0, 0)
            })
        }
        return box
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

    private fun buildHomePage(): View {
        val p = page()

        p.addView(ImageView(this).apply {
            setImageResource(R.mipmap.ic_launcher)
            layoutParams = LinearLayout.LayoutParams(dp(56), dp(56)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                setMargins(0, dp(4), 0, dp(2))
            }
            contentDescription = getString(R.string.app_name)
        })
        p.addView(TextView(this).apply {
            setText(R.string.app_name)
            textSize = 20f
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER_HORIZONTAL
        })

        // ОДНА круглая кнопка Старт/Стоп (дубликат снизу убран — v0.8) с пульс-кольцом
        val buttonBox = android.widget.FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(216), dp(216)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                setMargins(0, dp(12), 0, dp(8))
            }
        }
        pulseRing = View(this).apply {
            layoutParams = android.widget.FrameLayout.LayoutParams(dp(216), dp(216)).apply {
                gravity = Gravity.CENTER
            }
            background = android.graphics.drawable.GradientDrawable().apply {
                shape = android.graphics.drawable.GradientDrawable.OVAL
                setStroke(dp(2), 0x6639D98A)
            }
            visibility = View.GONE
        }
        buttonBox.addView(pulseRing)
        bigButton = MaterialButton(this).apply {
            setText(R.string.btn_start_short)
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
            shapeAppearanceModel = ShapeAppearanceModel.builder()
                .setAllCornerSizes(dp(110).toFloat()).build()
            layoutParams = android.widget.FrameLayout.LayoutParams(dp(196), dp(196)).apply {
                gravity = Gravity.CENTER
            }
            setOnClickListener {
                if (bigButtonIsStart) startTunnel() else stopTunnel()
            }
        }
        buttonBox.addView(bigButton)
        p.addView(buttonBox)

        // Карточка трафика: шапка состояния как в консоли
        val inner = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        trafficGraph = TrafficGraphView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(84),
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
        dnsLineView = TextView(this).apply {
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
        }
        inner.addView(dnsLineView)
        speedTestView = TextView(this).apply {
            setText(R.string.speedtest_waiting)
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
        }
        inner.addView(speedTestView)
        protoLineViews.add(TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(2), 0, 0)
        })
        inner.addView(protoLineViews.last())
        p.addView(card(inner))

        // Единое консольное окно статуса (листается, live-кнопка в баре)
        homeConsole = StatusConsole(this).apply {
            setTitle(getString(R.string.console_title_service))
            setBodyHeight(210)
        }
        p.addView(homeConsole)

        usageViews.add(TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(8), 0, 0)
            setTextColor(0xFF6B7280.toInt())
        })
        p.addView(usageViews.last())
        return scrollWrap(p)
    }

    // ---------- Вкладка 2: Связь ----------

    private fun buildLinkPage(): View {
        val p = page()
        p.addView(TextView(this).apply {
            setText(R.string.link_tab_hint)
            textSize = 13f
            setPadding(0, dp(4), 0, dp(4))
        })

        // Окно ссылки в стиле «О устройстве»: статус + поле + Очистить.
        // Статус скрыт, пока пуст (v0.8.2: никаких «пустых полей» на вкладке)
        val linkCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        linkCard.addView(sectionTitle(R.string.config_hint_title, null))
        linkStatusView = TextView(this).apply {
            textSize = 12f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(2), 0, dp(4))
            visibility = View.GONE
        }
        linkCard.addView(linkStatusView)
        val layout = TextInputLayout(this).apply {
            hint = getString(R.string.config_hint)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { setMargins(0, dp(4), 0, dp(8)) }
        }
        configView = TextInputEditText(this).apply {
            setText(prefs().getString(TunnelService.KEY_CONFIG, ""))
            minLines = 2
            minHeight = dp(80)
            // КАНОН v0.8: вставил — приложение само всё починило и сохранило
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    val now = System.currentTimeMillis()
                    if (now - configEditDebounce < 400) return // дебаунс на пасту
                    configEditDebounce = now
                    val text = s?.toString() ?: ""
                    if (text.isBlank()) {
                        setLinkStatus(null)
                        return
                    }
                    applyPastedConfig(text, announce = false, silentFail = true)
                }
            })
        }
        layout.addView(configView)
        linkCard.addView(layout)
        linkCard.addView(
            row(
                outlined(R.string.link_clear).apply {
                    setOnClickListener { confirmClearLink() }
                },
                outlined(R.string.qr_scan).apply { setOnClickListener { launchScan() } },
            )
        )
        p.addView(card(linkCard))

        if (qrSupported) {
            p.addView(row(outlined(R.string.qr_show).apply { setOnClickListener { showQr() } }))
        }

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

        // Поделиться приложением: ссылка или APK (модули вшиты, настроек нет)
        val shareCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        shareCard.addView(sectionTitle(R.string.btn_share_app, null))
        shareCard.addView(TextView(this).apply {
            setText(R.string.share_choose)
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
            setPadding(0, dp(2), 0, dp(4))
        })
        shareCard.addView(
            row(
                filled(R.string.share_link).apply { setOnClickListener { shareAppLink() } },
                outlined(R.string.share_apk).apply { setOnClickListener { shareAppApk() } },
            )
        )
        p.addView(card(shareCard))
        return scrollWrap(p)
    }

    // ---------- Вкладка 3: Обновление ----------

    private fun buildUpdatePage(): View {
        val p = page()
        versionView = TextView(this).apply {
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(4), 0, dp(4))
        }
        p.addView(versionView)

        // Модули: обновляются без переустановки APK (как POS-машины)
        val modulesCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        modulesCard.addView(sectionTitle(R.string.modules_section, null))
        modulesInfoView = TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(4), 0, dp(4))
        }
        modulesCard.addView(modulesInfoView)
        modulesCard.addView(filled(R.string.modules_check_now).apply {
            setOnClickListener { syncModulesAsync(force = true) }
        })
        p.addView(card(modulesCard))

        // Авто-проверка — в карточке (UX-канон: единый вид всех переключателей)
        p.addView(card(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(SwitchMaterial(this@MainActivity).apply {
                setText(R.string.update_auto)
                isChecked = prefs().getBoolean(TunnelService.KEY_AUTO_UPDATE, true)
                setOnCheckedChangeListener { _, checked ->
                    val old = prefs().getBoolean(TunnelService.KEY_AUTO_UPDATE, true)
                    if (old != checked) {
                        prefs().edit().putBoolean(TunnelService.KEY_AUTO_UPDATE, checked).apply()
                        TunnelService.logSettingChange(getString(R.string.set_auto_update), old.toString(), checked.toString())
                        renderServiceLogs()
                    }
                }
            })
        }))

        p.addView(
            row(
                filled(R.string.update_check).apply {
                    setOnClickListener { checkForUpdateAsync(showIfUpToDate = true) }
                },
            )
        )

        // Журнал обновления/модулей — ТО ЖЕ консольное окно и формат, что на главной
        updateConsole = StatusConsole(this).apply {
            setTitle(getString(R.string.console_title_update))
            setBodyHeight(240)
        }
        p.addView(updateConsole)
        return scrollWrap(p)
    }

    // ---------- Вкладка 4: Лог ----------

    private fun buildLogPage(): View {
        val p = page()
        p.addView(TextView(this).apply {
            setText(R.string.logs_title)
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(4), 0, dp(4))
        })
        logConsole = StatusConsole(this).apply {
            setTitle(getString(R.string.console_title_service))
            setBodyHeight(280)
        }
        p.addView(logConsole)
        p.addView(
            row(
                outlined(R.string.log_copy_all).apply { setOnClickListener { copyServiceLog() } },
                outlined(R.string.log_share).apply { setOnClickListener { shareServiceLog() } },
            )
        )
        return scrollWrap(p)
    }

    // ---------- Вкладка 5: Настройки ----------

    private fun buildSettingsPage(): View {
        val p = page()

        // Тема (v0.8.1): авто (настройка телефона; на старых Android — чёрная) / тёмная / светлая
        p.addView(buildThemeCard())

        // О приложении: версии/модули/Рам/диск/трафик за всё время/протокол + константы защиты
        p.addView(sectionTitle(R.string.about_app_title, null))
        appInfoBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        p.addView(card(appInfoBox))

        // О устройстве (как «О телефоне» + CPU/RAM/SDK/Java)
        p.addView(sectionTitle(R.string.settings_device, null))
        deviceInfoBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        p.addView(card(deviceInfoBox))

        // О сети: ВСЁ, что приложение узнало — честно, по группам
        p.addView(sectionTitle(R.string.about_net_title, getString(R.string.about_net_hint)))
        netInfoBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        p.addView(card(netInfoBox))

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
                        renderServiceLogs()
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
                        renderServiceLogs()
                    }
                }
            })
        }))

        // Автоподключение при открытии (выкл по умолчанию)
        p.addView(card(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(SwitchMaterial(this@MainActivity).apply {
                setText(R.string.set_autoreconnect)
                isChecked = prefs().getBoolean(TunnelService.KEY_AUTO_RECONNECT, false)
                setOnCheckedChangeListener { _, checked ->
                    val old = prefs().getBoolean(TunnelService.KEY_AUTO_RECONNECT, false)
                    if (old != checked) {
                        prefs().edit().putBoolean(TunnelService.KEY_AUTO_RECONNECT, checked).apply()
                        TunnelService.logSettingChange(getString(R.string.set_autoreconnect), old.toString(), checked.toString())
                        renderServiceLogs()
                    }
                }
            })
        }))

        // Лимит трафика: «лимит — король»
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
        limitNextView = TextView(this).apply {
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
            setPadding(0, dp(2), 0, dp(4))
        }
        lim.addView(limitNextView)
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
        // Период: сутки / месяц (UX-канон: явный выбор вместо «угадай день»)
        lim.addView(TextView(this).apply {
            setText(R.string.set_limit_period)
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
        })
        val periodBox = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val periodDay = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(R.string.set_limit_period_day)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val periodMonth = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(R.string.set_limit_period_month)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .apply { setMargins(dp(6), 0, 0, 0) }
        }
        periodBox.addView(periodDay)
        periodBox.addView(periodMonth)
        lim.addView(periodBox)
        var selectedPeriod = prefs().getString(TunnelService.KEY_LIMIT_PERIOD, TunnelService.PERIOD_DAY)
            ?: TunnelService.PERIOD_DAY
        fun paintPeriod() {
            periodDay.backgroundTintList = android.content.res.ColorStateList.valueOf(
                if (selectedPeriod == TunnelService.PERIOD_DAY) 0xFF2E7D32.toInt() else 0x00FFFFFF,
            )
            periodMonth.backgroundTintList = android.content.res.ColorStateList.valueOf(
                if (selectedPeriod == TunnelService.PERIOD_MONTH) 0xFF2E7D32.toInt() else 0x00FFFFFF,
            )
        }
        periodDay.setOnClickListener {
            selectedPeriod = TunnelService.PERIOD_DAY; paintPeriod()
        }
        periodMonth.setOnClickListener {
            selectedPeriod = TunnelService.PERIOD_MONTH; paintPeriod()
        }
        paintPeriod()
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
                        val period = if (bytes > 0) selectedPeriod else TunnelService.PERIOD_DAY
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
                        renderServiceLogs(); refreshUsageSummary(); refreshLimitNext()
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
                        renderServiceLogs(); refreshUsageSummary()
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
                renderServiceLogs()
            }
        })
        p.addView(card(probe))
        return scrollWrap(p)
    }

    /**
     * v0.8.1: карта «Тема» — авто / тёмная / светлая (применяется сразу).
     */
    private fun buildThemeCard(): LinearLayout {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        box.addView(TextView(this).apply {
            setText(R.string.set_theme_title)
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
        })
        val rowBox = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val bAuto = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(R.string.set_theme_auto)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val bDark = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(R.string.set_theme_dark)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .apply { setMargins(dp(6), 0, 0, 0) }
        }
        val bLight = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(R.string.set_theme_light)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .apply { setMargins(dp(6), 0, 0, 0) }
        }
        rowBox.addView(bAuto); rowBox.addView(bDark); rowBox.addView(bLight)
        box.addView(rowBox)
        fun paint() {
            val sel = ThemeMode.normalize(prefs().getString(TunnelService.KEY_THEME, ThemeMode.AUTO))
            val on = 0xFF2E7D32.toInt()
            val off = 0x00FFFFFF
            bAuto.backgroundTintList = android.content.res.ColorStateList.valueOf(if (sel == ThemeMode.AUTO) on else off)
            bDark.backgroundTintList = android.content.res.ColorStateList.valueOf(if (sel == ThemeMode.DARK) on else off)
            bLight.backgroundTintList = android.content.res.ColorStateList.valueOf(if (sel == ThemeMode.LIGHT) on else off)
        }
        fun pick(mode: String) {
            val old = ThemeMode.normalize(prefs().getString(TunnelService.KEY_THEME, ThemeMode.AUTO))
            prefs().edit().putString(TunnelService.KEY_THEME, mode).apply()
            TunnelService.logSettingChange(getString(R.string.set_theme_title), old, mode)
            renderServiceLogs()
            paint()
            // применяем сразу, без перезапуска приложения
            androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(
                ThemeMode.resolveNightMode(mode, Build.VERSION.SDK_INT),
            )
        }
        bAuto.setOnClickListener { pick(ThemeMode.AUTO) }
        bDark.setOnClickListener { pick(ThemeMode.DARK) }
        bLight.setOnClickListener { pick(ThemeMode.LIGHT) }
        paint()
        return box
    }

    private fun outlined(textRes: Int) =
        MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(textRes)
        }

    private fun filled(textRes: Int) = MaterialButton(this).apply { setText(textRes) }

    private fun describeLimit(bytes: Long, period: String, day: Int): String {
        if (bytes <= 0) return "без ограничений"
        val pr = if (period == TunnelService.PERIOD_MONTH) "месяц (сброс $day)" else "сутки"
        return "${fmtBytes(bytes)}/$pr"
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
        // v0.8: лимит — король. Достигнут → НОЛЬ байт: окно предупреждения вместо старта.
        val used = prefs().getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
        val limit = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
        if (limit > 0 && used >= limit) {
            showLimitDialog(null)
            TunnelService.pushLog(getString(R.string.status_limit_reached), LogKind.WARN)
            renderServiceLogs()
            return
        }
        val i = Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_START)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
        setRunningUi(true)
    }

    private fun stopTunnel() {
        startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_STOP))
        setRunningUi(false)
    }

    /** Одна центральная кнопка + пульс-кольцо в активных состояниях. */
    private fun setRunningUi(running: Boolean) {
        bigButtonIsStart = !running
        if (running) {
            bigButton.setText(R.string.btn_stop_short)
            bigButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFFC62828.toInt())
            pulseRing.visibility = View.VISIBLE
            startPulse()
        } else {
            bigButton.setText(R.string.btn_start_short)
            bigButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF2E7D32.toInt())
            pulseRing.visibility = View.GONE
            stopPulse()
        }
    }

    private var pulseAnimator: android.animation.ValueAnimator? = null
    private fun startPulse() {
        stopPulse()
        val a = android.animation.ValueAnimator.ofFloat(0f, 1f)
        a.duration = 1200
        a.repeatCount = android.animation.ValueAnimator.INFINITE
        a.addUpdateListener { anim ->
            val t = anim.animatedValue as Float
            pulseRing.scaleX = 1f + t * 0.08f
            pulseRing.scaleY = 1f + t * 0.08f
            pulseRing.alpha = 0.7f - t * 0.5f
        }
        a.start()
        pulseAnimator = a
    }

    private fun stopPulse() {
        pulseAnimator?.cancel()
        pulseAnimator = null
        pulseRing.scaleX = 1f
        pulseRing.scaleY = 1f
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
        setProtoText(getString(R.string.proto_switching, RrpProtocols.labelWithVer(proto)))
        val i = Intent(this, TunnelService::class.java)
            .setAction(TunnelService.ACTION_SWITCH_PROTO)
            .putExtra(TunnelService.EXTRA_PROTO, proto)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
    }

    // ================================================================= Ссылка (авто-починка)

    /** Вставили/ввели ссылку → приложение САМО чинит, сохраняет и подтверждает. */
    private fun applyPastedConfig(content: String, announce: Boolean, silentFail: Boolean = false) {
        try {
            val cfg = RrpUri.parse(content) // бронепарсер чинит мусор сам
            val canonical = cfg.serialize()
            configView.setText(canonical)
            configView.setSelection(canonical.length)
            prefs().edit().putString(TunnelService.KEY_CONFIG, canonical).apply()
            setLinkStatus(getString(R.string.link_status_ok))
            if (announce) {
                Toast.makeText(this, R.string.link_saved, Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            setLinkStatus(getString(R.string.link_status_bad))
            if (announce || !silentFail) {
                Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun setLinkStatus(okText: String?) {
        // v0.8.2: пустой статус НЕ занимает место — никаких «пустых полей»
        if (okText == null) {
            linkStatusView.visibility = View.GONE
            return
        }
        linkStatusView.visibility = View.VISIBLE
        linkStatusView.text = okText
        linkStatusView.setTextColor(0xFF2E7D32.toInt())
    }

    /** Очистить поле — только с подтверждением (канон UX v0.8). */
    private fun confirmClearLink() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.link_clear)
            .setMessage(R.string.link_clear_confirm)
            .setPositiveButton(android.R.string.yes) { _, _ ->
                configView.setText("")
                prefs().edit().remove(TunnelService.KEY_CONFIG).apply()
                setLinkStatus(null)
                Toast.makeText(this, R.string.link_clear, Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ================================================================= Сеть/статус

    private fun renderServiceLogs() {
        val lines = TunnelService.snapshotLogs().map { l ->
            StatusConsole.Line(
                l.text,
                when (l.kind) {
                    LogKind.OK -> StatusConsole.Role.OK
                    LogKind.WARN -> StatusConsole.Role.WARN
                    LogKind.ERR -> StatusConsole.Role.ERR
                    else -> StatusConsole.Role.INFO
                },
            )
        }
        homeConsole.render(lines)
        logConsole.render(lines)
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

    private fun setUsageText(text: String) {
        usageViews.forEach { it.text = text }
    }

    private fun setProtoText(text: String) {
        protoLineViews.forEach { it.text = text }
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
                getString(R.string.proto_current, RrpProtocols.labelWithVer(current))
            } else {
                getString(
                    R.string.proto_current_list,
                    RrpProtocols.labelWithVer(current),
                    known.joinToString(", ") { RrpProtocols.labelWithVer(it) },
                )
            }
        )
    }

    /** Внешний IP/страна/оператор + локальный IP + DNS-факты (честно). */
    private fun refreshNetInfoAsync() {
        Thread {
            val info: NetInfo? = try {
                NetInfoFetcher.fetch()
            } catch (_: Exception) {
                null
            }
            val local = TunnelService.localIp()
            val dnsServers = try { DnsProbe.systemServers() } catch (_: Throwable) { emptyList() }
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
                            info.countryCode?.let { cc2 -> append(" (").append(cc2).append(")") }
                        }
                        info.isp?.let { append(" · ").append(it) }
                        // v0.8.1: честный источник (куда ходили за IP)
                        if (info.source.isNotEmpty()) append(" · ").append(getString(R.string.netinfo_source, info.source))
                    }
                }
                localIpView.text = getString(R.string.local_ip, local ?: "—")
                dnsLineView.text = getString(R.string.dns_servers_line, dnsServers.joinToString(", ").ifEmpty { "—" })
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
            applyPastedConfig(text, announce = true)
            Toast.makeText(this, R.string.config_imported, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
        }
    }

    // ================================================================= Поделиться приложением

    private fun shareAppLink() {
        val url = "https://github.com/stelgen/reverseray"
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, url)
        }
        startActivity(Intent.createChooser(send, getString(R.string.btn_share_app)))
    }

    /**
     * Поделиться APK «в сборе»: текущий APK приложения + вшитые модули
     * (реестр протоколов в коде). НЕ передаются: настройки, ссылка/токен,
     * логи, счётчики и любая приватная информация — у нового пользователя
     * всё будет в дефолтах.
     */
    private fun shareAppApk() {
        if (Build.VERSION.SDK_INT >= 19 && fileIoSupported) {
            try {
                shareApkLauncher.launch("reverseray-${currentVersion()}.apk")
                return
            } catch (_: ActivityNotFoundException) {
                // нет SAF-пикера — фоллбек на прямую шару ниже
            }
        }
        try {
            val apk = File(applicationInfo.sourceDir)
            val copy = File(cacheDir, "reverseray-${currentVersion()}.apk")
            apk.copyTo(copy, overwrite = true)
            val uri = FileProvider.getUriForFile(this, "$packageName.files", copy)
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "application/vnd.android.package-archive"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(send, getString(R.string.btn_share_app)))
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.share_apk_error), Toast.LENGTH_SHORT).show()
        }
    }

    private fun copyApkTo(uri: Uri) {
        try {
            contentResolver.openOutputStream(uri)?.use { out ->
                File(applicationInfo.sourceDir).inputStream().use { it.copyTo(out, 64 * 1024) }
                out.flush()
            }
            Toast.makeText(this, R.string.config_saved, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.share_apk_error), Toast.LENGTH_SHORT).show()
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

    // ================================================================= Обновление + модули

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

    private fun refreshModulesInfo() {
        val v = RrpProtocols.registryVersion()
        val protocols = RrpProtocols.displayList()
        modulesInfoView.text = getString(
            R.string.proto_current_list,
            if (v.isEmpty()) getString(R.string.app_modules_builtin) else v,
            protocols.joinToString(", "),
        )
    }

    private fun refreshUpdateConsole() {
        // v0.8.2: строки журнала обновлений несут цветовую роль (как в консоли туннеля)
        val lines = UpdateLogger.snapshot().map { l ->
            StatusConsole.Line(
                l.text,
                when (l.kind) {
                    LogKind.OK -> StatusConsole.Role.OK
                    LogKind.WARN -> StatusConsole.Role.WARN
                    LogKind.ERR -> StatusConsole.Role.ERR
                    else -> StatusConsole.Role.INFO
                },
            )
        }
        updateConsole.render(lines)
    }

    /** v0.8: применить сохранённый манифест модулей при старте. */
    private fun loadCachedModules() {
        try {
            val f = File(filesDir, "modules.json")
            if (!f.exists()) return
            val m = Modules.parse(f.readText())
            Modules.apply(m)
        } catch (_: Exception) {
            // битый кеш не применяем — работаем на встроенных
        }
    }

    /**
     * Синхронизация модулей (тот же modules.json, что ест сервер):
     * качается ТОЛЬКО если версия/хеш изменились; применяется без
     * переустановки APK. Прогресс и скорость — в консоль обновления.
     */
    private fun syncModulesAsync(force: Boolean) {
        val url = Modules.DEFAULT_URL
        UpdateLogger.add(getString(R.string.upd_modules_check, url.substringAfterLast('/')))
        Thread {
            try {
                val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 10_000
                conn.readTimeout = 15_000
                conn.setRequestProperty("Accept", "application/json")
                conn.connect()
                if (conn.responseCode != 200) {
                    throw Modules.ManifestException("HTTP ${conn.responseCode}")
                }
                UpdateLogger.add(getString(R.string.upd_modules_http, conn.responseCode))
                val len = conn.contentLengthLong
                var total = 0L
                var lastPct = -10
                val baos = java.io.ByteArrayOutputStream()
                conn.inputStream.use { input ->
                    val buf = ByteArray(16 * 1024)
                    val start = System.currentTimeMillis()
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        baos.write(buf, 0, n)
                        total += n
                        if (len > 0) {
                            val pct = (total * 100 / len).toInt().coerceIn(0, 100)
                            if (pct >= lastPct + 10) {
                                lastPct = pct
                                val secs = ((System.currentTimeMillis() - start).coerceAtLeast(1)) / 1000.0
                                val kbps = total / 1024.0 / secs
                                UpdateLogger.add(getString(R.string.modules_progress, pct, String.format(Locale.US, "%.0f КБ/с", kbps)))
                            }
                        }
                    }
                }
                conn.disconnect()
                val body = baos.toString("UTF-8")
                UpdateLogger.add(getString(R.string.upd_modules_received, fmtBytes(total)))
                val m = Modules.parse(body)
                UpdateLogger.add(
                    getString(
                        R.string.upd_modules_parsed, m.version,
                        m.enabledProtocolIds().joinToString(", ") { RrpProtocols.labelWithVer(it) },
                    ),
                )
                // даунгрейд запрещён (как на сервере)
                val current = RrpProtocols.registryVersion()
                if (current.isNotEmpty() && Modules.versionCompare(m.version, current) < 0) {
                    UpdateLogger.add(getString(R.string.upd_modules_older, m.version, current), LogKind.WARN)
                    refreshUpdateConsoleSafe()
                    return@Thread
                }
                val cachedHash = prefs().getString(KEY_MODULES_HASH, "")
                val hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(body.toByteArray(Charsets.UTF_8))
                    .joinToString("") { String.format(Locale.US, "%02x", it) }
                if (!force && m.version == current && hash == cachedHash) {
                    UpdateLogger.add(getString(R.string.modules_up_to_date), LogKind.OK)
                    refreshUpdateConsoleSafe()
                    return@Thread
                }
                Modules.apply(m)
                File(filesDir, "modules.json").writeText(body)
                prefs().edit().putString(KEY_MODULES_HASH, hash).apply()
                UpdateLogger.add(
                    getString(
                        R.string.modules_applied, m.version,
                        m.enabledProtocolIds().joinToString(", ") { RrpProtocols.labelWithVer(it) },
                    ),
                    LogKind.OK,
                )
                runOnUiThread {
                    refreshModulesInfo()
                    refreshProtoLine()
                }
            } catch (e: Exception) {
                UpdateLogger.add(getString(R.string.modules_failed, e.message ?: "?"), LogKind.ERR)
            }
            refreshUpdateConsoleSafe()
        }.apply { isDaemon = true }.start()
    }

    private fun refreshUpdateConsoleSafe() {
        runOnUiThread { refreshUpdateConsole() }
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

    /** v0.8: автоподключение при открытии приложения (выкл по умолчанию). */
    private fun maybeAutoConnect() {
        if (!prefs().getBoolean(TunnelService.KEY_AUTO_RECONNECT, false)) return
        val cfg = prefs().getString(TunnelService.KEY_CONFIG, null) ?: return
        if (cfg.isBlank()) return
        val used = prefs().getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
        val limit = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
        if (limit > 0 && used >= limit) {
            // лимит достигнут: ждём сброса (TunnelService сам ждёт даты)
            TunnelService.pushLog(getString(R.string.status_limit_reached), LogKind.WARN)
            showLimitDialog(null)
            return
        }
        startTunnel()
    }

    private fun checkForUpdateAsync(showIfUpToDate: Boolean) {
        val current = currentVersion()
        UpdateLogger.add(getString(R.string.upd_check_start, current))
        refreshUpdateConsoleSafe()
        Thread {
            val info = UpdateChecker().check(current)
            if (info == null) {
                UpdateLogger.add(getString(R.string.upd_check_none))
                if (showIfUpToDate) {
                    runOnUiThread { Toast.makeText(this, R.string.update_latest, Toast.LENGTH_SHORT).show() }
                }
            } else {
                UpdateLogger.add(getString(R.string.upd_check_available, info.latestTag, info.apkUrl.substringAfterLast('/')), LogKind.OK)
                if (info.sumsUrl.isNotEmpty()) {
                    UpdateLogger.add(getString(R.string.upd_sums_found))
                } else {
                    UpdateLogger.add(getString(R.string.upd_sums_missing), LogKind.WARN)
                }
                runOnUiThread {
                    refreshUpdateConsole()
                    MaterialAlertDialogBuilder(this)
                        .setTitle(getString(R.string.update_title, info.latestTag))
                        .setMessage(getString(R.string.update_question))
                        .setPositiveButton(R.string.update_download) { _, _ -> downloadUpdate(info) }
                        .setNegativeButton(android.R.string.cancel, null)
                        .show()
                }
            }
            refreshUpdateConsoleSafe()
        }.apply { isDaemon = true }.start()
    }

    private fun downloadUpdate(info: UpdateInfo) {
        val dir = File(cacheDir, "apk").apply { mkdirs() }
        val dest = File(dir, "update-${info.latestTag}.apk")
        UpdateLogger.add(getString(R.string.upd_dl_start, info.latestTag))
        Thread {
            try {
                val conn = java.net.URL(info.apkUrl).openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 10_000
                conn.readTimeout = 20_000
                conn.connect()
                val len = conn.contentLengthLong
                var total = 0L
                var lastPct = -10
                conn.inputStream.use { input ->
                    dest.outputStream().use { out ->
                        val buf = ByteArray(64 * 1024)
                        val start = System.currentTimeMillis()
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            out.write(buf, 0, n)
                            total += n
                            if (len > 0) {
                                val pct = (total * 100 / len).toInt().coerceIn(0, 100)
                                if (pct >= lastPct + 10) {
                                    lastPct = pct
                                    val secs = ((System.currentTimeMillis() - start).coerceAtLeast(1)) / 1000.0
                                    val speed = String.format(Locale.US, "%.0f КБ/с", total / 1024.0 / secs)
                                    UpdateLogger.add(getString(R.string.update_progress, pct, speed))
                                }
                            }
                        }
                        out.flush()
                    }
                }
                conn.disconnect()
                // v0.8.1 (анти-подмена): сверяем APK с SHA256SUMS релиза до установки
                val checker = UpdateChecker()
                val sums = checker.downloadSums(info.sumsUrl)
                val verifyErr = checker.verifyApk(dest, sums)
                if (verifyErr != null) {
                    dest.delete()
                    UpdateLogger.add(getString(R.string.upd_verify_fail, verifyErr), LogKind.ERR)
                    runOnUiThread {
                        refreshUpdateConsole()
                        Toast.makeText(this, getString(R.string.update_error, "SHA256 mismatch"), Toast.LENGTH_LONG).show()
                    }
                    return@Thread
                }
                UpdateLogger.add(getString(R.string.upd_dl_done, dest.name, fmtBytes(dest.length())))
                UpdateLogger.add(getString(R.string.upd_verify_ok, fmtBytes(dest.length())), LogKind.OK)
                runOnUiThread {
                    refreshUpdateConsole()
                    installApk(dest)
                }
            } catch (e: Exception) {
                UpdateLogger.add(getString(R.string.upd_dl_error, e.message ?: "?"), LogKind.ERR)
                runOnUiThread {
                    refreshUpdateConsole()
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
            UpdateLogger.add(getString(R.string.upd_install_no_installer), LogKind.WARN)
            Toast.makeText(this, R.string.update_error, Toast.LENGTH_SHORT).show()
        }
    }

    // ================================================================= Лимит — король

    /** Окно «траффик закончился» — на Старт/Реконнект и при падении туннеля. */
    private fun showLimitDialog(statusText: String?) {
        val used = prefs().getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
        val limit = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
        val next = nextResetDateString()
        val msg = getString(R.string.limit_dialog_msg, fmtBytes(used), fmtBytes(limit), next)
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.limit_dialog_title)
            .setMessage(msg)
            .setPositiveButton(R.string.limit_dialog_wait) { _, _ ->
                // авто-реконнект включаем и отдаём ожидание сервису
                prefs().edit().putBoolean(TunnelService.KEY_AUTO_RECONNECT, true).apply()
                TunnelService.pushLog(getString(R.string.status_limit_wait, 0), LogKind.WARN)
                renderServiceLogs()
            }
            .setNegativeButton(android.R.string.ok, null)
            .show()
        if (statusText != null) {
            setUsageText(usageSummaryText(used, limit))
        }
    }

    /** Строка «следующий сброс счётчика» — настройки + главный. */
    private fun refreshLimitNext() {
        val used = prefs().getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
        val limit = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
        limitNextView.text = if (limit > 0) {
            getString(R.string.set_limit_next, nextResetDateString())
        } else {
            ""
        }
        setUsageText(usageSummaryText(used, limit))
    }

    private fun nextResetDateString(): String {
        val period = prefs().getString(TunnelService.KEY_LIMIT_PERIOD, TunnelService.PERIOD_DAY)
            ?: TunnelService.PERIOD_DAY
        val day = prefs().getInt(TunnelService.KEY_LIMIT_RESET_DAY, 1)
        val at = LimitReset.nextResetAtMs(period, day)
        return SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(at))
    }

    // ================================================================= Панели «О …»

    private fun infoRow(parent: LinearLayout, k: String, v: String) {
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
        parent.addView(l)
    }

    /** «О приложении»: версии, модули, RAM, диск, трафик за всё время, протокол
     *  + v0.8.1: константы/переменные защиты и честные факты (серт, источники). */
    private fun refreshAppPanel() {
        appInfoBox.removeAllViews()
        val code = try {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0).versionCode
        } catch (_: Exception) { 0 }
        val rt = Runtime.getRuntime()
        val ramUsed = rt.totalMemory() - rt.freeMemory()
        val apkLen = try { File(applicationInfo.sourceDir).length() } catch (_: Exception) { 0L }
        val dataLen = try { dirSize(filesDir) + dirSize(cacheDir) } catch (_: Exception) { 0L }
        val lifetime = prefs().getLong(TunnelService.KEY_TRAFFIC_LIFETIME, 0L)
        val currentProto = try {
            RrpUri.parse(prefs().getString(TunnelService.KEY_CONFIG, "") ?: "").proto
        } catch (_: Exception) { RrpProtocols.DEFAULT }
        val modulesV = RrpProtocols.registryVersion().ifEmpty { getString(R.string.app_modules_builtin) }
        infoRow(appInfoBox, getString(R.string.app_version_row), "${currentVersion()} ($code)")
        infoRow(appInfoBox, getString(R.string.app_modules_row), "$modulesV · ${RrpProtocols.displayList().joinToString(", ") { RrpProtocols.labelWithVer(it) }}")
        infoRow(appInfoBox, getString(R.string.app_ram_row), fmtBytes(ramUsed))
        infoRow(appInfoBox, getString(R.string.app_disk_row), fmtBytes(apkLen + dataLen))
        infoRow(appInfoBox, getString(R.string.app_traffic_life_row), fmtBytes(lifetime))
        infoRow(appInfoBox, getString(R.string.app_proto_row), RrpProtocols.labelWithVer(currentProto))
        // v0.8.1: версия текущего протокола (или пусто, если версии нет — канон)
        val pver = RrpProtocols.ver(currentProto)
        infoRow(appInfoBox, getString(R.string.app_proto_ver_row), pver.ifEmpty { "—" })
        // v0.8.2: модуль камуфляжа «API Mask» — версия и статус, честно
        val camo = RrpProtocols.camouflageConfig()
        infoRow(
            appInfoBox, getString(R.string.app_camo_row),
            if (camo.enabled) RrpProtocols.camouflageLabel() else getString(R.string.app_camo_off),
        )
        // v0.8.1: срок действия серверного TLS-сертификата (если видели рукопожатие)
        val certMs = RrpClient.lastServerCertNotAfterMs
        if (certMs > 0) {
            infoRow(appInfoBox, getString(R.string.app_cert_row), SimpleDateFormat("dd.MM.yyyy", Locale.getDefault()).format(Date(certMs)))
        }
        appInfoBox.addView(
            Button(this).apply {
                setText(R.string.dev_copy)
                background = null
                setOnClickListener {
                    copyPanel(appInfoBox, "ReverseRay app")
                }
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { gravity = Gravity.END }
            }
        )

        // Константы защиты — отдельная честная секция (канал «ничего не прячем»)
        appInfoBox.addView(TextView(this).apply {
            setText(R.string.sf_section)
            textSize = 13f
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(10), 0, dp(2))
        })
        val sfTitles = listOf(
            R.string.sf_tls_min, R.string.sf_alpn, R.string.sf_tls_provider,
            R.string.sf_cert_model, R.string.sf_pin_policy, R.string.sf_zero_rtt,
            R.string.sf_token_storage, R.string.sf_handshake, R.string.sf_nonce,
            R.string.sf_rate_limit, R.string.sf_mtproto2, R.string.sf_frame_limits,
            R.string.sf_wan, R.string.sf_ssrf, R.string.sf_modules, R.string.sf_apk_integrity,
        )
        for ((titleRes, value) in sfTitles.zip(SecurityFacts.values())) {
            infoRow(appInfoBox, getString(titleRes), value)
        }
    }

    /** «О устройстве» + CPU-модель, общая RAM, SDK, Java. */
    private fun refreshDevicePanel() {
        deviceInfoBox.removeAllViews()
        val kernel = try { System.getProperty("os.version") ?: "—" } catch (_: Exception) { "—" }
        val cpuModel = cpuModel()
        val abis = try { Build.SUPPORTED_ABIS.firstOrNull() ?: "—" } catch (_: Exception) { "—" }
        val sec = try {
            if (Build.VERSION.SDK_INT >= 22) {
                @Suppress("DEPRECATION")
                Build.VERSION.SECURITY_PATCH
            } else "—"
        } catch (_: Throwable) { "—" }
        val totalRam = totalRamBytes()
        val m = resources.displayMetrics
        infoRow(deviceInfoBox, getString(R.string.dev_model), "${Build.MANUFACTURER} ${Build.MODEL}")
        infoRow(deviceInfoBox, getString(R.string.dev_android), "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        infoRow(deviceInfoBox, getString(R.string.dev_sdk), "SDK ${Build.VERSION.SDK_INT}")
        infoRow(deviceInfoBox, getString(R.string.dev_cpu_model), cpuModel.ifEmpty { abis })
        infoRow(deviceInfoBox, getString(R.string.dev_ram_total), fmtBytes(totalRam))
        infoRow(deviceInfoBox, getString(R.string.dev_java), javaVmInfo())
        infoRow(deviceInfoBox, getString(R.string.dev_build), Build.DISPLAY)
        infoRow(deviceInfoBox, getString(R.string.dev_patch), sec)
        infoRow(deviceInfoBox, getString(R.string.dev_kernel), kernel)
        infoRow(deviceInfoBox, getString(R.string.dev_screen), "${m.widthPixels}×${m.heightPixels} @${m.density}x")
        infoRow(deviceInfoBox, getString(R.string.dev_version), "${currentVersion()} (${getString(R.string.app_name)})")
        // v0.8.1: честно показываем, ЧТО именно читаем об устройстве (канал прозрачности)
        infoRow(deviceInfoBox, getString(R.string.dev_sources_row), getString(R.string.dev_sources_list))
        deviceInfoBox.addView(
            Button(this).apply {
                setText(R.string.dev_copy)
                background = null
                setOnClickListener { copyPanel(deviceInfoBox, "ReverseRay device") }
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { gravity = Gravity.END }
            }
        )
    }

    /** «О сети» — честно всё, что приложение узнало (DnsProbe + NetInfo)
     *  + v0.8.1: ЧЕМ и ГДЕ мы это узнали (источники — канон прозрачности). */
    private fun refreshNetPanel() {
        netInfoBox.removeAllViews()
        infoRow(netInfoBox, getString(R.string.netinfo_loading), lastExternalIp ?: "…")
        netInfoBox.addView(TextView(this).apply {
            setText(R.string.about_net_hint)
            textSize = 11f
            setTextColor(0xFF6B7280.toInt())
            setPadding(0, dp(6), 0, dp(2))
        })
        Thread {
            val dns = try { DnsProbe.collect() } catch (_: Throwable) { null }
            val external = try { NetInfoFetcher.fetch() } catch (_: Exception) { null }
            runOnUiThread {
                netInfoBox.removeAllViews()
                // Честные источники: куда ходили и что читали локально
                infoRow(
                    netInfoBox, getString(R.string.net_sources_row),
                    NetInfoFetcher.SOURCES.joinToString(", ") + " · " +
                        getString(R.string.net_sources_local),
                )
                external?.let { e ->
                    infoRow(
                        netInfoBox, "Внешний IP",
                        "${e.ip}${e.country?.let { " · $it" } ?: ""}${e.isp?.let { " · $it" } ?: ""}" +
                            (if (e.source.isNotEmpty()) " · ${getString(R.string.netinfo_source, e.source)}" else ""),
                    )
                }
                if (dns == null) {
                    infoRow(netInfoBox, "DNS", "не удалось собрать факты")
                } else {
                    for ((k, v) in DnsProbe.describe(dns)) {
                        infoRow(netInfoBox, k, v)
                    }
                }
            }
        }.apply { isDaemon = true }.start()
    }

    private fun copyPanel(box: LinearLayout, label: String) {
        val sb = StringBuilder()
        for (i in 0 until box.childCount) {
            val rowL = box.getChildAt(i) as? LinearLayout ?: continue
            if (rowL.childCount == 2) {
                sb.append((rowL.getChildAt(0) as TextView).text).append(": ")
                    .append((rowL.getChildAt(1) as TextView).text).append('\n')
            }
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, sb.toString()))
        Toast.makeText(this, R.string.logs_copied, Toast.LENGTH_SHORT).show()
    }

    private fun dirSize(dir: File): Long = try {
        dir.walkBottomUp().filter { it.isFile }.map { it.length() }.sum()
    } catch (_: Exception) {
        0L
    }

    private fun cpuModel(): String = try {
        File("/proc/cpuinfo").useLines { lines ->
            lines.firstOrNull { it.startsWith("Hardware") }?.substringAfter(":")?.trim()
                ?: lines.firstOrNull { it.startsWith("model name") }?.substringAfter(":")?.trim()
                ?: ""
        }
    } catch (_: Exception) {
        ""
    }

    private fun totalRamBytes(): Long = try {
        val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo()
        am.getMemoryInfo(mi)
        mi.totalMem
    } catch (_: Exception) {
        0L
    }

    private fun javaVmInfo(): String = try {
        "${System.getProperty("java.vm.name") ?: "?"} ${System.getProperty("java.vm.version") ?: ""}"
    } catch (_: Exception) {
        "?"
    }

    // ================================================================= Лог: копировать/поделиться

    private fun copyServiceLog() {
        val text = logConsole.snapshotText().ifEmpty { getString(R.string.logs_empty) }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("ReverseRay log", text))
        Toast.makeText(this, R.string.logs_copied, Toast.LENGTH_SHORT).show()
    }

    private fun shareServiceLog() {
        val text = logConsole.snapshotText().ifEmpty { getString(R.string.logs_empty) }
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(send, getString(R.string.log_share)))
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
        const val KEY_MODULES_HASH = "modules_hash"
    }
}

/** Следующая дата сброса лимита — вынесено для юнит-тестов (без android.*). */
object LimitReset {

    fun nextResetAtMs(period: String, resetDay: Int): Long {
        val cal = Calendar.getInstance()
        if (period == TunnelService.PERIOD_MONTH) {
            cal.add(Calendar.MONTH, 1)
            cal.set(Calendar.DAY_OF_MONTH, resetDay.coerceIn(1, 28))
        } else {
            cal.add(Calendar.DAY_OF_YEAR, 1)
        }
        cal.set(Calendar.HOUR_OF_DAY, 0)
        cal.set(Calendar.MINUTE, 0)
        cal.set(Calendar.SECOND, 0)
        cal.set(Calendar.MILLISECOND, 0)
        return cal.timeInMillis
    }
}