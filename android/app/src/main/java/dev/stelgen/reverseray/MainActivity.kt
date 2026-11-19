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
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.CheckBox
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
import dev.stelgen.reverseray.core.RrpFrame
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.RrpUriConfig
import dev.stelgen.reverseray.core.SecurityFacts
import dev.stelgen.reverseray.core.SessionStore
import dev.stelgen.reverseray.service.PrefsBackend
import dev.stelgen.reverseray.core.ThemeMode
import dev.stelgen.reverseray.ui.Formats
import dev.stelgen.reverseray.ui.GraphHistory
import dev.stelgen.reverseray.ui.DashboardView
import dev.stelgen.reverseray.ui.PulseRingView
import dev.stelgen.reverseray.net.DnsProbe
import dev.stelgen.reverseray.net.NetInfo
import dev.stelgen.reverseray.net.NetInfoFetcher
import dev.stelgen.reverseray.core.LogStore
import dev.stelgen.reverseray.service.LogKind
import dev.stelgen.reverseray.service.TunnelService
import dev.stelgen.reverseray.ui.*
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

    // v0.8.3: язык Activity из prefs (канон i18n; фолбэк — EN-дефолт ресурсов)
    override fun attachBaseContext(base: android.content.Context) {
        super.attachBaseContext(L10nUi.wrap(base))
    }

    // ---------- вкладки ----------
    private lateinit var tabLayout: TabLayout
    // v0.8.2: каждая вкладка — ScrollView (контент листается ВСЕГДА,
    // включая ландшафт и крупные шрифты — UX-канон скроллинга)
    internal lateinit var pageHome: View

    /** Для extension-зон (backing field доступен только в классе). */
    internal fun pageInitialized(): Boolean = this::pageHome.isInitialized
    internal fun logFilterInitialized(): Boolean = this::logFilterRow.isInitialized
    internal lateinit var pageLink: View
    internal lateinit var pageUpdate: View
    internal lateinit var pageLog: View
    internal lateinit var pageSettings: View
    internal lateinit var dashboard: DashboardView

    // ---------- главная ----------
    internal lateinit var bigButton: MaterialButton
    internal lateinit var pulseRing: PulseRingView
    internal var bigButtonIsStart = true
    internal var lastButtonMode: Mode? = null
    internal lateinit var trafficGraph: TrafficGraphView
    internal lateinit var trafficLabel: TextView
    internal lateinit var packetsLabel: TextView
    internal lateinit var netFlag: ImageView
    internal var mainStatusDot: View? = null
    internal lateinit var netInfoView: TextView
    internal lateinit var localIpView: TextView
    internal lateinit var dnsLineView: TextView
    internal lateinit var speedTestView: TextView
    internal lateinit var homeConsole: StatusConsole

    /** Строки «текущий протокол» живут на двух вкладках — обновляем все. */
    internal val connLineViews = mutableListOf<TextView>()

    /** Актуальный согласованный протокол сессии (EXTRA_PROTO); пусто = не подключались. */
    @Volatile private var lastNegotiatedProto = ""
    /** Сводка лимита трафика — на главной и в настройках. */
    internal val usageViews = mutableListOf<TextView>()

    // ---------- связь ----------
    internal lateinit var linkValueView: TextView
    internal lateinit var linkStatusView: TextView
    private var configEditDebounce = 0L

    // ---------- обновление ----------
    internal lateinit var versionView: TextView
    internal lateinit var modulesInfoView: TextView
    internal lateinit var updateConsole: StatusConsole

    // ---------- лог ----------
    internal lateinit var logConsole: StatusConsole
    internal lateinit var logFilterRow: HorizontalScrollView

    /** v1.5.0: фильтр лога «по сессии» (null = все строки). */
    @Volatile internal var logSessionFilter: String? = null

    // ---------- настройки ----------
    internal lateinit var deviceInfoBox: LinearLayout
    internal lateinit var appInfoBox: LinearLayout
    internal lateinit var netInfoBox: LinearLayout
    internal lateinit var sessionsBox: LinearLayout
    internal lateinit var usageSummaryView: TextView
    internal lateinit var limitNextView: TextView

    private val uiHandler = Handler(Looper.getMainLooper())
    private val netInfoRunnable = object : Runnable {
        override fun run() {
            refreshNetInfoAsync()
            uiHandler.postDelayed(this, NETINFO_REFRESH_MS)
        }
    }

    internal var lastExternalIp: String? = null

    /** zxing-embedded требует API 19+ (overrideLibrary в манифесте). */
    internal val qrSupported: Boolean get() = Build.VERSION.SDK_INT >= 19

    /** SAF (файлы конфига) доступен с API 19. */
    internal val fileIoSupported: Boolean get() = Build.VERSION.SDK_INT >= 19

    internal val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val content = result.contents ?: return@registerForActivityResult
        applyPastedConfig(content, announce = true)
    }

    internal val exportFileLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            if (uri != null) writeConfigToFile(uri)
        }

    internal val importFileLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) readConfigFromFile(uri)
        }

    /** SAF-приёмник для «Поделиться APK» (пишем копию в выбранное место). */
    internal val shareApkLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri ->
            if (uri != null) copyApkTo(uri)
        }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            intent ?: return
            when (intent.action) {
                TunnelService.ACTION_STATS -> {
                    // v1.5.0: дашборд сессий (EXTRA_SESSIONS — JSON-снапшот)
                    intent.getStringExtra(TunnelService.EXTRA_SESSIONS)?.let {
                        lastSessionsJson = it
                        renderDashboard(it)
                    }
                    val rx = intent.getLongExtra(TunnelService.EXTRA_RX_RATE, 0L)
                    val tx = intent.getLongExtra(TunnelService.EXTRA_TX_RATE, 0L)
                    trafficGraph.addSample(rx.toFloat(), tx.toFloat())
                    GraphHistory.push(rx.toFloat(), tx.toFloat(), fromService = true)
                    syncGraphVisibility()
                    // v1.5.1: среднее (EMA) и пик окна — из GraphHistory (пишется всегда)
                    val (avgEma, peakNow) = GraphHistory.stats()
                    trafficLabel.text = getString(R.string.traffic_rates, fmtRate(rx), fmtRate(tx)) + "\n" +
                        getString(R.string.traffic_stats, fmtRate(avgEma.toLong()), fmtRate(peakNow.toLong()))
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
                    // v1.5.0: сервис остановлен — дашборд в оффлайн-снапшот профилей
                    if (state == TunnelService.STATE_STOPPED) {
                        lastSessionsJson = ""
                        preserveScroll { dashboard.update(offlineStats()) }
                    }
                    intent.getStringExtra(TunnelService.EXTRA_STATUS)?.let { statusText ->
                        renderServiceLogs()
                        if (state == TunnelService.STATE_LIMIT_REACHED) {
                            showLimitDialog(statusText)
                        }
                        // v0.9.0: ротация CA — предлагаем владельцу ЯВНО принять новый пин
                        if (state == TunnelService.STATE_PIN_MISMATCH) {
                            intent.getStringExtra(TunnelService.EXTRA_REAL_PIN)?.let {
                                showPinMismatchDialog(it)
                            }
                        }
                    }
                    when (state) {
                        TunnelService.STATE_CONNECTED, TunnelService.STATE_RETRY, TunnelService.STATE_PROTO -> {
                            // v0.9.9 ФИКС ГЛАВНОГО ЭЛЕМЕНТА: STATE_PROTO — финальное
                            // «подключено с протоколом X»; раньше проваливался в
                            // else → DISCONNECTED и кнопка откатывалась в «Start»
                            // при живом туннеле (канон M2: смена состояния — fade).
                            intent.getStringExtra(TunnelService.EXTRA_PROTO)?.let { p ->
                                lastNegotiatedProto = p
                                refreshConnLine()
                            }
                            setUiState(state)
                        }
                        TunnelService.STATE_PROTO_ROLLBACK -> {
                            intent.getStringExtra(TunnelService.EXTRA_PROTO)?.let { old ->
                                lastNegotiatedProto = old
                                refreshConnLine()
                                Toast.makeText(
                                    this@MainActivity,
                                    R.string.proto_rollback_toast,
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                            setUiState(state)
                        }
                        TunnelService.STATE_CONNECTED -> {
                            pinMismatchDialogShown = false
                            setUiState(state)
                        }
                        else -> setUiState(state) // STOPPED/ERROR/LIMIT/INFO/PIN — кнопка честно отражает состояние
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
        // v0.9.2 (R3/R4): мгновенная синхронизация из сервиса — кнопка, статус,
        // протокол и ИСТОРИЯ графика переживают пересоздание Activity.
        syncUiFromService()
        // v0.9.9: приложение обновилось → модули подтягиваются САМИ
        // (не нужно жать «Проверить модули» после каждого обновления APK)
        val apkVer = currentVersion()
        val prevVer = prefs().getString("last_apk_ver", "") ?: ""
        if (prevVer.isNotBlank() && prevVer != apkVer) {
            UpdateLogger.add(getString(R.string.upd_auto_modules), LogKind.INFO)
            syncModulesAsync(false)
        }
        prefs().edit().putString("last_apk_ver", apkVer).apply()
        // v0.9.2 (R9): реестр обновился (модуль нового протокола прилетел) —
        // строки протокола перерисовываются СРАЗУ, не дожидаясь статуса.
        RrpProtocols.onRegistryChanged = {
            runOnUiThread { refreshConnLine() }
        }
        // v0.8.2: журнал обновлений льётся в консоль СРАЗУ (реалтайм),
        // а не только при перерендере вкладки
        // v0.9.6: ОДИН источник — LogStore. Реалтайм: канал UPDATE льётся в
        // консоль обновлений, полный лог дорисовывается, если открыта вкладка.
        // Главная обновляется статус-броадкастами (renderServiceLogs).
        LogStore.onEntry = { e ->
            runOnUiThread {
                val line = StatusConsole.Line(e.text, StatusConsole.roleOf(e.kind))
                if (e.channel == LogStore.Channel.UPDATE) {
                    updateConsole.append(line)
                }
                // v0.9.7: вкладка «Лог» — ВСЕ каналы в реалтайме (канон: полный лог)
                if (isLogTabOpen()) {
                    logConsole.append(line)
                }
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
        // v1.5.1: график пишется ВСЕГДА — пока сервис молчит, питаем его
        // общесистемными скоростями (TrafficStats, дельты раз в 1 с)
        startDeviceSampler()
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
        stopDeviceSampler()
        try { unregisterReceiver(statusReceiver) } catch (_: Exception) {}
    }

    // ---- v1.5.1: ВСЕГДА-пишущийся график — общесистемный сэмплер ----

    private var deviceSampler: Thread? = null
    private var devLastRx = 0L
    private var devLastTx = 0L

    private fun startDeviceSampler() {
        if (deviceSampler?.isAlive == true) return
        devLastRx = android.net.TrafficStats.getTotalRxBytes()
        devLastTx = android.net.TrafficStats.getTotalTxBytes()
        deviceSampler = Thread({
            while (!Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(1_000)
                    val rxTot = android.net.TrafficStats.getTotalRxBytes()
                    val txTot = android.net.TrafficStats.getTotalTxBytes()
                    val drx = (rxTot - devLastRx).coerceAtLeast(0)
                    val dtx = (txTot - devLastTx).coerceAtLeast(0)
                    devLastRx = rxTot
                    devLastTx = txTot
                    // туннель молчит дольше 2.5 с — рисуем общесистемный трафик
                    val serviceSilent =
                        System.currentTimeMillis() - GraphHistory.lastServiceSampleMs >
                        GraphHistory.SERVICE_SILENCE_MS
                    if (serviceSilent) {
                        runOnUiThread {
                            trafficGraph.addSample(drx.toFloat(), dtx.toFloat())
                            GraphHistory.push(drx.toFloat(), dtx.toFloat(), fromService = false)
                            syncGraphVisibility()
                            trafficLabel.text = getString(
                                R.string.traffic_device_rates, fmtRate(drx), fmtRate(dtx),
                            )
                        }
                    }
                } catch (_: InterruptedException) {
                    return@Thread
                } catch (_: Throwable) {
                    // одиночный сбой сэмплера не роняет Activity
                }
            }
        }, "rr-device-net").apply { isDaemon = true; start() }
    }

    private fun stopDeviceSampler() {
        deviceSampler?.interrupt()
        deviceSampler = null
    }

    // ================================================================= UI

    internal fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

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
            // v1.6.0: вкладка «Серверы» УБРАНА — сессии живут на «Подключении»
            // и графики серверов на Home (дашборд-вкладка была дублем).
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
        currentTab = index
        listOf(pageHome, pageLink, pageUpdate, pageLog, pageSettings).forEachIndexed { i, p ->
            val show = i == index
            p.visibility = if (show) View.VISIBLE else View.GONE
            // v0.9.2 (R5): мягкий fade-переход вкладок (150мс, Views-канон)
            if (show && p.alpha < 1f) {
                p.animate().alpha(1f).setDuration(150).start()
            } else if (show) {
                p.alpha = 0.4f
                p.animate().alpha(1f).setDuration(150).start()
            }
        }
        when (index) {
            2 -> { refreshVersionRow(); refreshModulesInfo(); refreshUpdateConsole() }
            3 -> { renderServiceLogs(); refreshLogFilterChips() }
            4 -> { refreshDevicePanel(); refreshAppPanel(); refreshNetPanel(); refreshUsageSummary(); refreshLimitNext() }
            // v1.6.0: сессии переехали на «Подключение» (вкладка 1) — там же
            // мульти-ввод ссылок; Настройки больше не дублируют управление.
            1 -> { refreshConnLine(); refreshSessionsCard() }
        }
    }

    /** Последний JSON-снапшот сессий из EXTRA_SESSIONS (пусто — сервис молчит). */
    @Volatile internal var lastSessionsJson: String = ""

    /** v1.6.2: текущая вкладка (для стабилизации скролла при пересборках). */
    internal var currentTab = 0

    internal fun page(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(12), dp(16), dp(16))
    }

    /**
     * v0.8.2 (UX-канон): оборачивает содержимое вкладки в ScrollView —
     * ЛЮБАЯ вкладка скроллится, когда контент не влезает (портрет/ландшафт,
     * крупные шрифты). fillViewport — фон тянется до низа без «рваных» краёв.
     */
    internal fun scrollWrap(content: LinearLayout): View = android.widget.ScrollView(this).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = true
        // v1.7.1 КАНОН «фокус не прыгает» (канон владельца: нажатие кнопки /
        // пересборка списков НИКОГДА не уносят вид). Механизм прыжка:
        // фокусный fallback ViewRootImpl после layout поднимает
        // focusableInTouchMode-потомка (консоль с selectable-текстом и т.п.) →
        // ScrollView едет к нему (smoothScroll переживает и
        // preserveScroll-восстановление). Рецепт: страница сама гасит
        // touch-фокус → fallback приходит в ScrollView, а не в глубину →
        // scrollToChild не вызывается вовсе. Прямые requestFocus от ввода
        // (TextInputEditText на «Подключении») это не ломает.
        setDescendantFocusability(ViewGroup.FOCUS_BEFORE_DESCENDANTS)
        isFocusable = true
        isFocusableInTouchMode = true
        addView(
            content,
            ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
    }

    internal fun card(content: LinearLayout): MaterialCardView = MaterialCardView(this).apply {
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

    internal fun sectionTitle(textRes: Int, hint: String? = null): LinearLayout {
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

    internal fun row(vararg buttons: MaterialButton): LinearLayout {
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

    // ---------- Вкладка 2: Связь ----------

    // ---------- Вкладка 3: Обновление ----------

    // ---------- Вкладка 4: Лог ----------

    // ---------- Вкладка 5: Настройки ----------

    internal fun outlined(textRes: Int) =
        MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            setText(textRes)
            // v0.9.7 (GUI-этап 2): эргономика — тач-таргет ≥ 48dp на всех кнопках
            minHeight = dp(48)
            minWidth = dp(88)
        }

    internal fun filled(textRes: Int) = MaterialButton(this).apply {
        setText(textRes)
        // v0.9.7 (GUI-этап 2): эргономика — тач-таргет ≥ 48dp на всех кнопках
        minHeight = dp(48)
    }

    internal fun describeLimit(bytes: Long, period: String, day: Int): String {
        if (bytes <= 0) return getString(R.string.limit_none)
        val pr = if (period == TunnelService.PERIOD_MONTH) getString(R.string.limit_period_month, day) else getString(R.string.limit_period_day)
        return "${fmtBytes(bytes)}/$pr"
    }

    internal fun limitGb(): String {
        val l = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
        return if (l <= 0) "10" else String.format(Locale.US, "%.0f", l / 1024.0 / 1024.0 / 1024.0)
    }

    // ================================================================= Действия

    /**
     * v1.6.1: ЕДИНАЯ точка нажатий главной кнопки — анти-спам канон:
     *  - СТОП/ОТМЕНА проходит ВСЕГДА (независимо от раздрая: юзер всегда
     *    может отключиться); нажатие во время подключения = ОТМЕНА коннекта
     *    (ACTION_STOP) — сервис глушит раннеры, UI честно STOPPED;
     *  - СТАРТ: дебаунс 700 мс (двойной тап не плодит start-intents) и
     *    кулдаун 1.2 с после стопа (раздрай процессов не залипает в
     *    start/stop-пинг-понг); кнопка на кулдауне на пару секунд «неактивна»
     *    ТОЛЬКО для старта (полупрозрачность — визуальный намёк), стоп жив.
     *  - СИНХРОННОСТЬ: источник истины — TunnelService.lastState + броадкасты
     *    (setUiState), UI никогда не «догоняет» сервис догадками.
     */
    internal var lastStartPressMs = 0L
    internal var lastStopPressMs = 0L

    internal val START_COOLDOWN_MS = 1_200L

    /** v1.6.0: 3 с в CONNECTING → красный «Тайм-аут» (канон владельца). */
    internal val connectTimeoutHandler = android.os.Handler(android.os.Looper.getMainLooper())
    internal val connectTimeoutRunnable = Runnable {
        if (lastButtonMode == Mode.CONNECTING) applyButtonMode(Mode.TIMEOUT)
    }

    /** v1.6.0: тайм-аут-режим кнопки (красный «Тайм-аут», коннект продолжается). */
    internal val CONNECT_TIMEOUT_MS = 3_000L

    /**
     * v0.9.5 (канон владельца): Старт/Стоп — СИНЯЯ кнопка; подключение —
     * тёмно-жёлто-оранжевая с надписью «Подключение»; ошибка — красная с
     * надписью «Ошибка» (цвет держится ERROR_HOLD_MS сервисом, затем
     * реконнект возвращает тёмно-жёлтый «Подключение»).
     */
    internal enum class Mode(val color: Int, val isStart: Boolean, val labelRes: Int) {
        DISCONNECTED(0xFF1565C0.toInt(), true, R.string.btn_start_short),
        CONNECTING(0xFFB26B00.toInt(), true, R.string.btn_connecting),
        CONNECTED(0xFF1565C0.toInt(), false, R.string.btn_stop_short),
        ERROR(0xFFC62828.toInt(), true, R.string.btn_error),
        TIMEOUT(0xFFC62828.toInt(), true, R.string.btn_timeout),
    }

    internal var buttonColorAnimator: android.animation.ValueAnimator? = null
    internal var ringMode: Mode? = null

    /** v1.0.0: зацикленное «дыхание» кнопки (REVERSE-цикл, гасится плавно). */
    internal var breathing: android.animation.ValueAnimator? = null
    internal var breathMode: Mode? = null

    // v0.9.3: анимации кольца перенесены в ui/PulseRingView (инкапсуляция,
    // экономия батареи — аниматор не крутится, когда вью невидимо).

    // ================================================================= Сеть/статус

    // ================================================================= Формат

    // ================================================================= Поделиться приложением

    // ================================================================= QR

    // ================================================================= Обновление + модули

    internal fun currentVersion(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: ""
    } catch (_: Exception) {
        ""
    }

    internal fun refreshVersionRow() {
        val code = try {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0).versionCode
        } catch (_: Exception) {
            0
        }
        versionView.text = getString(R.string.version_row, currentVersion(), code)
    }

    internal fun refreshModulesInfo() {
        val v = RrpProtocols.registryVersion()
        val protocols = RrpProtocols.displayList()
        modulesInfoView.text = getString(
            R.string.proto_current_list,
            if (v.isEmpty()) getString(R.string.app_modules_builtin) else v,
            protocols.joinToString(", "),
        )
    }

    internal fun refreshUpdateConsole() {
        // v0.9.7: единый маппинг цветов (StatusConsole.roleOf), источник — LogStore (канал UPDATE)
        updateConsole.render(toConsoleLines(UpdateLogger.snapshot()))
    }

    /** v0.8: применить сохранённый манифест модулей при старте. */
    internal fun loadCachedModules() {
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
    internal fun syncModulesAsync(force: Boolean) {
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
                                UpdateLogger.add(getString(R.string.modules_progress, pct, Formats.kbps(this, kbps)))
                            }
                        }
                    }
                }
                conn.disconnect()
                val body = baos.toString("UTF-8")
                UpdateLogger.add(getString(R.string.upd_modules_received, fmtBytes(total)), LogKind.OK)
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
                    refreshConnLine()
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

    internal fun checkForUpdateAsync(showIfUpToDate: Boolean) {
        val current = currentVersion()
        UpdateLogger.add(getString(R.string.upd_check_start, current))
        refreshUpdateConsoleSafe()
        Thread {
            val info = UpdateChecker().check(current)
            if (info == null) {
                UpdateLogger.add(getString(R.string.upd_check_none), LogKind.OK)
                if (showIfUpToDate) {
                    runOnUiThread { Toast.makeText(this, R.string.update_latest, Toast.LENGTH_SHORT).show() }
                }
            } else {
                UpdateLogger.add(getString(R.string.upd_check_available, info.latestTag, info.apkUrl.substringAfterLast('/')), LogKind.OK)
                if (info.sumsUrl.isNotEmpty()) {
                    UpdateLogger.add(getString(R.string.upd_sums_found), LogKind.OK)
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
                                    val speed = Formats.kbps(this, total / 1024.0 / secs)
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
    internal fun showLimitDialog(statusText: String?) {
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

    /** v0.9.0: раз в эпизод — не спамим диалогом на каждый ретрай. */
    internal var pinMismatchDialogShown = false

    /** v0.9.0: ротация CA — ЯВНОЕ подтверждение владельца (анти-MITM канон:
     *  молча не доверяем никогда; отказ = туннель продолжает ретраить с отказом). */
    private fun showPinMismatchDialog(realPin: String) {
        if (pinMismatchDialogShown) return
        pinMismatchDialogShown = true
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pin_mismatch_title)
            .setMessage(getString(R.string.pin_mismatch_msg, realPin))
            .setPositiveButton(R.string.pin_accept) { _, _ ->
                startService(
                    Intent(this, TunnelService::class.java)
                        .setAction(TunnelService.ACTION_ACCEPT_PIN)
                        .putExtra(TunnelService.EXTRA_REAL_PIN, realPin),
                )
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    /** Строка «следующий сброс счётчика» — настройки + главный. */
    internal fun refreshLimitNext() {
        val used = prefs().getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
        val limit = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
        limitNextView.text = if (limit > 0) {
            getString(R.string.set_limit_next, nextResetDateString())
        } else {
            ""
        }
        setUsageText(usageSummaryText(used, limit))
    }

    internal fun nextResetDateString(): String {
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
                        netInfoBox, getString(R.string.net_external_ip),
                        "${e.ip}${e.country?.let { " · $it" } ?: ""}${e.isp?.let { " · $it" } ?: ""}" +
                            (if (e.source.isNotEmpty()) " · ${getString(R.string.netinfo_source, e.source)}" else ""),
                    )
                }
                if (dns == null) {
                    infoRow(netInfoBox, "DNS", getString(R.string.net_facts_failed))
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

    internal fun copyServiceLog() {
        val text = logConsole.snapshotText().ifEmpty { getString(R.string.logs_empty) }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("ReverseRay log", text))
        Toast.makeText(this, R.string.logs_copied, Toast.LENGTH_SHORT).show()
    }

    internal fun shareServiceLog() {
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

    /**
     * v1.5.0: зеркало канона ссылки в URI PRIMARY-профиля (SessionStore) —
     * legacy-писатели конфига (вставка/правка ссылки, транспорт) остаются
     * источником правды для PRIMARY, профиль не рассинхронизируется.
     */
    internal fun syncPrimaryProfileUri(canonical: String) {
        try {
            val p = prefs()
            val store = SessionStore(PrefsBackend(p))
            store.migrateLegacy(p.getString(TunnelService.KEY_CONFIG, null))
            store.active()?.let { store.update(it.copy(uri = canonical)) }
        } catch (_: Exception) {
        }
    }

    // ================================================================= Сессии (v1.5.0)

    /** SessionStore поверх prefs (миграция идемпотентна). */
    private fun sessionStore(): SessionStore {
        val store = SessionStore(PrefsBackend(prefs()))
        store.migrateLegacy(prefs().getString(TunnelService.KEY_CONFIG, null))
        return store
    }

    /** Команда дашборда/настроек в сервис по сессии (изоляция). */
    private fun sendSessionCmd(id: String, cmd: String) {
        val i = Intent(this, TunnelService::class.java)
            .setAction(TunnelService.ACTION_SESSION)
            .putExtra(TunnelService.EXTRA_SESSION_ID, id)
            .putExtra(TunnelService.EXTRA_SESSION_CMD, cmd)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
    }

    /** Цвета статусов = канон цветов главной кнопки (v1.7.0). second — пульсировать. */
    private fun stateStyle(state: String): Pair<Int, Boolean> = when (state) {
        "CONNECTED", "PROTO", "up" -> 0xFF39D98A.toInt() to false
        "CONNECTING", "RETRY", "PROTO_ROLLBACK", "connecting" -> 0xFFB26B00.toInt() to true
        "ERROR", "LIMIT_REACHED", "PIN_MISMATCH" -> 0xFFC62828.toInt() to true
        else -> 0xFFC62828.toInt() to false // отключён/остановлен — красная без пульса
    }

    /** Снимок состояний живых сессий (EXTRA_SESSIONS): id → state. */
    private fun sessionStatesSnapshot(): Map<String, String> = try {
        val arr = org.json.JSONArray(lastSessionsJson)
        val m = HashMap<String, String>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            m[o.optString("id")] = o.optString("state")
        }
        m
    } catch (_: Exception) {
        emptyMap()
    }

    /** Пульсирующая статус-точка строки сервера (v1.7.0). */
    internal fun statusDot(color: Int, pulse: Boolean): View {
        val dot = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(10), dp(10)).apply {
                gravity = Gravity.CENTER_VERTICAL
                setMargins(0, 0, dp(8), 0)
            }
            background = android.graphics.drawable.GradientDrawable().apply {
                shape = android.graphics.drawable.GradientDrawable.OVAL
                setColor(color)
            }
        }
        if (pulse) {
            android.animation.ObjectAnimator.ofFloat(dot, "alpha", 1f, 0.25f).apply {
                duration = 700
                repeatMode = android.animation.ValueAnimator.REVERSE
                repeatCount = android.animation.ValueAnimator.INFINITE
                start()
            }
        }
        return dot
    }

    /**
     * Пересборка списка серверов на «Подключении» (v1.7.0): строка =
     * статус-точка + имя + хост из ссылки + кнопки равной ширины
     * [Изменить · Вкл/Выкл · PRIMARY · Удалить].
     */
    internal fun refreshSessionsCard() {
        if (!this::sessionsBox.isInitialized) return
        preserveScroll {
            sessionsBox.removeAllViews()
            val store = sessionStore()
            val active = store.activeId()
            val states = sessionStatesSnapshot()
            for (pr in store.profiles()) {
                val (color, pulse) = stateStyle(states[pr.id] ?: "")
                val line = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
                val head = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                head.addView(statusDot(color, pulse))
                head.addView(TextView(this).apply {
                    text = (if (pr.id == active) "★ " else "") + pr.name
                    textSize = 14f
                    setTypeface(typeface, Typeface.BOLD)
                    setTextColor(0xFFFFFFFF.toInt())
                    layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                })
                head.addView(TextView(this).apply {
                    text = states[pr.id]?.let { st ->
                        getString(
                            when (st) {
                                "CONNECTED", "PROTO" -> R.string.dash_state_connected
                                "CONNECTING", "RETRY", "PROTO_ROLLBACK" -> R.string.dash_state_connecting
                                else -> R.string.dash_state_error
                            },
                        )
                    } ?: getString(if (pr.enabled) R.string.dash_state_disabled else R.string.sess_off_state)
                    textSize = 12f
                })
                line.addView(head)
                line.addView(TextView(this).apply {
                    text = try {
                        val c = RrpUri.parse(pr.uri)
                        c.host + ":" + c.ports.first()
                    } catch (_: Exception) {
                        pr.uri
                    }
                    textSize = 11f
                    setTypeface(Typeface.MONOSPACE)
                    setTextColor(0xFF8FA3D9.toInt())
                    maxLines = 1
                    ellipsize = android.text.TextUtils.TruncateAt.MIDDLE
                    setPadding(0, dp(2), 0, 0)
                })
                val btnRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                fun addBtn(labelRes: Int, onClick: () -> Unit) {
                    btnRow.addView(outlined(labelRes).apply {
                        setOnClickListener { onClick() }
                        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                            .apply { setMargins(0, dp(6), dp(6), 0) }
                    })
                }
                addBtn(R.string.sess_edit) { showEditSessionDialog(pr.id) }
                addBtn(if (pr.enabled) R.string.sess_off else R.string.sess_on) {
                    store.setEnabled(pr.id, !pr.enabled)
                    sendSessionCmd(pr.id, if (pr.enabled) "disconnect" else "connect")
                    refreshSessionsCard()
                }
                if (pr.id != active) addBtn(R.string.dash_session_primary) {
                    store.setActive(pr.id)
                    sendSessionCmd(pr.id, "primary")
                    refreshSessionsCard()
                    preserveScroll { dashboard.update(offlineStats()) }
                }
                addBtn(R.string.sess_delete) { confirmDeleteSession(pr.id) }
                line.addView(btnRow)
                sessionsBox.addView(line)
            }
        }
    }

    /**
     * v1.7.0: редактирование сервера — то же окно, что и добавление, но с
     * предзаполненными ссылкой и именем. PRIMARY синхронизирует зеркало
     * KEY_CONFIG; живая сессия переподключается с новым конфигом.
     */
    private fun showEditSessionDialog(id: String) {
        val store = sessionStore()
        val pr = store.byId(id) ?: return
        val input = TextInputEditText(this).apply {
            hint = getString(R.string.sess_add_hint)
            minLines = 1
            setTextSize(12f)
            setTypeface(Typeface.MONOSPACE)
            setText(pr.uri)
        }
        val nameInput = TextInputEditText(this).apply {
            hint = getString(R.string.sess_name_hint)
            setTextSize(12f)
            setText(pr.name)
        }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dp(16)
            setPadding(pad, pad, pad, 0)
            addView(input)
            addView(nameInput)
        }
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.sess_edit_title, pr.name))
            .setView(container)
            .setPositiveButton(R.string.link_ok, null)
            .setNegativeButton(R.string.link_cancel, null)
            .create()
        dialog.show()
        dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener { d ->
                val raw = input.text?.toString()?.trim().orEmpty()
                val name = nameInput.text?.toString()?.trim().orEmpty()
                val canonical = try {
                    RrpUri.parse(raw).serialize()
                } catch (e: Exception) {
                    Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                dialog.dismiss()
                val wasActive = pr.id == store.activeId()
                store.update(pr.copy(uri = canonical, name = name.ifBlank { pr.name }))
                if (wasActive) {
                    prefs().edit().putString(TunnelService.KEY_CONFIG, canonical).apply()
                }
                Toast.makeText(this, R.string.sess_updated, Toast.LENGTH_SHORT).show()
                refreshSessionsCard()
                sendSessionCmd(pr.id, "reconnect")
            }
    }

    /**
     * v1.5.1: добавление сервера:
     *  - чекбокс «Проверить подключение» (probe ДО сохранения — можно снять,
     *    если сервер ещё не поднят, а профиль нужен в списке);
     *  - при провале пробы — ЯВНОЕ предложение «Добавить без проверки»
     *    (v1.5.0 молча отказывал — сервер не появлялся в списке вовсе);
     *  - чекбокс «Подключить сразу» — новый профиль не остаётся выключенным.
     */
    internal fun showAddSessionDialog() {
        val input = TextInputEditText(this).apply {
            hint = getString(R.string.sess_add_hint)
            minLines = 1
            setTextSize(12f)
            setTypeface(Typeface.MONOSPACE)
        }
        val nameInput = TextInputEditText(this).apply {
            hint = getString(R.string.sess_name_hint)
            setTextSize(12f)
        }
        val verifyBox = android.widget.CheckBox(this).apply { setText(R.string.sess_verify); isChecked = true; setTextSize(12f) }
        val nowBox = android.widget.CheckBox(this).apply { setText(R.string.sess_add_now); isChecked = true; setTextSize(12f) }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dp(16)
            setPadding(pad, pad, pad, 0)
            addView(input)
            addView(nameInput)
            addView(verifyBox)
            addView(nowBox)
        }
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.sess_add_title)
            .setView(container)
            .setPositiveButton(R.string.link_ok, null)
            .setNegativeButton(R.string.link_cancel, null)
            .create()
        dialog.show()
        fun commit(name: String, canonical: String, connectNow: Boolean) {
            val store = sessionStore()
            val created = store.add(canonical, name.ifBlank { null }, enabled = connectNow)
            if (created != null) {
                Toast.makeText(this, getString(R.string.sess_added, created.name), Toast.LENGTH_LONG).show()
                refreshSessionsCard()
                if (connectNow) sendSessionCmd(created.id, "connect")
                if (lastSessionsJson.isBlank()) preserveScroll { dashboard.update(offlineStats()) }
            }
        }
        dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val raw = input.text?.toString()?.trim().orEmpty()
                val name = nameInput.text?.toString()?.trim().orEmpty()
                val cfg = try {
                    RrpUri.parse(raw)
                } catch (e: Exception) {
                    Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                val canonical = cfg.serialize()
                val connectNow = nowBox.isChecked
                if (!verifyBox.isChecked) {
                    dialog.dismiss()
                    commit(name, canonical, connectNow)
                    return@setOnClickListener
                }
                kotlin.concurrent.thread {
                    val (ok, msg) = try {
                        probeServer(cfg)
                    } catch (e: Exception) {
                        ProbeOut(false, e.message ?: "?")
                    }
                    runOnUiThread {
                        if (ok) {
                            dialog.dismiss()
                            commit(name, canonical, connectNow)
                        } else {
                            // v1.5.1: провал пробы больше НЕ теряет ссылку —
                            // предлагаем добавить без проверки (сервер мог быть
                            // временно недоступен).
                            MaterialAlertDialogBuilder(this)
                                .setMessage(getString(R.string.sess_probe_fail_add, msg))
                                .setPositiveButton(R.string.sess_anyway) { d2, _ ->
                                    d2.dismiss()
                                    dialog.dismiss()
                                    commit(name, canonical, connectNow)
                                }
                                .setNegativeButton(R.string.link_cancel, null)
                                .show()
                        }
                    }
                }
            }
    }

    /**
     * v1.6.0: пакетный импорт ссылок на «Подключении» (по одной на строку;
     * бронепарсер чинит мусор сам). Добавляются включёнными — коннект по
     * кнопке Старт (PRIMARY коннектится всегда, остальные — по enabled).
     * @return (добавлено, нераспознано).
     */
    internal fun addBulkSessions(text: String): Pair<Int, Int> {
        if (text.isBlank()) return 0 to 0
        val store = sessionStore()
        var ok = 0
        var bad = 0
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            val created = try {
                val canonical = RrpUri.parse(line).serialize()
                store.add(canonical, null, enabled = true)
            } catch (_: Exception) {
                null
            }
            if (created != null) ok++ else bad++
        }
        return ok to bad
    }

    private fun showRenameSessionDialog(id: String) {
        val store = sessionStore()
        val pr = store.byId(id) ?: return
        val input = TextInputEditText(this).apply {
            setText(pr.name)
            setTextSize(12f)
        }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dp(16)
            setPadding(pad, pad, pad, 0)
            addView(input)
        }
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.sess_rename)
            .setView(container)
            .setPositiveButton(R.string.link_ok) { d, _ ->
                d.dismiss()
                val name = input.text?.toString()?.trim().orEmpty()
                if (name.isNotBlank() && store.rename(id, name)) {
                    Toast.makeText(this, R.string.sess_renamed, Toast.LENGTH_SHORT).show()
                    refreshSessionsCard()
                    preserveScroll { dashboard.update(offlineStats()) }
                }
            }
            .setNegativeButton(R.string.link_cancel, null)
            .show()
    }

    private fun confirmDeleteSession(id: String) {
        val store = sessionStore()
        val pr = store.byId(id) ?: return
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.sess_delete)
            .setMessage(getString(R.string.sess_confirm_delete, pr.name))
            .setPositiveButton(R.string.link_ok) { d, _ ->
                d.dismiss()
                if (store.remove(id)) {
                    sendSessionCmd(id, "disconnect")
                    Toast.makeText(this, R.string.sess_removed, Toast.LENGTH_SHORT).show()
                    refreshSessionsCard()
                    preserveScroll { dashboard.update(offlineStats()) }
                }
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    internal fun prefs() = getSharedPreferences(TunnelService.PREFS, MODE_PRIVATE)

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