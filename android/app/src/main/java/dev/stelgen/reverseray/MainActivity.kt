@file:Suppress("WildcardImport") // ui.* — DSL расширений (см. комментарий у импорта)

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
import dev.stelgen.reverseray.core.ConfigResult
import dev.stelgen.reverseray.core.ConfigSource
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
import dev.stelgen.reverseray.net.DnsProbe
import dev.stelgen.reverseray.net.NetInfo
import dev.stelgen.reverseray.net.NetInfoFetcher
import dev.stelgen.reverseray.core.LogStore
import dev.stelgen.reverseray.service.LogKind
import dev.stelgen.reverseray.service.TunnelService
import dev.stelgen.reverseray.update.UpdateChecker
import dev.stelgen.reverseray.update.UpdateInfo
import dev.stelgen.reverseray.update.UpdateLogger
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import dev.stelgen.reverseray.ui.* // ui-пакет — DSL расширений MainActivity;
                                   // имена классов и builder-extension совпадают —
                                   // явный импорт невозможен (ktlint-фаза переименует)

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

    /**
     * v1.8.4: ИКОНОЧНАЯ кнопка (вкладка «Подключение», карточка сессии):
     * текст надписи уходит в contentDescription (доступность), на кнопке —
     * только стандартная системная иконка. Тач-таргет ≥ 48dp.
     */
    internal fun iconBtn(iconRes: Int, descRes: Int) =
        MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = ""
            icon = androidx.appcompat.content.res.AppCompatResources.getDrawable(this@MainActivity, iconRes)
            iconGravity = com.google.android.material.button.MaterialButton.ICON_GRAVITY_TEXT_START
            iconPadding = 0
            contentDescription = getString(descRes)
            minHeight = dp(48)
            minWidth = dp(56)
        }

    internal fun filled(textRes: Int) = MaterialButton(this).apply {
        setText(textRes)
        // v0.9.7 (GUI-этап 2): эргономика — тач-таргет ≥ 48dp на всех кнопках
        minHeight = dp(48)
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


    /** v1.6.0: 3 с в CONNECTING → красный «Тайм-аут» (канон владельца). */
    internal val connectTimeoutHandler = android.os.Handler(android.os.Looper.getMainLooper())
    internal val connectTimeoutRunnable = Runnable {
        if (lastButtonMode == Mode.CONNECTING) applyButtonMode(Mode.TIMEOUT)
    }


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

    // ================================================================= Лимит — король

    /** v0.9.0: раз в эпизод — не спамим диалогом на каждый ретрай. */
    internal var pinMismatchDialogShown = false

    // ================================================================= Панели «О …»

    // ================================================================= Лог: копировать/поделиться

    // ================================================================= Разное

    // ================================================================= Сессии (v1.5.0)

    /** SessionStore поверх prefs (миграция идемпотентна). */
    // v1.8.4: private → internal (resolvedConfig в ui/Misc.kt зовёт из расширения)
    internal fun sessionStore(): SessionStore {
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
                // v1.8.4: 4 действия карточки — иконки вместо текста
                // (изменить/вкл-выкл/сделать основным/удалить).
                fun addIcon(iconRes: Int, descRes: Int, onClick: () -> Unit) {
                    btnRow.addView(iconBtn(iconRes, descRes).apply {
                        setOnClickListener { onClick() }
                        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                            .apply { setMargins(0, dp(6), dp(6), 0) }
                    })
                }
                addIcon(android.R.drawable.ic_menu_edit, R.string.sess_edit) { showEditSessionDialog(pr.id) }
                addIcon(
                    if (pr.enabled) android.R.drawable.ic_media_pause else android.R.drawable.ic_media_play,
                    if (pr.enabled) R.string.sess_off else R.string.sess_on,
                ) {
                    store.setEnabled(pr.id, !pr.enabled)
                    sendSessionCmd(pr.id, if (pr.enabled) "disconnect" else "connect")
                    refreshSessionsCard()
                }
                if (pr.id != active) addIcon(R.drawable.ic_star, R.string.dash_session_primary) {
                    store.setActive(pr.id)
                    sendSessionCmd(pr.id, "primary")
                    refreshSessionsCard()
                    preserveScroll { dashboard.update(offlineStats()) }
                }
                addIcon(android.R.drawable.ic_menu_delete, R.string.sess_delete) { confirmDeleteSession(pr.id) }
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
                // v1.8.4: единая валидация ConfigSource; зеркало KEY_CONFIG
                // синхронизирует SessionStore.update() для PRIMARY (единственная
                // точка — без ручного дублирования).
                val canonical = when (val res = ConfigSource.validate(raw)) {
                    is ConfigResult.Valid -> res.canonical
                    is ConfigResult.Invalid -> {
                        Toast.makeText(this, getString(R.string.invalid_config, res.reason), Toast.LENGTH_LONG).show()
                        return@setOnClickListener
                    }
                    ConfigResult.Empty -> {
                        Toast.makeText(this, getString(R.string.invalid_config, getString(R.string.status_no_config)), Toast.LENGTH_LONG).show()
                        return@setOnClickListener
                    }
                }
                dialog.dismiss()
                store.update(pr.copy(uri = canonical, name = name.ifBlank { pr.name }))
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
                // v1.8.4: единая валидация ConfigSource (была своя try/catch parse)
                val cfg = when (val res = ConfigSource.validate(raw)) {
                    is ConfigResult.Valid -> res.cfg
                    is ConfigResult.Invalid -> {
                        Toast.makeText(this, getString(R.string.invalid_config, res.reason), Toast.LENGTH_LONG).show()
                        return@setOnClickListener
                    }
                    ConfigResult.Empty -> {
                        Toast.makeText(this, getString(R.string.invalid_config, getString(R.string.status_no_config)), Toast.LENGTH_LONG).show()
                        return@setOnClickListener
                    }
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
            val created = when (val res = ConfigSource.validate(line)) {
                is ConfigResult.Valid -> store.add(res.canonical, null, enabled = true)
                else -> null
            }
            if (created != null) ok++ else bad++
        }
        return ok to bad
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

    internal companion object {
        const val NETINFO_REFRESH_MS = 60_000L
        /** v1.6.0: 3 с в CONNECTING → красный «Тайм-аут» (канон владельца). */
        internal const val CONNECT_TIMEOUT_MS = 3_000L
        internal const val START_COOLDOWN_MS = 1_200L
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