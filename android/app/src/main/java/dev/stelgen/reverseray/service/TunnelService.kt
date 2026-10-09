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
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import dev.stelgen.reverseray.MainActivity
import dev.stelgen.reverseray.L10nUi
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.Apimask
import dev.stelgen.reverseray.core.Msgs
import dev.stelgen.reverseray.core.ProtoFallback
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.RrpUriConfig
import dev.stelgen.reverseray.ui.Formats
import java.net.NetworkInterface
import dev.stelgen.reverseray.net.SpeedTest
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.Random
import java.util.concurrent.atomic.AtomicLong

/**
 * Foreground-сервис: держит пул RrpClient (по одному на порт из конфига).
 *
 * - уведомления: channels на 26+, просто Notification на старых;
 * - сеть: NetworkCallback на 21+, CONNECTIVITY_ACTION — фолбэк для <21;
 * - при появлении сети — мгновенный retry всех коннектов с cooldown 3 c;
 * - экспоненциальный backoff 1→60 c ±30 % (RrpClient.backoffDelayMs);
 *
 * v0.8:
 * - ЛИМИТ ТРАФИКА — КОРОЛЬ: при исчерпании отправляется РОВНО НОЛЬ байт
 *   (туннель останавливается, все кадры затыкаются), на экране — сообщение
 *   и отдельное окно при нажатии Старт/Реконнект; счётчик живёт в RAM и
 *   пишется на память РЕДКО (раз в минуту — дисциплина SSD/памяти);
 * - автоподключение (по умолчанию выкл): при достигнутом лимите ждём
 *   даты сброса и переподключаемся только после него;
 * - спидтест 5 с после CONNECTED — только если лимит не достигнут;
 * - счётчик трафика за всё время (KEY_TRAFFIC_LIFETIME) — запись раз в минуту;
 * - журнал статуса с цветовыми ролями (зелёный/красный/тёмно-жёлтый/белый)
 *   для единого консольного окна на всех вкладках.
 *
 * v0.7.4:
 * - СМЕНА ПРОТОКОЛА с валидацией реального трафика (PROBE до реального хоста):
 *   provisional-коннект с новым протоколом → PROBE → коммит (запись ссылки
 *   и протокола) только после успеха; при неудаче — мгновенный откат UI
 *   и остаёмся на последнем рабочем протоколе. Анти-цикл: 3 ретрая с паузой,
 *   cooldown 60 с между сменами, ссылка не трогается до валидации.
 * - ЛИМИТ ТРАФИКА (по умолчанию без ограничений): сумма вход+выход за период
 *   (сутки/календарный месяц с днём сброса); превышение → туннель останавливается.
 * - ТОЛЬКО WI-FI: не поднимать туннель в мобильной сети, стартовать при появлении Wi-Fi.
 * - ЛОГИ НАСТРОЕК: изменённые настройки попадают в статус-лог только при
 *   фактическом изменении значения.
 * - Счётчики пакетов/последний размер для строки «стрелки» на главном экране.
 */
/** Роль строки журнала — цвет в едином консольном окне (v0.8). Файловый уровень:
 *  импортируется MainActivity и тестами. */
enum class LogKind { INFO, OK, WARN, ERR }

/** Строка журнала с цветовой ролью. */
class LogLine(val text: String, val kind: LogKind)

class TunnelService : Service() {

    // v0.8.3: язык сервиса/уведомлений из prefs (канон i18n)
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(L10nUi.wrap(base))
    }

    private class Target(val host: String, val port: Int)

    @Volatile private var lifetime: AtomicLong = AtomicLong(0)

    private inner class Runner(val target: Target) {
        @Volatile var kick = false
        /** активный клиент — для форс-закрытия при stopTunnel (иначе стоп ждёт handshake-таймаут до 20с) */
        @Volatile var client: RrpClient? = null
    }

    private val runners = mutableListOf<Runner>()
    private val rnd = Random()
    private val lastNetKick = AtomicLong(0)
    @Volatile private var statsThread: Thread? = null
    private var lastTx = 0L
    private var lastRx = 0L

    @Volatile private var config: RrpUriConfig? = null
    @Volatile private var stopping = true
    private var wakeLock: PowerManager.WakeLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var legacyReceiver: BroadcastReceiver? = null

    /** Идёт ли сейчас валидационная смена протокола. */
    @Volatile private var switchingProto = false
    /** Спидтест не молотит при каждом READY. */
    @Volatile private var speedTestBusy = false
    /** Ждун сброса лимита для авто-переподключения. */
    @Volatile private var limitWaitThread: Thread? = null

    private val clientListener = object : RrpClient.Listener {
        override fun onLog(client: RrpClient, message: String) {
            Log.d(TAG, "${client.host}:${client.port}: $message")
            pushLog("${client.host}:${client.port}: $message")
        }

        // v0.9.0: пин из ссылки не совпал — UI предлагает владельцу ЯВНО
        // принять новый пин (анти-MITM канон: молча не доверяем никогда)
        override fun onPinMismatch(client: RrpClient, realPin: String) {
            sendBroadcast(
                Intent(ACTION_STATUS).setPackage(packageName)
                    .putExtra(EXTRA_STATE, STATE_PIN_MISMATCH)
                    .putExtra(EXTRA_STATUS, getString(R.string.pin_mismatch_status))
                    .putExtra(EXTRA_REAL_PIN, realPin)
            )
        }

        override fun onState(client: RrpClient, state: RrpClient.State) {
            if (state == RrpClient.State.READY) {
                if (client.mtProtoActive) {
                    pushLog(getString(R.string.log_mtp_keys), LogKind.OK)
                }
                sendBroadcast(
                    Intent(ACTION_STATUS).setPackage(packageName)
                        .putExtra(EXTRA_STATUS, client.negotiatedProto)
                        .putExtra(EXTRA_STATE, STATE_PROTO)
                        .putExtra(EXTRA_PROTO, client.negotiatedProto)
                )
                maybeRunSpeedTest()
            }
        }
    }

    /** Спидтест 5 с — ровно один раз на сессию, ТОЛЬКО если лимит не достигнут.
     *  v0.8.1: честно показываем ВСЕ внешние хосты (HTTP-проверка, TCP-пинг,
     *  скачивание) — канон «куда пошли — обо всём признаёмся». */
    private fun maybeRunSpeedTest() {
        if (stopping) return
        val usage = accountTraffic(0)
        if (usage.limit > 0 && usage.used >= usage.limit) {
            pushLog(getString(R.string.log_speedtest_skipped), LogKind.WARN)
            return
        }
        if (speedTestBusy) return
        speedTestBusy = true
        pushLog(getString(R.string.log_speedtest_plan, SpeedTest.plan().joinToString(" · ")))
        Thread {
            val r = SpeedTest.run()
            r.endpoints.forEach { pushLog(getString(R.string.log_speedtest_line, it)) }
                val line = if (r.ok) {
                val mbs = String.format(Locale.US, "%.2f", r.bytesPerSec / 1024.0 / 1024.0)
                getString(
                    R.string.log_speedtest_result,
                    mbs, r.pingMs,
                    if (r.httpOk) getString(R.string.speed_http_ok, r.httpMs) else getString(R.string.speed_http_down),
                    fmtBytes(r.totalBytes), r.durationMs / 1000,
                )
            } else {
                getString(R.string.log_speedtest_failed, r.error ?: getString(R.string.speed_no_data))
            }
            pushLog(line, if (r.ok) LogKind.OK else LogKind.WARN)
            sendBroadcast(
                Intent(ACTION_STATS).setPackage(packageName)
                    .putExtra(EXTRA_SPEEDTEST_TEXT, line)
            )
            speedTestBusy = false
        }.apply { isDaemon = true }.start()
    }

    // v0.8.3: единицы из ресурсов (динамический язык) — общий Formats (дубль удалён)
    private fun fmtBytes(b: Long): String = Formats.bytes(this, b)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        lifetime = AtomicLong(prefs().getLong(KEY_TRAFFIC_LIFETIME, 0L))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_SWITCH_PROTO -> {
                val p = RrpProtocols.normalize(intent.getStringExtra(EXTRA_PROTO))
                startForegroundCompat(getString(R.string.notif_starting))
                Thread({ switchProtocol(p) }, "rrp-switch").start()
                return START_STICKY
            }
            ACTION_ACCEPT_PIN -> {
                // v0.9.0: владелец ЯВНО принял новый пин CA — обновляем ссылку,
                // пишем в журнал и реконнектим. Никакого молчаливого доверия.
                val newPin = intent.getStringExtra(EXTRA_REAL_PIN)
                val link = prefs().getString(KEY_CONFIG, null)
                val updated = newPin?.let { RrpUri.replacePin(link ?: "", it) }
                if (updated != null) {
                    prefs().edit().putString(KEY_CONFIG, updated).apply()
                    pushLog(Msgs.PIN_ACCEPTED.t(newPin ?: ""), LogKind.WARN)
                    startTunnel()
                } else {
                    pushLog(Msgs.SEND_FAILED.t("pin update failed"), LogKind.ERR)
                }
                return START_STICKY
            }
            else -> startTunnel()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    // ---------- туннель ----------

    private fun currentProto(): String = RrpProtocols.normalize(prefs().getString(KEY_PROTO, null) ?: RrpProtocols.DEFAULT)

    private fun startTunnel() {
        if (!stopping && runners.isNotEmpty()) {
            updateStatus(STATE_INFO, getString(R.string.status_already_running))
            return
        }
        val cfg = try {
            prefs().getString(KEY_CONFIG, null)?.let { RrpUri.parse(it) }
        } catch (e: Exception) {
            Log.w(TAG, getString(R.string.log_config_parse_failed, e.message))
            null
        }
        if (cfg == null) {
            updateStatus(STATE_ERROR, getString(R.string.status_no_config))
            stopSelf()
            return
        }
        config = cfg
        stopping = false
        startForegroundCompat(getString(R.string.notif_starting))
        acquireWakeLock()
        logDevicePreamble(cfg)

        // v0.7.4: «только по Wi-Fi» — в мобильной сети туннель не поднимаем;
        // NetworkCallback дёрнет kickAll при появлении Wi-Fi.
        if (wifiOnly() && !isOnWifi()) {
            updateStatus(STATE_INFO, getString(R.string.status_wait_wifi))
            registerNetworkWatching()
            startStatsLoop()
            return
        }

        spawnRunners()
        registerNetworkWatching()
        startStatsLoop()
        updateStatus(STATE_CONNECTING, getString(R.string.status_connecting, cfg.host))
    }

    private fun spawnRunners() {
        val cfg = config ?: return
        val proto = currentProto()
        for (port in cfg.ports) {
            val r = Runner(Target(cfg.host, port))
            synchronized(runners) { runners.add(r) }
            Thread({ runLoop(r, proto) }, "rrp-conn-$port").start()
        }
    }

    /** Информация об устройстве — в журнал простым текстом (одна строка на старт). */
    private fun logDevicePreamble(cfg: RrpUriConfig) {
        try {
            val info = getString(
                R.string.log_device_info,
                Build.MANUFACTURER, Build.MODEL, Build.VERSION.RELEASE, Build.VERSION.SDK_INT,
                Build.DISPLAY, currentProto(), cfg.host, cfg.ports.joinToString(","),
            )
            pushLog(info)
        } catch (_: Exception) {}
    }

    /** Реалтайм-статистика трафика: раз в 500 мс шлёт ACTION_STATS (байт/с). */
    private fun startStatsLoop() {
        if (statsThread?.isAlive == true) return
        lastTx = 0
        lastRx = 0
        val t = Thread({
            var persistTick = 0
            while (!stopping) {
                try {
                    Thread.sleep(STATS_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                var tx = 0L
                var rx = 0L
                var pk = longArrayOf(0, 0, 0, 0)
                var kind = ""
                synchronized(runners) {
                    runners.forEach { r ->
                        r.client?.bytesSnapshot()?.let { (a, b) -> tx += a; rx += b }
                        r.client?.packetsSnapshot()?.let { p ->
                            pk[0] += p[0]; pk[1] += p[1]; pk[2] = p[2]; pk[3] = p[3]
                        }
                        if (r.client?.lastPacketKind?.isNotEmpty() == true) kind = r.client!!.lastPacketKind
                    }
                }
                val dtx = tx - lastTx
                val drx = rx - lastRx
                lastTx = tx
                lastRx = rx

                // v0.8: счётчик за всё время (канон: RAM, запись на диск пореже)
                prefs().edit()
                    .putLong(KEY_TRAFFIC_LIFETIME, lifetime.addAndGet(drx + dtx)).apply()
                // v0.7.4/v0.8: учёт лимита трафика (сумма вход+выход за период)
                val usage = accountTraffic(drx + dtx)

                sendBroadcast(
                    Intent(ACTION_STATS)
                        .setPackage(packageName)
                        .putExtra(EXTRA_TX_RATE, dtx * 1000L / STATS_INTERVAL_MS)
                        .putExtra(EXTRA_RX_RATE, drx * 1000L / STATS_INTERVAL_MS)
                        .putExtra(EXTRA_TX_TOTAL, tx)
                        .putExtra(EXTRA_RX_TOTAL, rx)
                        .putExtra(EXTRA_PKT_TX_COUNT, pk[0])
                        .putExtra(EXTRA_PKT_RX_COUNT, pk[1])
                        .putExtra(EXTRA_PKT_TX_SIZE, pk[2])
                        .putExtra(EXTRA_PKT_RX_SIZE, pk[3])
                        .putExtra(EXTRA_PKT_KIND, kind)
                        .putExtra(EXTRA_USAGE_BYTES, usage.used)
                        .putExtra(EXTRA_USAGE_LIMIT, usage.limit)
                )
                if (usage.limit > 0 && usage.used >= usage.limit) {
                    // КАНОН «ЛИМИТ — КОРОЛЬ»: ровно ноль байт от нас.
                    updateStatus(STATE_ERROR, getString(R.string.status_limit_reached))
                    pushLog(getString(R.string.status_limit_reached), LogKind.ERR)
                    sendBroadcast(
                        Intent(ACTION_STATUS).setPackage(packageName)
                            .putExtra(EXTRA_STATE, STATE_LIMIT_REACHED)
                            .putExtra(EXTRA_STATUS, getString(R.string.status_limit_reached))
                            .putExtra(EXTRA_USAGE_BYTES, usage.used)
                            .putExtra(EXTRA_USAGE_LIMIT, usage.limit)
                    )
                    stopTunnel() // туннель и все коннекты умирают — ноль байт
                    maybeWaitLimitReset()
                    return@Thread
                }
                // персистим счётчик РАЗ В МИНУТУ (дисциплина SSD/памяти, v0.8)
                if (++persistTick >= PERSIST_EVERY_TICKS) {
                    persistTick = 0
                    persistUsage()
                }
            }
        }, "rrp-stats").apply { isDaemon = true; start() }
        statsThread = t
    }

    // ---------- лимит трафика ----------

    private data class Usage(val used: Long, val limit: Long)

    /**
     * Ожидание сброса лимита (авто-реконнект вкл): вычисляем дату следующего
     * сброса и ждём её, не тратя батарейку/трафик (грубые проверки раз в
     * минуту). По сбросу — реконнект. Выключаемо нитью stopTunnel().
     */
    private fun maybeWaitLimitReset() {
        if (!prefs().getBoolean(KEY_AUTO_RECONNECT, false)) return
        if (limitWaitThread?.isAlive == true) return
        val period = prefs().getString(KEY_LIMIT_PERIOD, PERIOD_DAY) ?: PERIOD_DAY
        val day = prefs().getInt(KEY_LIMIT_RESET_DAY, 1)
        val at = nextResetAtMs(period, day)
        val hours = ((at - System.currentTimeMillis()) / 3_600_000L).coerceAtLeast(0)
        pushLog(getString(R.string.status_limit_wait, hours), LogKind.WARN)
        updateStatus(STATE_LIMIT_REACHED, getString(R.string.status_limit_reached))
        val t = Thread {
            while (!stopping) {
                val usage = accountTraffic(0)
                if (usage.limit <= 0) {
                    pushLog(getString(R.string.log_limit_removed), LogKind.OK)
                    startTunnel()
                    return@Thread
                }
                if (System.currentTimeMillis() >= at) {
                    pushLog(getString(R.string.log_limit_period), LogKind.OK)
                    startTunnel()
                    return@Thread
                }
                try {
                    Thread.sleep(LIMIT_POLL_MS)
                } catch (_: InterruptedException) {
                    return@Thread
                }
            }
        }
        t.isDaemon = true
        limitWaitThread = t
        t.start()
    }

    /** Следующая дата сброса: сутки — завтра в это же время; месяц — день сброса. */
    internal fun nextResetAtMs(period: String, day: Int): Long {
        val cal = Calendar.getInstance()
        if (period == PERIOD_MONTH) {
            cal.add(Calendar.MONTH, 1)
            cal.set(Calendar.DAY_OF_MONTH, day.coerceIn(1, 28))
        } else {
            cal.add(Calendar.DAY_OF_YEAR, 1)
        }
        cal.set(Calendar.HOUR_OF_DAY, 0)
        cal.set(Calendar.MINUTE, 0)
        cal.set(Calendar.SECOND, 0)
        cal.set(Calendar.MILLISECOND, 0)
        return cal.timeInMillis
    }

    /** Сбрасывает счётчик при смене периода, возвращает [used, limit]. */
    private fun accountTraffic(delta: Long): Usage {
        val p = prefs()
        val limit = p.getLong(KEY_TRAFFIC_LIMIT, 0L)
        val period = p.getString(KEY_LIMIT_PERIOD, PERIOD_DAY) ?: PERIOD_DAY
        val key = usagePeriodKey(period)
        var used = p.getLong(KEY_TRAFFIC_USED, 0L)
        if (p.getString(KEY_USAGE_PERIOD, null) != key) {
            used = 0
            p.edit().putString(KEY_USAGE_PERIOD, key).apply()
        }
        if (delta > 0) used += delta
        return Usage(used, limit)
    }

    private fun persistUsage() {
        val usage = accountTraffic(0)
        prefs().edit().putLong(KEY_TRAFFIC_USED, usage.used).apply()
    }

    /** Ключ периода: "2026-10-08" для суток, "2026-10" для месяца. */
    private fun usagePeriodKey(period: String): String {
        val fmt = if (period == PERIOD_MONTH) "yyyy-MM" else "yyyy-MM-dd"
        return SimpleDateFormat(fmt, Locale.ROOT).format(Date())
    }

    private fun wifiOnly(): Boolean = prefs().getBoolean(KEY_WIFI_ONLY, false)

    /** Подключение сейчас по Wi-Fi? (API 21+: capabilities; 14–20: legacy тип). */
    @Suppress("DEPRECATION")
    private fun isOnWifi(): Boolean {
        val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return try {
            if (Build.VERSION.SDK_INT >= 23) {
                val net = cm.activeNetwork ?: return false
                val caps = cm.getNetworkCapabilities(net) ?: return false
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            } else {
                val info = cm.activeNetworkInfo
                info != null && info.type == ConnectivityManager.TYPE_WIFI && info.isConnected
            }
        } catch (_: Exception) {
            false
        }
    }

    // ---------- смена протокола (валидация → коммит, иначе откат) ----------

    /**
     * Валидационная смена протокола:
     * 1) provisional-коннект с новым протоколом + PROBE реального хоста;
     * 2) успех → коммит: сохраняем протокол и обновляем ссылку в конфиге;
     * 3) неудача (3 ретрая) → мгновенный откат UI на текущий протокол,
     *    ссылка НЕ меняется; cooldown, чтобы не молотить по rate-limit.
     */
    private fun switchProtocol(newProtoRaw: String) {
        val newProto = RrpProtocols.normalize(newProtoRaw)
        val oldProto = currentProto()
        val p = prefs()
        if (switchingProto) {
            updateStatus(STATE_INFO, getString(R.string.status_switch_busy))
            return
        }
        val now = System.currentTimeMillis()
        if (now < nextSwitchAllowedAt) {
            updateStatus(STATE_INFO, getString(R.string.status_switch_cooldown, (nextSwitchAllowedAt - now) / 1000))
            return
        }
        if (newProto == oldProto) {
            updateStatus(STATE_INFO, getString(R.string.status_switch_same, newProto))
            return
        }
        switchingProto = true
        try {
            val cfg = try {
                RrpUri.parse(p.getString(KEY_CONFIG, null) ?: "")
            } catch (e: Exception) {
                updateStatus(STATE_ERROR, getString(R.string.status_no_config))
                return
            }
            updateStatus(STATE_CONNECTING, getString(R.string.status_switch_trying, newProto))
            var lastErr = ""
            for (attempt in 1..SWITCH_RETRIES) {
                val client = buildClient(cfg, newProto, validate = true)
                try {
                    client.connect()
                    // валидация (PROBE) уже прошла внутри connect() — коммитим
                    commitProto(newProto, cfg)
                    updateStatus(STATE_CONNECTED, getString(R.string.status_switch_done, newProto))
                    try { client.close() } catch (_: Exception) {}
                    restartRunnersQuietly()
                    return
                } catch (e: Exception) {
                    lastErr = e.message ?: "?"
                    pushLog(getString(R.string.log_proto_attempt, attempt, SWITCH_RETRIES, lastErr))
                    updateStatus(STATE_ERROR, getString(R.string.status_switch_fail, newProto, lastErr))
                } finally {
                    try { client.close() } catch (_: Exception) {}
                }
                if (attempt < SWITCH_RETRIES) {
                    try { Thread.sleep(SWITCH_RETRY_PAUSE_MS) } catch (_: InterruptedException) { break }
                }
            }
            // откат: UI вернёт выбор на старый протокол сразу, не дожидаясь реконнекта
            nextSwitchAllowedAt = System.currentTimeMillis() + SWITCH_COOLDOWN_MS
            updateStatus(STATE_ERROR, getString(R.string.status_switch_rolled_back, newProto, oldProto, lastErr))
            sendBroadcast(
                Intent(ACTION_STATUS).setPackage(packageName)
                    .putExtra(EXTRA_STATE, STATE_PROTO_ROLLBACK)
                    .putExtra(EXTRA_STATUS, getString(R.string.status_switch_rolled_back, newProto, oldProto, lastErr))
                    .putExtra(EXTRA_PROTO, oldProto)
            )
        } finally {
            switchingProto = false
        }
    }

    /** Коммит: протокол + ссылка с новым proto= сохраняются ПОСЛЕ успешной валидации. */
    private fun commitProto(proto: String, cfg: RrpUriConfig) {
        prefs().edit().putString(KEY_PROTO, proto).apply()
        // обновляем ссылку: proto= должен отражать реально работающий протокол
        val updated = cfg.copy(proto = proto).serialize()
        prefs().edit().putString(KEY_CONFIG, updated).apply()
        pushLog(getString(R.string.log_proto_applied, proto))
    }

    /** Перезапуск рабочих коннектов с новым протоколом (без смены статуса). */
    private fun restartRunnersQuietly() {
        if (stopping) return
        val active: List<Runner>
        synchronized(runners) {
            active = runners.toList()
            runners.clear()
        }
        active.forEach {
            it.kick = true
            try { it.client?.close() } catch (_: Exception) {}
        }
        spawnRunners()
    }

    private fun buildClient(cfg: RrpUriConfig, proto: String, validate: Boolean): RrpClient {
        return RrpClient(
            host = cfg.host,
            port = cfg.ports.firstOrNull() ?: 4433,
            token = cfg.token,
            pin = cfg.pin,
            allowLan = allowLan(),
            listener = clientListener,
            deviceName = cfg.name?.takeIf { it.isNotBlank() } ?: "phone-1",
            transport = cfg.transport,
            agentName = "ReverseRay-Android/" + appVersion(),
            noisePolicy = buildNoisePolicy(),
            protoId = proto,
            validateProbeTarget = if (validate) prefs().getString(KEY_PROBE_TARGET, DEFAULT_PROBE_TARGET) else null,
        )
    }

    /**
     * v0.8.2: политика шума камуфляжа «API Mask» из ОБЩЕГО манифеста
     * (включён манифестом + подтверждён сервером в READY). Шаблоны строк
     * лога — на языке приложения (ресурсы), честно: сколько байт, бюджет.
     */
    private fun buildNoisePolicy(): Apimask.NoisePolicy? {
        val cfg = RrpProtocols.camouflageConfig()
        if (!cfg.enabled) return null
        val engine = Apimask.Engine(cfg)
        val label = RrpProtocols.camouflageLabel()
        return Apimask.NoisePolicy(engine) { bytes, used, budget ->
            if (bytes > 0) {
                getString(R.string.apimask_beat, label, bytes, fmtBytes(used), fmtBytes(budget.toLong()))
            } else {
                getString(R.string.apimask_budget_done, label, fmtBytes(used), fmtBytes(budget.toLong()))
            }
        }
    }

    private fun appVersion(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
    } catch (_: Exception) {
        "?"
    }

    private fun runLoop(r: Runner, proto: String) {
        var attempt = 0
        var lastError = "?"
        // v0.8.1: подряд идущие неудачи на ТЕКУЩЕМ протоколе (для фоллбека)
        var failStreak = 0
        while (!stopping) {
            val cfg = config ?: break
            // протокол перечитываем КАЖДУЮ итерацию: так подхватывается
            // и смена протокола, и фоллбек, и заморозка обновлений (без пересоздания)
            val useProto = RrpProtocols.normalize(
                prefs().getString(KEY_PROTO, null) ?: RrpProtocols.DEFAULT,
            )
            val client = RrpClient(
                host = r.target.host,
                port = r.target.port,
                token = cfg.token,
                pin = cfg.pin,
                allowLan = allowLan(),
                listener = clientListener,
                deviceName = cfg.name?.takeIf { it.isNotBlank() } ?: "phone-1",
                transport = cfg.transport,
                agentName = "ReverseRay-Android/" + appVersion(),
                noisePolicy = buildNoisePolicy(),
                protoId = useProto,
            )
            r.client = client
            try {
                client.connect()
                failStreak = 0
                attempt = 0
                updateStatus(STATE_CONNECTED, getString(R.string.status_connected, r.target.port))
                while (!stopping && client.state == RrpClient.State.READY) {
                    try {
                        Thread.sleep(500)
                    } catch (_: InterruptedException) {
                        break
                    }
                }
            } catch (e: Exception) {
                lastError = e.message ?: "?"
                failStreak++
                updateStatus(STATE_ERROR, getString(R.string.status_error, r.target.port, lastError))
                // v0.8.1 КАНОН ФОЛЛБЕКА: новый модуль протокола сломал клиент →
                // откатываемся на предыдущий рабочий (rrp1). Сервер НЕ откатываем
                // (анти-цикл: обновления рассинхронизированы, авто-обновление
                // может быть отключено — модули заморожены, это не должно ломать).
                if (ProtoFallback.shouldFallback(useProto, failStreak)) {
                    pushLog(ProtoFallback.fallbackReason(useProto), LogKind.WARN)
                    applyProtoFallback(useProto)
                    return
                }
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
            r.client = null
            if (stopping) break
            attempt++
            val delay = RrpClient.backoffDelayMs(attempt - 1, rnd)
            // ERROR держится на экране минимум HOLD_ERROR_MS, чтобы юзер
            // успел прочитать причину, а не мигал «реконнект».
            try { Thread.sleep(ERROR_HOLD_MS) } catch (_: InterruptedException) {}
            if (stopping) break
            updateStatus(STATE_RETRY, getString(R.string.status_retry_last, r.target.port, delay / 1000, lastError))
            sleepWithKick(r, delay)
        }
    }

    /**
     * v0.8.1: клиентский фоллбек на фундамент (rrp1) — сохраняем протокол и
     * ссылку (proto= отражает реально работающий), перезапускаем коннекты.
     * UI получает STATE_PROTO_ROLLBACK и обновляет строку протокола.
     */
    private fun applyProtoFallback(brokenProto: String) {
        val p = prefs()
        p.edit().putString(KEY_PROTO, RrpProtocols.DEFAULT).apply()
        try {
            val cfg = RrpUri.parse(p.getString(KEY_CONFIG, "") ?: "")
            if (cfg.proto != RrpProtocols.DEFAULT) {
                p.edit().putString(KEY_CONFIG, cfg.copy(proto = RrpProtocols.DEFAULT).serialize()).apply()
            }
        } catch (_: Exception) {
        }
        sendBroadcast(
            Intent(ACTION_STATUS).setPackage(packageName)
                .putExtra(EXTRA_STATE, STATE_PROTO_ROLLBACK)
                .putExtra(EXTRA_STATUS, ProtoFallback.fallbackReason(brokenProto))
                .putExtra(EXTRA_PROTO, RrpProtocols.DEFAULT)
        )
        if (!stopping) {
            restartRunnersQuietly()
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
        val active: List<Runner>
        synchronized(runners) {
            active = runners.toList()
            runners.clear()
        }
        active.forEach {
            it.kick = true
            try { it.client?.close() } catch (_: Exception) {}
        }
        statsThread?.interrupt()
        statsThread = null
        limitWaitThread?.interrupt()
        limitWaitThread = null
        unregisterNetworkWatching()
        releaseWakeLock()
        persistUsageSafely()
        updateStatus(STATE_STOPPED, getString(R.string.status_stopped))
    }

    private fun persistUsageSafely() {
        try { persistUsage() } catch (_: Exception) {}
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
                Log.w(TAG, getString(R.string.log_netcallback_failed, e.message))
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
        Log.d(TAG, getString(R.string.log_network_back))
        // wifi-only: kick только если мы на Wi-Fi
        if (wifiOnly() && !isOnWifi()) {
            updateStatus(STATE_INFO, getString(R.string.status_wait_wifi))
            return
        }
        synchronized(runners) { runners.forEach { it.kick = true } }
        // если туннель ещё не поднимался из-за отсутствия Wi-Fi — поднимаем
        if (runners.isEmpty() && !stopping) spawnRunners()
    }

    private fun unregisterNetworkWatching() {
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

    // ---------- foreground / уведомления ----------

    private fun startForegroundCompat(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
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
        builder
            .setSmallIcon(R.drawable.ic_stat_reverseray)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setOngoing(true)
        return if (Build.VERSION.SDK_INT >= 16) {
            builder.build()
        } else {
            @Suppress("DEPRECATION")
            builder.getNotification() // API 14-15: build() ещё нет
        }
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

    private fun updateStatus(state: String, text: String) {
        lastStatus = text
        // цветовая роль по состоянию (канон единого консольного окна v0.8)
        val kind = when (state) {
            STATE_CONNECTED, STATE_PROTO -> LogKind.OK
            STATE_ERROR, STATE_STOPPED, STATE_LIMIT_REACHED -> LogKind.ERR
            STATE_CONNECTING, STATE_RETRY -> LogKind.WARN
            else -> LogKind.INFO
        }
        pushLog(text, kind)
        sendBroadcast(
            Intent(ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(EXTRA_STATUS, text)
                .putExtra(EXTRA_STATE, state)
        )
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

        // v0.7.4: протокол и лимит трафика
        const val KEY_PROTO = "proto"
        const val KEY_TRAFFIC_LIMIT = "traffic_limit"      // байт; 0 = без лимита
        const val KEY_LIMIT_PERIOD = "limit_period"        // PERIOD_DAY | PERIOD_MONTH
        const val KEY_LIMIT_RESET_DAY = "limit_reset_day"  // 1..28 (для месяца)
        const val KEY_TRAFFIC_USED = "traffic_used"        // израсходовано за период
        const val KEY_USAGE_PERIOD = "usage_period"        // ключ периода ("2026-10-08")
        const val KEY_WIFI_ONLY = "wifi_only"
        const val KEY_PROBE_TARGET = "probe_target"
        const val KEY_AUTO_UPDATE = "auto_update"          // проверка обновлений раз в 24 ч
        const val KEY_THEME = "theme"                      // v0.8.1: auto|dark|light
        // v0.8:
        const val KEY_AUTO_RECONNECT = "auto_reconnect"    // автоподключение при открытии + ожидание сброса лимита (выкл по умолчанию)
        const val KEY_TRAFFIC_LIFETIME = "traffic_lifetime" // суммарный трафик за всё время
        const val PERIOD_DAY = "day"
        const val PERIOD_MONTH = "month"
        const val DEFAULT_PROBE_TARGET = "1.1.1.1:443"

        const val STATE_CONNECTING = "CONNECTING"
        const val STATE_CONNECTED = "CONNECTED"
        const val STATE_RETRY = "RETRY"
        const val STATE_ERROR = "ERROR"
        const val STATE_STOPPED = "STOPPED"
        const val STATE_INFO = "INFO"
        const val STATE_PROTO = "PROTO"
        const val STATE_PROTO_ROLLBACK = "PROTO_ROLLBACK"
        const val STATE_LIMIT_REACHED = "LIMIT_REACHED" // v0.8: лимит — отдельное важное состояние
        const val STATE_PIN_MISMATCH = "PIN_MISMATCH" // v0.9.0: ротация CA — явное подтверждение владельца
        const val EXTRA_REAL_PIN = "real_pin" // v0.9.0: фактический пин сервера (base64url канона ссылки)
        const val ACTION_ACCEPT_PIN = "dev.stelgen.reverseray.action.ACCEPT_PIN" // v0.9.0

        const val EXTRA_STATE = "state"

        const val ACTION_START = "dev.stelgen.reverseray.action.START"
        const val ACTION_STOP = "dev.stelgen.reverseray.action.STOP"
        const val ACTION_STATUS = "dev.stelgen.reverseray.action.STATUS"
        const val ACTION_STATS = "dev.stelgen.reverseray.action.STATS"
        const val ACTION_SWITCH_PROTO = "dev.stelgen.reverseray.action.SWITCH_PROTO"
        const val EXTRA_STATUS = "status"
        const val EXTRA_TX_RATE = "tx_rate"
        const val EXTRA_RX_RATE = "rx_rate"
        const val EXTRA_TX_TOTAL = "tx_total"
        const val EXTRA_RX_TOTAL = "rx_total"
        const val EXTRA_PROTO = "proto"
        const val EXTRA_PKT_TX_COUNT = "pkt_tx_count"
        const val EXTRA_PKT_RX_COUNT = "pkt_rx_count"
        const val EXTRA_PKT_TX_SIZE = "pkt_tx_size"
        const val EXTRA_PKT_RX_SIZE = "pkt_rx_size"
        const val EXTRA_PKT_KIND = "pkt_kind"
        const val EXTRA_USAGE_BYTES = "usage_bytes"
        const val EXTRA_USAGE_LIMIT = "usage_limit"
        const val EXTRA_SPEEDTEST_TEXT = "speedtest_text" // v0.8: строка спидтеста
        private const val STATS_INTERVAL_MS = 500L
        private const val ERROR_HOLD_MS = 1_500L
        private const val PERSIST_EVERY_TICKS = 120 // ~60 c — дисциплина SSD/памяти (v0.8)
        private const val LIMIT_POLL_MS = 60_000L // проверка сброса лимита раз в минуту

        private const val CHANNEL_ID = "tunnel"
        private const val NOTIF_ID = 1
        private const val NET_RETRY_COOLDOWN_MS = 3_000L

        // смена протокола: ретраи/паузы/cooldown — защита от rate-limit циклов
        private const val SWITCH_RETRIES = 3
        private const val SWITCH_RETRY_PAUSE_MS = 5_000L
        private const val SWITCH_COOLDOWN_MS = 60_000L
        @Volatile private var nextSwitchAllowedAt = 0L

        @Volatile var lastStatus: String = ""

        /** Журнал статусов/ошибок (новые сверху) с цветовой ролью строки. */
        private val logLines = ArrayDeque<LogLine>()

        fun snapshotLogs(): List<LogLine> = synchronized(logLines) { logLines.toList() }

        fun pushLog(line: String, kind: LogKind = LogKind.INFO) {
            synchronized(logLines) {
                logLines.addFirst(LogLine(line, kind))
                while (logLines.size > 300) logLines.removeLast()
            }
        }

        /**
         * Логирование изменения настройки: вызывается ТОЛЬКО когда значение
         * реально изменилось (проверка на стороне MainActivity). Попадает и в
         * журнал, и в статусную строку главного экрана.
         */
        fun logSettingChange(name: String, from: String, to: String) {
            if (from == to) return // не менялось — не пишем
            val line = Msgs.LOG_SETTING_CHANGE.t(name, from, to) // companion без Context — типизированный каталог core
            pushLog(line, LogKind.WARN) // важное (тёмно-жёлтое): изменение настроек
            lastStatus = line
        }

        /** Первый не-loopback IPv4 в локальной сети (или IPv6 как фолбэк). */
        fun localIp(): String? {
            return try {
                val cand = NetworkInterface.getNetworkInterfaces().asSequence()
                    .filter { it.isUp && !it.isLoopback }
                    .flatMap { it.inetAddresses.asSequence() }
                    .toList()
                cand.firstOrNull { !it.isLoopbackAddress && it is java.net.Inet4Address }?.hostAddress
                    ?: cand.firstOrNull { !it.isLoopbackAddress }?.hostAddress
            } catch (_: Exception) {
                null
            }
        }
    }
}
