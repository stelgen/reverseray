package dev.stelgen.reverseray.ui

// v1.8.2: зона вынесена из MainActivity.kt (дробление по зонам
// ответственности). Pure refactor: private → internal у задетых членов,
// поведение не меняется.

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
import android.widget.CheckBox
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
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
import dev.stelgen.reverseray.MainActivity
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.LogStore
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
import dev.stelgen.reverseray.core.ThemeMode
import dev.stelgen.reverseray.net.DnsProbe
import dev.stelgen.reverseray.net.NetInfo
import dev.stelgen.reverseray.net.NetInfoFetcher
import dev.stelgen.reverseray.service.LogKind
import dev.stelgen.reverseray.service.PrefsBackend
import dev.stelgen.reverseray.service.TunnelService
import dev.stelgen.reverseray.update.UpdateChecker
import dev.stelgen.reverseray.update.UpdateInfo
import dev.stelgen.reverseray.update.UpdateLogger
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/**
 * v1.5.0: страница «Серверы» — дашборд сессий. Действия по карточкам
 * уходят в сервис командой ACTION_SESSION (connect/disconnect/reconnect/
 * probe/primary) — изолированно, без рестарта других сессий.
 */
// v1.6.0: дашборд сессий встроен в Home (вкладка «Серверы» удалена):
// общий график с полной сетевой инфой сверху, ниже — карточки по серверам
// с идентичными графиками. Действия — командами ACTION_SESSION.
internal fun MainActivity.attachDashboardTo(parent: LinearLayout) {
    dashboard = DashboardView(this)
    dashboard.onAction = { id, cmd ->
        val i = Intent(this, TunnelService::class.java)
            .setAction(TunnelService.ACTION_SESSION)
            .putExtra(TunnelService.EXTRA_SESSION_ID, id)
            .putExtra(TunnelService.EXTRA_SESSION_CMD, cmd)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
    }
    parent.addView(sectionTitle(R.string.sess_section_title, null))
    // v1.7.0: кнопка добавления переехала в начало «Подключения»
    parent.addView(dashboard)
    if (lastSessionsJson.isBlank()) preserveScroll { dashboard.update(offlineStats()) }
}

/**
 * v1.6.2: пересборка списков НЕ должна двигать экран: фиксируем scrollY
 * активной вкладки, выполняем пересборку, возвращаем позицию (post —
 * после перелайаута; страховочный пост через 64 мс).
 */
internal fun MainActivity.preserveScroll(block: () -> Unit) {
    // во время buildUi страницы ещё не собраны — просто выполняем блок
    if (!pageInitialized()) {
        block()
        return
    }
    val sv = when (currentTab) {
        0 -> pageHome; 1 -> pageLink; 2 -> pageUpdate; 3 -> pageLog; 4 -> pageSettings; else -> null
    } as? android.widget.ScrollView
    val y = sv?.scrollY ?: 0
    block()
    if (sv != null) {
        sv.post { sv.scrollTo(0, y) }
        sv.postDelayed({ sv.scrollTo(0, y) }, 64)
    }
}

/** Оффлайн-снапшот из профилей (сервис не шлёт статсы: stopped/disabled). */
internal fun MainActivity.offlineStats(): List<DashboardView.Stat> {
    return try {
        val store = SessionStore(PrefsBackend(prefs()))
        store.migrateLegacy(prefs().getString(TunnelService.KEY_CONFIG, null))
        val active = store.activeId()
        store.profiles().map { pr ->
            DashboardView.Stat(
                id = pr.id, name = pr.name,
                state = if (pr.enabled) TunnelService.STATE_STOPPED else "disabled",
                rxRate = 0, txRate = 0, rxTotal = 0, txTotal = 0,
                proto = "", rttMs = 0, reconnects = 0, errors = 0, switches = 0,
                uptimeMs = 0, primary = pr.id == active,
            )
        }
    } catch (_: Exception) {
        emptyList()
    }
}

/** Рендер дашборда по JSON из сервиса (ACTION_STATS). */
internal fun MainActivity.renderDashboard(json: String) {
    val list = ArrayList<DashboardView.Stat>()
    try {
        val arr = org.json.JSONArray(json)
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            list.add(
                DashboardView.Stat(
                    id = o.optString("id"),
                    name = o.optString("name"),
                    state = o.optString("state"),
                    rxRate = o.optLong("rx_rate"),
                    txRate = o.optLong("tx_rate"),
                    rxTotal = o.optLong("rx_total"),
                    txTotal = o.optLong("tx_total"),
                    proto = o.optString("proto"),
                    rttMs = o.optLong("rtt_ms"),
                    reconnects = o.optLong("reconnects"),
                    errors = o.optLong("errors"),
                    switches = o.optLong("switches"),
                    uptimeMs = o.optLong("uptime_ms"),
                    primary = o.optBoolean("primary"),
                ),
            )
        }
    } catch (_: Exception) {
    }
    // v1.6.2: дашборд пересобирается каждые 500 мс — скролл Home не дёргается
    preserveScroll { dashboard.update(list) }
}

internal fun MainActivity.buildHomePage(): View {
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
    // Версия под именем — без строковых ресурсов (техническая метка).
    p.addView(TextView(this).apply {
        text = "v" + (try {
            packageManager.getPackageInfo(packageName, 0).versionName
        } catch (_: Exception) {
            ""
        })
        textSize = 12f
        gravity = Gravity.CENTER_HORIZONTAL
        setTextColor(0xFF6B7280.toInt())
        setPadding(0, dp(0), 0, dp(2))
    })

    // ОДНА круглая кнопка Старт/Стоп (дубликат снизу убран — v0.8) с
    // кольцами состояния (v0.9.3: PulseRingView — канон 2026, без дёрганья)
    val buttonBox = android.widget.FrameLayout(this).apply {
        layoutParams = LinearLayout.LayoutParams(dp(216), dp(216)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            setMargins(0, dp(12), 0, dp(8))
        }
    }
    pulseRing = PulseRingView(this).apply {
        layoutParams = android.widget.FrameLayout.LayoutParams(dp(216), dp(216)).apply {
            gravity = Gravity.CENTER
        }
        setStrokeWidthPx(dp(2).toFloat())
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
            // v1.6.1: анти-спам машина (психованные мульти-нажатия):
            // стоп/отмена коннекта проходят ВСЕГДА, старт — с дебаунсом
            // и кулдауном после стопа; статус всегда синхронен сервису.
            handleMainButtonPress()
        }
        // v0.9.3 (канон анимаций 2026): тактильный отклик нажатия —
        // лёгкое сжатие 3% (120мс, Decelerate) и упругий возврат
        // (200мс, Overshoot 0.8) — плавно, без дёрганья. Событие
        // потребляем (return true), клик выполняем сами на UP —
        // ровно один клик (performClick — паттерн a11y, как в StatusConsole).
        setOnTouchListener { v, ev ->
            val springBack = {
                // v1.0.1: нажатие сжимает СБОРКУ (кольцо+кнопка), дыхание
                // кнопки живёт непрерывно — цикл не разрывается
                buttonBox.animate().cancel()
                buttonBox.animate().scaleX(1f).scaleY(1f).setDuration(200)
                    .setInterpolator(android.view.animation.OvershootInterpolator(0.8f)).start()
            }
            when (ev.actionMasked) {
                android.view.MotionEvent.ACTION_DOWN -> {
                    buttonBox.animate().cancel()
                    buttonBox.animate().scaleX(0.97f).scaleY(0.97f).setDuration(120)
                        .setInterpolator(android.view.animation.DecelerateInterpolator()).start()
                }
                android.view.MotionEvent.ACTION_UP -> {
                    springBack()
                    v.performClick()
                }
                android.view.MotionEvent.ACTION_CANCEL -> springBack()
            }
            true
        }
    }
    buttonBox.addView(bigButton)
    p.addView(buttonBox)

    // Карточка трафика (v1.7.0): шапка как у серверных карточек —
    // статус-точка (цвет кнопки), заголовок, флаг страны; цифры —
    // каждая с новой строки (детерминированная высота).
    val inner = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    val mainHead = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
    mainStatusDot = statusDot(0xFF8FA3D9.toInt(), false)
    mainHead.addView(mainStatusDot)
    mainHead.addView(TextView(this).apply {
        setText(R.string.home_device_title)
        textSize = 14f
        setTypeface(typeface, Typeface.BOLD)
        setTextColor(0xFFFFFFFF.toInt())
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
    })
    netFlag = ImageView(this).apply {
        layoutParams = LinearLayout.LayoutParams(dp(22), dp(15))
        scaleType = ImageView.ScaleType.FIT_CENTER
        visibility = View.GONE
    }
    mainHead.addView(netFlag)
    inner.addView(mainHead)
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
        maxLines = 3
    }
    inner.addView(trafficLabel)
    packetsLabel = TextView(this).apply {
        textSize = 12f
        setPadding(0, dp(2), 0, 0)
        setTextColor(0xFF6B7280.toInt())
    }
    inner.addView(packetsLabel)

    netInfoView = TextView(this).apply {
        setText(R.string.netinfo_loading)
        textSize = 12f
    }
    inner.addView(netInfoView)
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
    // v0.9.9 (UX): ОДНА строка — актуальный протокол + транспорт
    connLineViews.add(TextView(this).apply {
        textSize = 12f
        setPadding(0, dp(2), 0, 0)
    })
    inner.addView(connLineViews.last())
    p.addView(card(inner))

    // v1.6.0: дашборд серверов на Home — общий график сверху (с полной
    // сетевой инфой), ниже — карточка на каждый сервер с тем же графиком.
    attachDashboardTo(p)

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
