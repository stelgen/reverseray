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
import dev.stelgen.reverseray.core.ProtocolState
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

internal fun MainActivity.toConsoleLines(entries: List<LogStore.Entry>): List<StatusConsole.Line> =
    entries.map { l -> StatusConsole.Line(l.text, StatusConsole.roleOf(l.kind)) }


/**
 * v0.9.7 (фильтрация по экранам LogStore.Screen): каждое окно берёт из LogStore сообщения
 * СВОЕГО типа — главная: статусы подключения (цвета: подключено —
 * зелёный, ошибка/отключено — красный, реконнект — тёмно-жёлтый),
 * обновление: канал UPDATE, полный лог: всё без исключений.
 */
internal fun MainActivity.renderServiceLogs() {
    homeConsole.render(toConsoleLines(LogStore.snapshotFor(LogStore.Screen.HOME)))
    updateConsole.render(toConsoleLines(LogStore.snapshotFor(LogStore.Screen.UPDATE)))
    logConsole.render(toConsoleLines(LogStore.snapshotFor(LogStore.Screen.LOG, logSessionFilter)))
}


/**
 * v1.5.0: чипы фильтра лога «по сессии» — «Все» + имена сессий из кольца.
 * Пересобирается при открытии вкладки LOG (сессии появляются/уходят).
 */
internal fun MainActivity.refreshLogFilterChips() {
    if (!logFilterInitialized()) return
    val box = logFilterRow.getChildAt(0) as LinearLayout
    box.removeAllViews()
    val all = logChip(getString(R.string.log_filter_all), logSessionFilter == null)
    all.setOnClickListener {
        logSessionFilter = null
        refreshLogFilterChips()
        renderServiceLogs()
    }
    box.addView(all)
    for (name in LogStore.knownSessions()) {
        val c = logChip(name, logSessionFilter == name)
        c.setOnClickListener {
            logSessionFilter = name
            refreshLogFilterChips()
            renderServiceLogs()
        }
        box.addView(c)
    }
}


internal fun MainActivity.logChip(text: String, selected: Boolean): TextView = TextView(this).apply {
    this.text = text
    textSize = 12f
    setPadding(dp(10), dp(4), dp(10), dp(4))
    setTextColor(if (selected) 0xFF39D98A.toInt() else 0xFF8FA3D9.toInt())
    if (selected) setTypeface(typeface, Typeface.BOLD)
    setBackgroundResource(android.R.drawable.list_selector_background)
    layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
    ).apply { setMargins(0, 0, dp(6), 0) }
}


/** Открыта ли сейчас вкладка полного лога (для реалтайм-дорисовки). */
internal fun MainActivity.isLogTabOpen(): Boolean =
    pageInitialized() && pageLog.visibility == View.VISIBLE


internal fun MainActivity.usageSummaryText(used: Long, limit: Long): String {
    val usedStr = fmtBytes(used)
    return if (limit > 0) {
        val pct = (used * 100 / limit).coerceAtMost(999)
        getString(R.string.usage_with_limit, usedStr, fmtBytes(limit), pct)
    } else {
        getString(R.string.usage_no_limit, usedStr)
    }
}


internal fun MainActivity.refreshUsageSummary() {
    val p = prefs()
    val used = p.getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
    val limit = p.getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
    setUsageText(usageSummaryText(used, limit))
}


internal fun MainActivity.setUsageText(text: String) {
    usageViews.forEach { it.text = text }
}


/**
 * v0.9.9 (UX): ОДНА строка «Соединение: <протокол> · <транспорт>».
 * Протокол — АКТУАЛЬНЫЙ согласованный (TunnelService.lastNegotiatedProto),
 * пока сессии нет — из ссылки. Список «сервер поддерживает» убран (шум).
 */
internal fun MainActivity.setConnText(text: String) {
    connLineViews.forEach { it.text = text }
}


internal fun MainActivity.refreshConnLine() {
    // v1.8.6: протокол читается ТОЛЬКО из ProtocolState (единый источник:
    // согласованный сессией > заявленный из ссылки > AUTO/ROTATE) и показывается
    // без пояснений — канон «как WS».
    val t = currentTransport()
    val transportShort = if (t == RrpUri.TRANSPORT_WS) "WS" else "TCP"
    connLineViews.forEach { it.text = getString(R.string.conn_line, ProtocolState.display(), transportShort) }
}


/** Внешний IP/страна/оператор + локальный IP + DNS-факты (честно). */
internal fun MainActivity.refreshNetInfoAsync() {
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

