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
import dev.stelgen.reverseray.L10nUi
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

internal fun MainActivity.buildSettingsPage(): View {
    val p = page()

    // v1.6.0: карточка сессий перенесена на «Подключение» (дубль убран);
    // здесь остаются тема/модули/лимиты/приложение.

    // Тема (v0.8.1): авто (настройка телефона; на старых Android — чёрная) / тёмная / светлая
    p.addView(buildThemeCard())

    // Язык (v0.8.3): system / русский / english — динамически, всё приложение и логи
    p.addView(buildLangCard())

    // Уровень журнала (v1.8.4): порог trace..panic — что вообще пишем в лог
    p.addView(buildLogLevelCard())

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
        addView(SwitchMaterial(this@buildSettingsPage).apply {
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
        addView(SwitchMaterial(this@buildSettingsPage).apply {
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
        addView(SwitchMaterial(this@buildSettingsPage).apply {
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
                        Toast.makeText(this@buildSettingsPage, R.string.set_limit_bad_value, Toast.LENGTH_SHORT).show()
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
                    Toast.makeText(this@buildSettingsPage, R.string.set_limit_applied, Toast.LENGTH_SHORT).show()
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
                    Toast.makeText(this@buildSettingsPage, R.string.set_limit_reset_done, Toast.LENGTH_SHORT).show()
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
                Toast.makeText(this@buildSettingsPage, R.string.set_probe_bad, Toast.LENGTH_SHORT).show()
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

    // v1.6.2: «Поделиться приложением» переехал со вкладки «Подключение»
    // в «Настройки» (канон: распространение — настройка, не подключение).
    val shareCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    shareCard.addView(sectionTitle(R.string.btn_share_app, null))
    shareCard.addView(
        row(
            filled(R.string.share_link).apply { setOnClickListener { shareAppLink() } },
            outlined(R.string.share_apk).apply { setOnClickListener { shareAppApk() } },
        )
    )
    p.addView(card(shareCard))

    // v1.7.0: инструменты конфига — сюда же переехали импорт/экспорт
    // и QR (канон: ввод/обмен конфигом — настройки, не подключение).
    val toolsCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    toolsCard.addView(sectionTitle(R.string.config_tools_title, null))
    // legacy-представление ссылки (статус/значение): создаётся скрытым —
    // импортеры/сканер/транспорт пишут в него, видимость не нужна
    // (канон ссылки показывает список серверов на «Подключении»).
    val legacyBox = LinearLayout(this).apply { visibility = View.GONE }
    linkStatusView = TextView(this).apply { visibility = View.GONE }
    linkValueView = TextView(this).apply { visibility = View.GONE }
    legacyBox.addView(linkStatusView)
    legacyBox.addView(linkValueView)
    toolsCard.addView(legacyBox)
    toolsCard.addView(
        row(
            outlined(R.string.import_config).also {
                it.setOnClickListener {
                    try {
                        importFileLauncher.launch(arrayOf("text/*", "application/octet-stream"))
                    } catch (e: ActivityNotFoundException) {
                        Toast.makeText(this, R.string.file_error_no_picker, Toast.LENGTH_SHORT).show()
                    }
                }
            },
            outlined(R.string.export_config).also {
                it.setOnClickListener { exportFileLauncher.launch("reverseray-config.txt") }
            },
        ),
    )
    if (qrSupported) {
        toolsCard.addView(
            row(
                outlined(R.string.qr_scan).apply { setOnClickListener { launchScan() } },
                outlined(R.string.qr_show).apply { setOnClickListener { showQr() } },
            ),
        )
    }
    p.addView(card(toolsCard))
    return scrollWrap(p)
}

/**
 * v0.8.1: карта «Тема» — авто / тёмная / светлая (применяется сразу).
 */
internal fun MainActivity.buildThemeCard(): LinearLayout {
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

/**
 * v0.8.3: карта «Язык» — Как в системе / Русский / English.
 * Применяется сразу (recreate): ресурсы — через attachBaseContext,
 * логи ядра — через L10n.lang (без перезапуска процесса).
 */
internal fun MainActivity.buildLangCard(): LinearLayout {
    val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    box.addView(TextView(this).apply {
        setText(R.string.settings_language)
        textSize = 14f
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(12), 0, dp(4))
    })
    val rowBox = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
    val bSystem = outlined(R.string.lang_system)
    val bRu = outlined(R.string.lang_ru)
    val bEn = outlined(R.string.lang_en)
    bSystem.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
    bRu.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        .apply { setMargins(dp(6), 0, 0, 0) }
    bEn.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        .apply { setMargins(dp(6), 0, 0, 0) }
    rowBox.addView(bSystem); rowBox.addView(bRu); rowBox.addView(bEn)
    box.addView(rowBox)
    fun paint() {
        val sel = L10nUi.saved(this@buildLangCard)
        val on = 0xFF2E7D32.toInt()
        val off = 0x00FFFFFF
        bSystem.backgroundTintList = android.content.res.ColorStateList.valueOf(if (sel == L10nUi.LANG_SYSTEM) on else off)
        bRu.backgroundTintList = android.content.res.ColorStateList.valueOf(if (sel == L10nUi.LANG_RU) on else off)
        bEn.backgroundTintList = android.content.res.ColorStateList.valueOf(if (sel == L10nUi.LANG_EN) on else off)
    }
    fun pick(mode: String) {
        val old = L10nUi.saved(this@buildLangCard)
        val norm = L10nUi.save(this@buildLangCard, mode)
        if (norm == old) return
        TunnelService.logSettingChange(getString(R.string.settings_language), old, norm)
        renderServiceLogs()
        // Язык применяем перезаданием базового контекста: recreate пересоздаёт
        // Activity → attachBaseContext возьмёт новую локаль из prefs.
        recreate()
    }
    bSystem.setOnClickListener { pick(L10nUi.LANG_SYSTEM) }
    bRu.setOnClickListener { pick(L10nUi.LANG_RU) }
    bEn.setOnClickListener { pick(L10nUi.LANG_EN) }
    paint()
    return box
}


/**
 * v1.8.4: карточка «Уровень журнала» — минимальный записываемый уровень
 * (LogStore.minLevel). Всё «тише» порога в кольцо и на экраны не попадает:
 * TRACE/DEBUG включаются осознанно (диагностика протокола), по умолчанию INFO.
 */
internal fun MainActivity.buildLogLevelCard(): LinearLayout {
    val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    box.addView(TextView(this).apply {
        setText(R.string.set_log_level)
        textSize = 14f
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(12), 0, dp(4))
    })
    box.addView(TextView(this).apply {
        setText(R.string.set_log_level_hint)
        textSize = 12f
        setTextColor(0xFF8FA3D9.toInt())
        setPadding(0, 0, 0, dp(4))
    })
    val btn = outlined(R.string.set_log_level)
    fun labelOf(k: LogKind): Int = when (k) {
        LogKind.TRACE -> R.string.lvl_trace
        LogKind.DEBUG -> R.string.lvl_debug
        LogKind.INFO -> R.string.lvl_info
        LogKind.NOTICE -> R.string.lvl_notice
        LogKind.OK -> R.string.lvl_ok
        LogKind.WARN -> R.string.lvl_warn
        LogKind.ERROR -> R.string.lvl_error
        LogKind.PANIC -> R.string.lvl_panic
    }
    fun paint() {
        val cur = LogKind.from(prefs().getString(TunnelService.KEY_LOG_MIN_LEVEL, null)) ?: LogKind.INFO
        btn.text = getString(labelOf(cur))
    }
    paint()
    btn.setOnClickListener {
        val levels = LogKind.entries.toTypedArray()
        val labels = levels.map { getString(labelOf(it)) }.toTypedArray()
        val cur = LogKind.from(prefs().getString(TunnelService.KEY_LOG_MIN_LEVEL, null)) ?: LogKind.INFO
        val selected = levels.indexOf(cur)
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.set_log_level)
            .setSingleChoiceItems(labels, selected) { d, which ->
                val old = cur.name
                val next = levels[which]
                if (next != cur) {
                    prefs().edit().putString(TunnelService.KEY_LOG_MIN_LEVEL, next.name).apply()
                    LogStore.minLevel = next
                    TunnelService.logSettingChange(
                        getString(R.string.set_log_level), old, next.name,
                    )
                }
                d.dismiss()
                paint()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }
    box.addView(btn)
    return box
}
