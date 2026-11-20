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
import dev.stelgen.reverseray.MainActivity.Mode
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.ConfigResult
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

internal fun MainActivity.handleMainButtonPress() {
    val now = android.os.SystemClock.elapsedRealtime()
    val mode = lastButtonMode
    if (!bigButtonIsStart || mode == Mode.CONNECTING || mode == Mode.TIMEOUT) {
        // стоп/отмена: защита от дребезга 400 мс (двойное событие одного тапа)
        if (now - lastStopPressMs < 400) return
        lastStopPressMs = now
        if (mode == Mode.CONNECTING || mode == Mode.TIMEOUT) {
            TunnelService.pushLog(getString(R.string.log_connect_cancelled), LogKind.WARN)
        }
        stopTunnel()
        return
    }
    if (now - lastStartPressMs < 700) return
    lastStartPressMs = now
    if (now - lastStopPressMs < START_COOLDOWN_MS) {
        // раздрай: краткий неактив только для СТАРТА — визуальный намёк
        bigButton.animate().cancel()
        bigButton.animate().alpha(0.55f).setDuration(120).withEndAction {
            bigButton.animate().alpha(1f).setDuration(280).start()
        }.start()
        return
    }
    startTunnel()
}

internal fun MainActivity.startTunnel() {
    // v1.8.4: единый резолв конфига (активный PRIMARY-профиль → зеркало
    // KEY_CONFIG) через ConfigSource — ранее только зеркало, и на чистой
    // установке/после добавления сервера кнопка говорила «Некорректный
    // конфиг», хотя ссылка была валидна и лежала в профиле сессии.
    when (val res = resolvedConfig()) {
        is ConfigResult.Invalid -> {
            Toast.makeText(this, getString(R.string.invalid_config, res.reason), Toast.LENGTH_LONG).show()
            return
        }
        ConfigResult.Empty -> {
            Toast.makeText(this, R.string.status_no_config, Toast.LENGTH_LONG).show()
            return
        }
        is ConfigResult.Valid -> {
            // канон в зеркало + PRIMARY-профиль (self-heal рассинхрона)
            prefs().edit().putString(TunnelService.KEY_CONFIG, res.canonical).apply()
            syncPrimaryProfileUri(res.canonical)
            updateLinkValueView(res.canonical)
        }
    }
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
    setUiState(TunnelService.STATE_CONNECTING)
}

internal fun MainActivity.stopTunnel() {
    startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_STOP))
    setUiState(TunnelService.STATE_STOPPED)
}

/**
 * v0.9.2 (R3): состояния кнопки как первоклассная машина состояний:
 * disconnected (зелёный Старт) / connecting (янтарный, вращение кольца)
 * / connected (красный Стоп + пульс) / error (тёмно-красный, ожидание).
 * Переходы цвета — плавные (ValueAnimator.ofArgb), без кринжа и аляпистости.
 * Источник истины — TunnelService.lastState (сервис переживает recreate).
 */
internal fun MainActivity.setUiState(state: String) {
    val mode = when (state) {
        TunnelService.STATE_CONNECTED, TunnelService.STATE_PROTO -> Mode.CONNECTED
        TunnelService.STATE_CONNECTING, TunnelService.STATE_RETRY, TunnelService.STATE_PROTO_ROLLBACK -> Mode.CONNECTING
        TunnelService.STATE_ERROR, TunnelService.STATE_LIMIT_REACHED, TunnelService.STATE_PIN_MISMATCH -> Mode.ERROR
        else -> Mode.DISCONNECTED // STOPPED / INFO
    }
    applyButtonMode(mode)
    // v1.6.0: тайм-аут подключения — 3 с без результата → красный «Тайм-аут»
    // (попытки НЕ прекращаются: сервер/сеть медленные — это индикация, не сбой).
    connectTimeoutHandler.removeCallbacks(connectTimeoutRunnable)
    if (mode == Mode.CONNECTING) {
        connectTimeoutHandler.postDelayed(connectTimeoutRunnable, CONNECT_TIMEOUT_MS)
    }
}

internal fun MainActivity.applyButtonMode(mode: Mode) {
    bigButtonIsStart = mode.isStart
    // v1.7.0: статус-точка главной карточки = цвет кнопки (+пульс в активных)
    mainStatusDot?.let { dot ->
        val (color, pulse) = when (mode) {
            Mode.CONNECTED -> 0xFF39D98A.toInt() to false
            Mode.CONNECTING -> 0xFFB26B00.toInt() to true
            Mode.TIMEOUT, Mode.ERROR -> 0xFFC62828.toInt() to true
            else -> 0xFFC62828.toInt() to false
        }
        (dot.background as? android.graphics.drawable.GradientDrawable)?.setColor(color)
        if (pulse && dot.alpha == 1f) {
            android.animation.ObjectAnimator.ofFloat(dot, "alpha", 1f, 0.25f).apply {
                duration = 700
                repeatMode = android.animation.ValueAnimator.REVERSE
                repeatCount = android.animation.ValueAnimator.INFINITE
                start()
            }
        } else if (!pulse) {
            dot.animate().cancel()
            dot.alpha = 1f
        }
    }
    // v0.9.9 (канон M2 «смена состояния — fade», M3 «без jump-cut»):
    // кроссфейд подписи Старт/Подключение/Стоп, синхронный плавному цвету
    val newLabel = getString(mode.labelRes)
    if (bigButton.text.toString() != newLabel) {
        bigButton.animate().cancel()
        bigButton.animate().alpha(0f).setDuration(120)
            .setInterpolator(android.view.animation.DecelerateInterpolator())
            .withEndAction {
                bigButton.setText(mode.labelRes)
                bigButton.animate().alpha(1f).setDuration(160)
                    .setInterpolator(android.view.animation.DecelerateInterpolator())
                    .start()
            }.start()
    }
    val current = (bigButton.backgroundTintList?.defaultColor ?: mode.color)
    if (current != mode.color) {
        buttonColorAnimator?.cancel()
        buttonColorAnimator = android.animation.ValueAnimator.ofArgb(current, mode.color).apply {
            duration = 250
            addUpdateListener { a ->
                bigButton.backgroundTintList =
                    android.content.res.ColorStateList.valueOf(a.animatedValue as Int)
            }
            start()
        }
    }
    // кольца состояния (v0.9.3 PulseRingView): connected — двойное
    // «дыхание» (спокойная индикация живого туннеля), connecting —
    // современный indeterminate-дугу, иначе — скрыто. Смена цвета колец
    // следует режиму (connecting — янтарь, connected — зелень), трек — тема.
    val ringState: Mode? = if (mode == Mode.CONNECTED || mode == Mode.CONNECTING || mode == Mode.TIMEOUT) mode else null
    if (ringState != ringMode) {
        ringMode = ringState
        if (ringState == null) {
            pulseRing.stop()
            pulseRing.visibility = View.GONE
        } else {
            pulseRing.visibility = View.VISIBLE
            pulseRing.setColors(
                when (ringState) {
                    Mode.CONNECTING -> 0xFFB26B00.toInt()
                    Mode.TIMEOUT -> 0xFFC62828.toInt()
                    else -> 0xFF39D98A.toInt()
                },
                0x26888888,
            )
            pulseRing.start(
                if (ringState == Mode.CONNECTED) PulseRingView.Kind.CONNECTED else PulseRingView.Kind.CONNECTING,
            )
        }
    }
    // v0.9.3 (канон 2026): смена состояния — мягкий «поп» 3.5% и упругий
    // возврат (140+220мс). Только при РЕАЛЬНОЙ смене режима — без дёрганья
    // при повторных синхронизациях UI из сервиса.
    // v1.0.1 (канон владельца): ДЫХАНИЕ — запускается ОДИН раз при входе
    // в активное состояние и живёт бесконечно (REVERSE-цикл 1100 мс,
    // AccelerateDecelerate); повторные синхронизации его НЕ трогают —
    // цикл непрерывен от начала до конца; выход только при смене режима —
    // плавное затухание в 1.0 (300 мс). Нажатие сжимает сборку (buttonBox),
    // не разрывая дыхание.
    if (mode != lastButtonMode) {
        lastButtonMode = mode
        if (mode == Mode.CONNECTED || mode == Mode.CONNECTING || mode == Mode.TIMEOUT) {
            if (breathMode != mode) {
                breathMode = mode
                breathing?.cancel()
                val (lo, hi) = if (mode == Mode.CONNECTED) 1.0f to 1.03f else 0.985f to 1.02f
                breathing = android.animation.ValueAnimator.ofFloat(lo, hi).apply {
                    duration = 1100
                    repeatMode = android.animation.ValueAnimator.REVERSE
                    repeatCount = android.animation.ValueAnimator.INFINITE
                    interpolator = android.view.animation.AccelerateDecelerateInterpolator()
                    addUpdateListener { a ->
                        val s = a.animatedValue as Float
                        bigButton.scaleX = s
                        bigButton.scaleY = s
                    }
                    start()
                }
            }
        } else if (breathMode != null) {
            breathMode = null
            val b = breathing
            breathing = null
            b?.cancel()
            bigButton.animate().cancel()
            bigButton.animate().scaleX(1f).scaleY(1f).setDuration(300)
                .setInterpolator(android.view.animation.DecelerateInterpolator()).start()
        }
    }
}

/** v0.9.7 (GUI-финал): пустой график не занимает место — GONE до первых данных. */
internal fun MainActivity.syncGraphVisibility() {
    trafficGraph.visibility = if (trafficGraph.hasData()) View.VISIBLE else View.GONE
}

/** Мгновенная синхронизация UI из сервиса (v0.9.2 R3/R4) — после recreate. */
internal fun MainActivity.syncUiFromService() {
    setUiState(TunnelService.lastState)
    // протокол и его известность — из ссылки + реестра сервера
    refreshConnLine()
    // v1.5.1: история графика живёт в GraphHistory (пишется ВСЕГДА:
    // и туннелем, и общесистемным сэмплером) — восстанавливаем из неё
    val (rxBuf, txBuf, head, valid) = GraphHistory.snapshot()
    val inter = FloatArray(GraphHistory.CAPACITY * 2)
    for (i in 0 until GraphHistory.CAPACITY) {
        inter[i * 2] = rxBuf[i]
        inter[i * 2 + 1] = txBuf[i]
    }
    trafficGraph.setHistory(inter, head, valid)
    syncGraphVisibility()
    renderServiceLogs()
}
