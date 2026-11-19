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
import dev.stelgen.reverseray.LimitReset
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

/** Окно «траффик закончился» — на Старт/Реконнект и при падении туннеля. */
internal fun MainActivity.showLimitDialog(statusText: String?) {
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


/** v0.9.0: ротация CA — ЯВНОЕ подтверждение владельца (анти-MITM канон:
 *  молча не доверяем никогда; отказ = туннель продолжает ретраить с отказом). */
internal fun MainActivity.showPinMismatchDialog(realPin: String) {
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
internal fun MainActivity.refreshLimitNext() {
    val used = prefs().getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
    val limit = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
    limitNextView.text = if (limit > 0) {
        getString(R.string.set_limit_next, nextResetDateString())
    } else {
        ""
    }
    setUsageText(usageSummaryText(used, limit))
}


internal fun MainActivity.nextResetDateString(): String {
    val period = prefs().getString(TunnelService.KEY_LIMIT_PERIOD, TunnelService.PERIOD_DAY)
        ?: TunnelService.PERIOD_DAY
    val day = prefs().getInt(TunnelService.KEY_LIMIT_RESET_DAY, 1)
    val at = LimitReset.nextResetAtMs(period, day)
    return SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(at))
}


internal fun MainActivity.describeLimit(bytes: Long, period: String, day: Int): String {
    if (bytes <= 0) return getString(R.string.limit_none)
    val pr = if (period == TunnelService.PERIOD_MONTH) getString(R.string.limit_period_month, day) else getString(R.string.limit_period_day)
    return "${fmtBytes(bytes)}/$pr"
}


internal fun MainActivity.limitGb(): String {
    val l = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
    return if (l <= 0) "10" else String.format(Locale.US, "%.0f", l / 1024.0 / 1024.0 / 1024.0)
}

