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

internal fun MainActivity.buildLinkPage(): View {
    val p = page()

    // ── 1. ДОБАВИТЬ СЕРВЕР — первой кнопкой вкладки (канон v1.7.0) ──
    p.addView(row(filled(R.string.sess_add).apply { setOnClickListener { showAddSessionDialog() } }))

    // ── 2. СЕРВЕРЫ: статус-точка (пульс) + имя + хост + действия ──
    // v1.7.0 FIX наложений: содержимое добавляется В inner-LinearLayout
    // карточки, а не в MaterialCardView (FrameLayout — дети СКЛАДЫВАЛИСЬ
    // друг на друга — тот самый «мусор» вверху вкладки).
    val sessionsInner = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    p.addView(card(sessionsInner))
    sessionsBox = sessionsInner
    refreshSessionsCard()

    // ── 3. ИМПОРТ ПАЧКОЙ (по одной rrp://-ссылке на строку) ──
    val bulkInner = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    bulkInner.addView(sectionTitle(R.string.sess_bulk_title, null))
    val bulkInput = TextInputEditText(this).apply {
        hint = getString(R.string.sess_bulk_hint)
        minLines = 2
        gravity = Gravity.TOP
        setTextSize(12f)
        setTypeface(Typeface.MONOSPACE)
    }
    bulkInner.addView(bulkInput)
    bulkInner.addView(
        row(
            outlined(R.string.sess_bulk_add).apply {
                setOnClickListener {
                    val text = bulkInput.text?.toString().orEmpty()
                    val (okN, badN) = addBulkSessions(text)
                    bulkInput.setText("")
                    Toast.makeText(
                        this@buildLinkPage,
                        getString(R.string.sess_bulk_result, okN, badN),
                        Toast.LENGTH_LONG,
                    ).show()
                    refreshSessionsCard()
                }
            },
        ),
    )
    p.addView(card(bulkInner))

    // ── Модули (v0.9.5): чекбокс-каркас для вкл/выкл модулей ──
    // Правила UX: один чекбокс = один модуль, мгновенный отклик,
    // уведомление + честный лог; выбор персистентен (переживает офлайн).
    val modsCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    modsCard.addView(sectionTitle(R.string.modules_section_modules, null))
    modsCard.addView(TextView(this).apply {
        setText(R.string.modules_hint)
        textSize = 12f
        setTextColor(0xFF6B7280.toInt())
        setPadding(0, dp(2), 0, dp(6))
    })
    // v1.0.0: модуль UDP-релей — галочка рядом с API Mask; гейт на клиенте
    // (телефон — точка egress UDP): выкл → UDP_ASSOC отклоняется, ноль дейтаграмм
    val udpCfg = Modules.lastUdp
    if (udpCfg != null) {
        val udpRow = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        udpRow.addView(CheckBox(this).apply {
            text = getString(R.string.udp_toggle)
            isChecked = prefs().getBoolean(TunnelService.KEY_UDP_ENABLED, true)
            textSize = 13f
            setOnCheckedChangeListener { _, checked ->
                val i = Intent(this@buildLinkPage, TunnelService::class.java)
                    .setAction(TunnelService.ACTION_UDP)
                    .putExtra(TunnelService.EXTRA_ENABLED, checked)
                if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
            }
        })
        modsCard.addView(udpRow)
    }
    p.addView(card(modsCard))

    // Протоколы
    val protoCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    // v0.9.7 (GUI-этап 2): единый заголовок карточки — как у всех остальных
    protoCard.addView(sectionTitle(R.string.proto_section, null))
    connLineViews.add(TextView(this).apply {
        textSize = 13f
        setPadding(0, dp(4), 0, dp(4))
        setText(R.string.proto_unknown)
    })
    protoCard.addView(connLineViews.last())
    protoCard.addView(outlined(R.string.proto_switch).apply {
        setOnClickListener { showProtocolPicker() }
    })
    protoCard.addView(outlined(R.string.transport_switch).apply {
        setOnClickListener { showTransportPicker() }
    })
    p.addView(card(protoCard))
    return scrollWrap(p)
}
