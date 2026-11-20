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
import android.view.View
import android.view.ViewGroup
import android.widget.Button
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
    // v1.8.8: «Модули» переехали к Tunnel protocol — одно мульти-окно
    // (несколько модулей сразу), по аналогии с «Switch protocol».
    protoCard.addView(outlined(R.string.modules_section_modules).apply {
        setOnClickListener { showModulesPicker() }
    })
    protoCard.addView(outlined(R.string.transport_switch).apply {
        setOnClickListener { showTransportPicker() }
    })
    p.addView(card(protoCard))
    return scrollWrap(p)
}
