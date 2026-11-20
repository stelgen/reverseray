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

internal fun MainActivity.buildUpdatePage(): View {
    val p = page()
    versionView = TextView(this).apply {
        textSize = 14f
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(4), 0, dp(4))
    }
    p.addView(versionView)

    // Модули: обновляются без переустановки APK (как POS-машины)
    val modulesCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    modulesCard.addView(sectionTitle(R.string.modules_section, null))
    modulesInfoView = TextView(this).apply {
        textSize = 12f
        setPadding(0, dp(4), 0, dp(4))
    }
    modulesCard.addView(modulesInfoView)
    // v1.8.8: кнопка «Обновить модули» упразднена — их обновляет ЕДИНАЯ
    // кнопка «Проверить обновления» ниже (приложение → модули, с логом).
    p.addView(card(modulesCard))

    // Авто-проверка — в карточке (UX-канон: единый вид всех переключателей)
    p.addView(card(LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(SwitchMaterial(this@buildUpdatePage).apply {
            setText(R.string.update_auto)
            isChecked = prefs().getBoolean(TunnelService.KEY_AUTO_UPDATE, true)
            setOnCheckedChangeListener { _, checked ->
                val old = prefs().getBoolean(TunnelService.KEY_AUTO_UPDATE, true)
                if (old != checked) {
                    prefs().edit().putBoolean(TunnelService.KEY_AUTO_UPDATE, checked).apply()
                    TunnelService.logSettingChange(getString(R.string.set_auto_update), old.toString(), checked.toString())
                    renderServiceLogs()
                }
            }
        })
    }))

    p.addView(
        row(
            filled(R.string.update_check).apply {
                setOnClickListener { checkAllUpdatesAsync() }
            },
        )
    )

    // Журнал обновления/модулей — ТО ЖЕ консольное окно и формат, что на главной
    updateConsole = StatusConsole(this).apply {
        setTitle(getString(R.string.console_title_update))
        setBodyHeight(240)
    }
    p.addView(updateConsole)
    return scrollWrap(p)
}

internal fun MainActivity.buildLogPage(): View {
    val p = page()
    p.addView(TextView(this).apply {
        setText(R.string.logs_title)
        textSize = 14f
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(4), 0, dp(4))
    })
    // v1.5.0: фильтр «по сессии» — чипы (Все / имена сессий из кольца)
    logFilterRow = HorizontalScrollView(this).apply {
        isHorizontalScrollBarEnabled = false
        addView(
            LinearLayout(this@buildLogPage).apply {
                orientation = LinearLayout.HORIZONTAL
            },
        )
    }
    p.addView(logFilterRow)
    logConsole = StatusConsole(this).apply {
        setTitle(getString(R.string.console_title_service))
        setBodyHeight(280)
    }
    p.addView(logConsole)
    p.addView(
        row(
            outlined(R.string.log_copy_all).apply { setOnClickListener { copyServiceLog() } },
            outlined(R.string.log_share).apply { setOnClickListener { shareServiceLog() } },
        )
    )
    return scrollWrap(p)
}
