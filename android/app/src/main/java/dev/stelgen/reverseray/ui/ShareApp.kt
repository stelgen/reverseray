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

internal fun MainActivity.shareAppLink() {
    val url = "https://github.com/stelgen/reverseray"
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, url)
    }
    startActivity(Intent.createChooser(send, getString(R.string.btn_share_app)))
}


/**
 * Поделиться APK «в сборе»: текущий APK приложения + вшитые модули
 * (реестр протоколов в коде). НЕ передаются: настройки, ссылка/токен,
 * логи, счётчики и любая приватная информация — у нового пользователя
 * всё будет в дефолтах.
 */
internal fun MainActivity.shareAppApk() {
    if (Build.VERSION.SDK_INT >= 19 && fileIoSupported) {
        try {
            shareApkLauncher.launch("reverseray-${currentVersion()}.apk")
            return
        } catch (_: ActivityNotFoundException) {
            // нет SAF-пикера — фоллбек на прямую шару ниже
        }
    }
    try {
        val apk = File(applicationInfo.sourceDir)
        val copy = File(cacheDir, "reverseray-${currentVersion()}.apk")
        apk.copyTo(copy, overwrite = true)
        val uri = FileProvider.getUriForFile(this, "$packageName.files", copy)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/vnd.android.package-archive"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(send, getString(R.string.btn_share_app)))
    } catch (e: Exception) {
        Toast.makeText(this, getString(R.string.share_apk_error), Toast.LENGTH_SHORT).show()
    }
}


internal fun MainActivity.copyApkTo(uri: Uri) {
    try {
        contentResolver.openOutputStream(uri)?.use { out ->
            File(applicationInfo.sourceDir).inputStream().use { it.copyTo(out, 64 * 1024) }
            out.flush()
        }
        Toast.makeText(this, R.string.config_saved, Toast.LENGTH_SHORT).show()
    } catch (e: Exception) {
        Toast.makeText(this, getString(R.string.share_apk_error), Toast.LENGTH_SHORT).show()
    }
}

