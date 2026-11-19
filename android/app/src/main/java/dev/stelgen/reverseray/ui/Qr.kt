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

internal fun MainActivity.launchScan() {
    if (!qrSupported) return
    val opts = ScanOptions().apply {
        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
        setPrompt(getString(R.string.qr_prompt))
        setBeepEnabled(false)
        setOrientationLocked(true)
    }
    try {
        scanLauncher.launch(opts)
    } catch (e: ActivityNotFoundException) {
        Toast.makeText(this, R.string.qr_error, Toast.LENGTH_SHORT).show()
    }
}


internal fun MainActivity.showQr() {
    val raw = try {
        RrpUri.parse(prefs().getString(TunnelService.KEY_CONFIG, "") ?: "").serialize() // QR всегда канонический
    } catch (e: Exception) {
        Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show()
        return
    }
    val bitmap: android.graphics.Bitmap = try {
        BarcodeEncoder().encodeBitmap(raw, com.google.zxing.BarcodeFormat.QR_CODE, 640, 640)
    } catch (e: Exception) {
        Toast.makeText(this, R.string.qr_error, Toast.LENGTH_SHORT).show()
        return
    }
    val iv = android.widget.ImageView(this).apply {
        setImageBitmap(bitmap)
        setPadding(24, 24, 24, 24)
    }
    val dialog = MaterialAlertDialogBuilder(this)
        .setTitle(R.string.qr_show)
        .setView(iv)
        .setPositiveButton(android.R.string.ok, null)
        .create()
    dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
    dialog.show()
}

