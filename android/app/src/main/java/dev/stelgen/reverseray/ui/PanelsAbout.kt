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

internal fun MainActivity.infoRow(parent: LinearLayout, k: String, v: String) {
    val l = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(0, dp(4), 0, dp(4))
    }
    l.addView(TextView(this).apply {
        text = k
        textSize = 13f
        setTextColor(0xFF6B7280.toInt())
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.45f)
    })
    l.addView(TextView(this).apply {
        text = v
        textSize = 13f
        setTypeface(typeface, Typeface.BOLD)
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.55f)
    })
    parent.addView(l)
}


/** «О приложении»: версии, модули, RAM, диск, трафик за всё время, протокол
 *  + v0.8.1: константы/переменные защиты и честные факты (серт, источники). */
internal fun MainActivity.refreshAppPanel() {
    appInfoBox.removeAllViews()
    val code = try {
        @Suppress("DEPRECATION")
        packageManager.getPackageInfo(packageName, 0).versionCode
    } catch (_: Exception) { 0 }
    val rt = Runtime.getRuntime()
    val ramUsed = rt.totalMemory() - rt.freeMemory()
    val apkLen = try { File(applicationInfo.sourceDir).length() } catch (_: Exception) { 0L }
    val dataLen = try { dirSize(filesDir) + dirSize(cacheDir) } catch (_: Exception) { 0L }
    val lifetime = prefs().getLong(TunnelService.KEY_TRAFFIC_LIFETIME, 0L)
    val currentProto = try {
        RrpUri.parse(prefs().getString(TunnelService.KEY_CONFIG, "") ?: "").proto
    } catch (_: Exception) { RrpProtocols.DEFAULT }
    val modulesV = RrpProtocols.registryVersion().ifEmpty { getString(R.string.app_modules_builtin) }
    infoRow(appInfoBox, getString(R.string.app_version_row), "${currentVersion()} ($code)")
    infoRow(appInfoBox, getString(R.string.app_modules_row), "$modulesV · ${RrpProtocols.displayList().joinToString(", ") { RrpProtocols.labelWithVer(it) }}")
    infoRow(appInfoBox, getString(R.string.app_ram_row), fmtBytes(ramUsed))
    infoRow(appInfoBox, getString(R.string.app_disk_row), fmtBytes(apkLen + dataLen))
    infoRow(appInfoBox, getString(R.string.app_traffic_life_row), fmtBytes(lifetime))
    infoRow(appInfoBox, getString(R.string.app_proto_row), ProtocolState.display())
    // v0.8.1: версия текущего протокола (или пусто, если версии нет — канон)
    val pver = RrpProtocols.ver(currentProto)
    infoRow(appInfoBox, getString(R.string.app_proto_ver_row), pver.ifEmpty { "—" })
    // v0.8.2: модуль камуфляжа «API Mask» — версия и статус, честно
    val camo = RrpProtocols.camouflageConfig()
    infoRow(
        appInfoBox, getString(R.string.app_camo_row),
        if (camo.enabled) RrpProtocols.camouflageLabel() else getString(R.string.app_camo_off),
    )
    // v0.8.1: срок действия серверного TLS-сертификата (если видели рукопожатие)
    val certMs = RrpClient.lastServerCertNotAfterMs
    if (certMs > 0) {
        infoRow(appInfoBox, getString(R.string.app_cert_row), SimpleDateFormat("dd.MM.yyyy", Locale.getDefault()).format(Date(certMs)))
    }
    appInfoBox.addView(
        Button(this).apply {
            setText(R.string.dev_copy)
            background = null
            setOnClickListener {
                copyPanel(appInfoBox, "ReverseRay app")
            }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { gravity = Gravity.END }
        }
    )

    // Константы защиты — отдельная честная секция (канал «ничего не прячем»)
    appInfoBox.addView(TextView(this).apply {
        setText(R.string.sf_section)
        textSize = 13f
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(10), 0, dp(2))
    })
    val sfTitles = listOf(
        R.string.sf_tls_min, R.string.sf_alpn, R.string.sf_tls_provider,
        R.string.sf_cert_model, R.string.sf_pin_policy, R.string.sf_zero_rtt,
        R.string.sf_token_storage, R.string.sf_handshake, R.string.sf_nonce,
        R.string.sf_rate_limit, R.string.sf_mtproto2, R.string.sf_frame_limits,
        R.string.sf_wan, R.string.sf_ssrf, R.string.sf_modules, R.string.sf_apk_integrity,
    )
    for ((titleRes, value) in sfTitles.zip(SecurityFacts.values())) {
        infoRow(appInfoBox, getString(titleRes), value)
    }
}


/** «О устройстве» + CPU-модель, общая RAM, SDK, Java. */
internal fun MainActivity.refreshDevicePanel() {
    deviceInfoBox.removeAllViews()
    val kernel = try { System.getProperty("os.version") ?: "—" } catch (_: Exception) { "—" }
    val cpuModel = cpuModel()
    val abis = try { Build.SUPPORTED_ABIS.firstOrNull() ?: "—" } catch (_: Exception) { "—" }
    val sec = try {
        if (Build.VERSION.SDK_INT >= 22) {
            @Suppress("DEPRECATION")
            Build.VERSION.SECURITY_PATCH
        } else "—"
    } catch (_: Throwable) { "—" }
    val totalRam = totalRamBytes()
    val m = resources.displayMetrics
    infoRow(deviceInfoBox, getString(R.string.dev_model), "${Build.MANUFACTURER} ${Build.MODEL}")
    infoRow(deviceInfoBox, getString(R.string.dev_android), "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
    infoRow(deviceInfoBox, getString(R.string.dev_sdk), "SDK ${Build.VERSION.SDK_INT}")
    infoRow(deviceInfoBox, getString(R.string.dev_cpu_model), cpuModel.ifEmpty { abis })
    infoRow(deviceInfoBox, getString(R.string.dev_ram_total), fmtBytes(totalRam))
    infoRow(deviceInfoBox, getString(R.string.dev_java), javaVmInfo())
    infoRow(deviceInfoBox, getString(R.string.dev_build), Build.DISPLAY)
    infoRow(deviceInfoBox, getString(R.string.dev_patch), sec)
    infoRow(deviceInfoBox, getString(R.string.dev_kernel), kernel)
    infoRow(deviceInfoBox, getString(R.string.dev_screen), "${m.widthPixels}×${m.heightPixels} @${m.density}x")
    infoRow(deviceInfoBox, getString(R.string.dev_version), "${currentVersion()} (${getString(R.string.app_name)})")
    // v0.8.1: честно показываем, ЧТО именно читаем об устройстве (канал прозрачности)
    infoRow(deviceInfoBox, getString(R.string.dev_sources_row), getString(R.string.dev_sources_list))
    deviceInfoBox.addView(
        Button(this).apply {
            setText(R.string.dev_copy)
            background = null
            setOnClickListener { copyPanel(deviceInfoBox, "ReverseRay device") }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { gravity = Gravity.END }
        }
    )
}


/** «О сети» — честно всё, что приложение узнало (DnsProbe + NetInfo)
 *  + v0.8.1: ЧЕМ и ГДЕ мы это узнали (источники — канон прозрачности). */
internal fun MainActivity.refreshNetPanel() {
    netInfoBox.removeAllViews()
    infoRow(netInfoBox, getString(R.string.netinfo_loading), lastExternalIp ?: "…")
    netInfoBox.addView(TextView(this).apply {
        setText(R.string.about_net_hint)
        textSize = 11f
        setTextColor(0xFF6B7280.toInt())
        setPadding(0, dp(6), 0, dp(2))
    })
    Thread {
        val dns = try { DnsProbe.collect() } catch (_: Throwable) { null }
        val external = try { NetInfoFetcher.fetch() } catch (_: Exception) { null }
        runOnUiThread {
            netInfoBox.removeAllViews()
            // Честные источники: куда ходили и что читали локально
            infoRow(
                netInfoBox, getString(R.string.net_sources_row),
                NetInfoFetcher.SOURCES.joinToString(", ") + " · " +
                    getString(R.string.net_sources_local),
            )
            external?.let { e ->
                infoRow(
                    netInfoBox, getString(R.string.net_external_ip),
                    "${e.ip}${e.country?.let { " · $it" } ?: ""}${e.isp?.let { " · $it" } ?: ""}" +
                        (if (e.source.isNotEmpty()) " · ${getString(R.string.netinfo_source, e.source)}" else ""),
                )
            }
            if (dns == null) {
                infoRow(netInfoBox, "DNS", getString(R.string.net_facts_failed))
            } else {
                for ((k, v) in DnsProbe.describe(dns)) {
                    infoRow(netInfoBox, k, v)
                }
            }
        }
    }.apply { isDaemon = true }.start()
}


internal fun MainActivity.copyPanel(box: LinearLayout, label: String) {
    val sb = StringBuilder()
    for (i in 0 until box.childCount) {
        val rowL = box.getChildAt(i) as? LinearLayout ?: continue
        if (rowL.childCount == 2) {
            sb.append((rowL.getChildAt(0) as TextView).text).append(": ")
                .append((rowL.getChildAt(1) as TextView).text).append('\n')
        }
    }
    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText(label, sb.toString()))
    Toast.makeText(this, R.string.logs_copied, Toast.LENGTH_SHORT).show()
}


internal fun MainActivity.dirSize(dir: File): Long = try {
    dir.walkBottomUp().filter { it.isFile }.map { it.length() }.sum()
} catch (_: Exception) {
    0L
}


internal fun MainActivity.cpuModel(): String = try {
    File("/proc/cpuinfo").useLines { lines ->
        lines.firstOrNull { it.startsWith("Hardware") }?.substringAfter(":")?.trim()
            ?: lines.firstOrNull { it.startsWith("model name") }?.substringAfter(":")?.trim()
            ?: ""
    }
} catch (_: Exception) {
    ""
}


internal fun MainActivity.totalRamBytes(): Long = try {
    val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    val mi = ActivityManager.MemoryInfo()
    am.getMemoryInfo(mi)
    mi.totalMem
} catch (_: Exception) {
    0L
}


internal fun MainActivity.javaVmInfo(): String = try {
    "${System.getProperty("java.vm.name") ?: "?"} ${System.getProperty("java.vm.version") ?: ""}"
} catch (_: Exception) {
    "?"
}

