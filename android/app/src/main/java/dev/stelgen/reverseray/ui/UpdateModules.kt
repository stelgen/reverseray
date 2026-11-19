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

internal fun MainActivity.currentVersion(): String = try {
    packageManager.getPackageInfo(packageName, 0).versionName ?: ""
} catch (_: Exception) {
    ""
}


internal fun MainActivity.refreshVersionRow() {
    val code = try {
        @Suppress("DEPRECATION")
        packageManager.getPackageInfo(packageName, 0).versionCode
    } catch (_: Exception) {
        0
    }
    versionView.text = getString(R.string.version_row, currentVersion(), code)
}


internal fun MainActivity.refreshModulesInfo() {
    val v = RrpProtocols.registryVersion()
    val protocols = RrpProtocols.displayList()
    modulesInfoView.text = getString(
        R.string.proto_current_list,
        if (v.isEmpty()) getString(R.string.app_modules_builtin) else v,
        protocols.joinToString(", "),
    )
}


internal fun MainActivity.refreshUpdateConsole() {
    // v0.9.7: единый маппинг цветов (StatusConsole.roleOf), источник — LogStore (канал UPDATE)
    updateConsole.render(toConsoleLines(UpdateLogger.snapshot()))
}


/** v0.8: применить сохранённый манифест модулей при старте. */
internal fun MainActivity.loadCachedModules() {
    try {
        val f = File(filesDir, "modules.json")
        if (!f.exists()) return
        val m = Modules.parse(f.readText())
        Modules.apply(m)
    } catch (_: Exception) {
        // битый кеш не применяем — работаем на встроенных
    }
}


/**
 * Синхронизация модулей (тот же modules.json, что ест сервер):
 * качается ТОЛЬКО если версия/хеш изменились; применяется без
 * переустановки APK. Прогресс и скорость — в консоль обновления.
 */
internal fun MainActivity.syncModulesAsync(force: Boolean) {
    val url = Modules.DEFAULT_URL
    UpdateLogger.add(getString(R.string.upd_modules_check, url.substringAfterLast('/')))
    Thread {
        try {
            val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 10_000
            conn.readTimeout = 15_000
            conn.setRequestProperty("Accept", "application/json")
            conn.connect()
            if (conn.responseCode != 200) {
                throw Modules.ManifestException("HTTP ${conn.responseCode}")
            }
            UpdateLogger.add(getString(R.string.upd_modules_http, conn.responseCode))
            val len = conn.contentLengthLong
            var total = 0L
            var lastPct = -10
            val baos = java.io.ByteArrayOutputStream()
            conn.inputStream.use { input ->
                val buf = ByteArray(16 * 1024)
                val start = System.currentTimeMillis()
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    baos.write(buf, 0, n)
                    total += n
                    if (len > 0) {
                        val pct = (total * 100 / len).toInt().coerceIn(0, 100)
                        if (pct >= lastPct + 10) {
                            lastPct = pct
                            val secs = ((System.currentTimeMillis() - start).coerceAtLeast(1)) / 1000.0
                            val kbps = total / 1024.0 / secs
                            UpdateLogger.add(getString(R.string.modules_progress, pct, Formats.kbps(this, kbps)))
                        }
                    }
                }
            }
            conn.disconnect()
            val body = baos.toString("UTF-8")
            UpdateLogger.add(getString(R.string.upd_modules_received, fmtBytes(total)), LogKind.OK)
            val m = Modules.parse(body)
            UpdateLogger.add(
                getString(
                    R.string.upd_modules_parsed, m.version,
                    m.enabledProtocolIds().joinToString(", ") { RrpProtocols.labelWithVer(it) },
                ),
            )
            // даунгрейд запрещён (как на сервере)
            val current = RrpProtocols.registryVersion()
            if (current.isNotEmpty() && Modules.versionCompare(m.version, current) < 0) {
                UpdateLogger.add(getString(R.string.upd_modules_older, m.version, current), LogKind.WARN)
                refreshUpdateConsoleSafe()
                return@Thread
            }
            val cachedHash = prefs().getString(MainActivity.KEY_MODULES_HASH, "")
            val hash = java.security.MessageDigest.getInstance("SHA-256")
                .digest(body.toByteArray(Charsets.UTF_8))
                .joinToString("") { String.format(Locale.US, "%02x", it) }
            if (!force && m.version == current && hash == cachedHash) {
                UpdateLogger.add(getString(R.string.modules_up_to_date), LogKind.OK)
                refreshUpdateConsoleSafe()
                return@Thread
            }
            Modules.apply(m)
            File(filesDir, "modules.json").writeText(body)
            prefs().edit().putString(MainActivity.KEY_MODULES_HASH, hash).apply()
            UpdateLogger.add(
                getString(
                    R.string.modules_applied, m.version,
                    m.enabledProtocolIds().joinToString(", ") { RrpProtocols.labelWithVer(it) },
                ),
                LogKind.OK,
            )
            runOnUiThread {
                refreshModulesInfo()
                refreshConnLine()
            }
        } catch (e: Exception) {
            UpdateLogger.add(getString(R.string.modules_failed, e.message ?: "?"), LogKind.ERR)
        }
        refreshUpdateConsoleSafe()
    }.apply { isDaemon = true }.start()
}


internal fun MainActivity.refreshUpdateConsoleSafe() {
    runOnUiThread { refreshUpdateConsole() }
}


/** Автопроверка обновлений раз в 24 ч (вкл. по умолчанию, закрываемое окно). */
internal fun MainActivity.maybeAutoCheckUpdate() {
    val p = prefs()
    if (!p.getBoolean(TunnelService.KEY_AUTO_UPDATE, true)) return
    val last = p.getLong(MainActivity.KEY_LAST_UPDATE_CHECK, 0L)
    val now = System.currentTimeMillis()
    if (now - last < MainActivity.UPDATE_CHECK_INTERVAL_MS) return
    p.edit().putLong(MainActivity.KEY_LAST_UPDATE_CHECK, now).apply()
    checkForUpdateAsync(showIfUpToDate = false)
}


/** v0.8: автоподключение при открытии приложения (выкл по умолчанию). */
internal fun MainActivity.maybeAutoConnect() {
    if (!prefs().getBoolean(TunnelService.KEY_AUTO_RECONNECT, false)) return
    val cfg = prefs().getString(TunnelService.KEY_CONFIG, null) ?: return
    if (cfg.isBlank()) return
    val used = prefs().getLong(TunnelService.KEY_TRAFFIC_USED, 0L)
    val limit = prefs().getLong(TunnelService.KEY_TRAFFIC_LIMIT, 0L)
    if (limit > 0 && used >= limit) {
        // лимит достигнут: ждём сброса (TunnelService сам ждёт даты)
        TunnelService.pushLog(getString(R.string.status_limit_reached), LogKind.WARN)
        showLimitDialog(null)
        return
    }
    startTunnel()
}


internal fun MainActivity.checkForUpdateAsync(showIfUpToDate: Boolean) {
    val current = currentVersion()
    UpdateLogger.add(getString(R.string.upd_check_start, current))
    refreshUpdateConsoleSafe()
    Thread {
        val info = UpdateChecker().check(current)
        if (info == null) {
            UpdateLogger.add(getString(R.string.upd_check_none), LogKind.OK)
            if (showIfUpToDate) {
                runOnUiThread { Toast.makeText(this, R.string.update_latest, Toast.LENGTH_SHORT).show() }
            }
        } else {
            UpdateLogger.add(getString(R.string.upd_check_available, info.latestTag, info.apkUrl.substringAfterLast('/')), LogKind.OK)
            if (info.sumsUrl.isNotEmpty()) {
                UpdateLogger.add(getString(R.string.upd_sums_found), LogKind.OK)
            } else {
                UpdateLogger.add(getString(R.string.upd_sums_missing), LogKind.WARN)
            }
            runOnUiThread {
                refreshUpdateConsole()
                MaterialAlertDialogBuilder(this)
                    .setTitle(getString(R.string.update_title, info.latestTag))
                    .setMessage(getString(R.string.update_question))
                    .setPositiveButton(R.string.update_download) { _, _ -> downloadUpdate(info) }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
        refreshUpdateConsoleSafe()
    }.apply { isDaemon = true }.start()
}


internal fun MainActivity.downloadUpdate(info: UpdateInfo) {
    val dir = File(cacheDir, "apk").apply { mkdirs() }
    val dest = File(dir, "update-${info.latestTag}.apk")
    UpdateLogger.add(getString(R.string.upd_dl_start, info.latestTag))
    Thread {
        try {
            val conn = java.net.URL(info.apkUrl).openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 10_000
            conn.readTimeout = 20_000
            conn.connect()
            val len = conn.contentLengthLong
            var total = 0L
            var lastPct = -10
            conn.inputStream.use { input ->
                dest.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    val start = System.currentTimeMillis()
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        total += n
                        if (len > 0) {
                            val pct = (total * 100 / len).toInt().coerceIn(0, 100)
                            if (pct >= lastPct + 10) {
                                lastPct = pct
                                val secs = ((System.currentTimeMillis() - start).coerceAtLeast(1)) / 1000.0
                                val speed = Formats.kbps(this, total / 1024.0 / secs)
                                UpdateLogger.add(getString(R.string.update_progress, pct, speed))
                            }
                        }
                    }
                    out.flush()
                }
            }
            conn.disconnect()
            // v0.8.1 (анти-подмена): сверяем APK с SHA256SUMS релиза до установки
            val checker = UpdateChecker()
            val sums = checker.downloadSums(info.sumsUrl)
            val verifyErr = checker.verifyApk(dest, sums)
            if (verifyErr != null) {
                dest.delete()
                UpdateLogger.add(getString(R.string.upd_verify_fail, verifyErr), LogKind.ERR)
                runOnUiThread {
                    refreshUpdateConsole()
                    Toast.makeText(this, getString(R.string.update_error, "SHA256 mismatch"), Toast.LENGTH_LONG).show()
                }
                return@Thread
            }
            UpdateLogger.add(getString(R.string.upd_dl_done, dest.name, fmtBytes(dest.length())))
            UpdateLogger.add(getString(R.string.upd_verify_ok, fmtBytes(dest.length())), LogKind.OK)
            runOnUiThread {
                refreshUpdateConsole()
                installApk(dest)
            }
        } catch (e: Exception) {
            UpdateLogger.add(getString(R.string.upd_dl_error, e.message ?: "?"), LogKind.ERR)
            runOnUiThread {
                refreshUpdateConsole()
                Toast.makeText(this, getString(R.string.update_error, e.message ?: ""), Toast.LENGTH_LONG).show()
            }
        }
    }.apply { isDaemon = true }.start()
}


internal fun MainActivity.installApk(file: File) {
    val uri: Uri = FileProvider.getUriForFile(this, "$packageName.files", file)
    val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
        data = uri
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    try {
        startActivity(intent)
    } catch (e: ActivityNotFoundException) {
        UpdateLogger.add(getString(R.string.upd_install_no_installer), LogKind.WARN)
        Toast.makeText(this, R.string.update_error, Toast.LENGTH_SHORT).show()
    }
}

