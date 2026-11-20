package dev.stelgen.reverseray.ui

// v1.8.0: диалоги/пикеры и link-зона вынесены из MainActivity.kt (дробление
// по зонам ответственности). Pure refactor: private → internal у задетых
// членов, поведение не меняется.

import android.content.Intent
import android.graphics.Typeface
import android.os.Build
import android.view.View
import android.widget.Toast
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import dev.stelgen.reverseray.MainActivity
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.ConfigResult
import dev.stelgen.reverseray.core.ConfigSource
import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.LogStore
import dev.stelgen.reverseray.core.RrpFrame
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.RrpUriConfig
import dev.stelgen.reverseray.core.ProtocolState
import dev.stelgen.reverseray.core.SessionStore
import dev.stelgen.reverseray.service.PrefsBackend
import dev.stelgen.reverseray.service.TunnelService
import dev.stelgen.reverseray.service.protoDisplayName

internal fun MainActivity.showProtocolPicker() {
    val ids = RrpProtocols.displayList()
    if (ids.isEmpty()) {
        Toast.makeText(this, R.string.proto_unknown, Toast.LENGTH_SHORT).show()
        return
    }
    // Заявленный протокол ссылки — для решения «менять или нет»;
    // ОТОБРАЖАЕМЫЙ текущий выбор — из ProtocolState (согласованный).
    val current = when (val res = resolvedConfig()) {
        is ConfigResult.Valid -> res.cfg.proto
        else -> ""
    }
    // v0.9.5: первый пункт — AUTO (ссылка без proto=): сервер сам согласует
    // лучший общий протокол (wireguard → mtproto2 → rrp1).
    // v1.8.0: второй пункт — «Ротация» (взаимоисключающ с AUTO).
    // v1.8.6: пункты — короткие имена протоколов БЕЗ пояснений (канон «как
    // WS»); после фоллбека сервера пикер честно показывает СОГЛАСОВАННЫЙ
    // протокол (ProtocolState), а не заявленный в ссылке.
    val rotateOn = prefs().getBoolean(TunnelService.KEY_PROTO_ROTATE, false)
    val options = mutableListOf<String>()
    options.add(ProtocolState.AUTO)
    options.add(ProtocolState.ROTATE)
    options.addAll(ids.map { ProtocolState.plainName(it) })
    val checked = when {
        rotateOn && ProtocolState.negotiated.isBlank() -> 1
        ProtocolState.negotiated.isNotBlank() -> ids.indexOf(ProtocolState.actual()).let { if (it < 0) 0 else it + 2 }
        current.isBlank() -> 0
        else -> ids.indexOf(ProtocolState.actual()).let { if (it < 0) 0 else it + 2 }
    }
    MaterialAlertDialogBuilder(this)
        .setTitle(R.string.proto_switch)
        .setSingleChoiceItems(options.toTypedArray(), checked) { dialog, which ->
            dialog.dismiss()
            if (which == 0) {
                if (current.isNotBlank() || rotateOn) requestProtoSwitch(TunnelService.PROTO_AUTO)
            } else if (which == 1) {
                if (!rotateOn) requestProtoSwitch(TunnelService.PROTO_ROTATE)
            } else {
                val picked = ids[which - 2]
                if (picked != current || rotateOn) requestProtoSwitch(picked)
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

internal fun MainActivity.requestProtoSwitch(proto: String) {
    setConnText(getString(R.string.proto_switching, protoDisplayName(proto)))
    val i = Intent(this, TunnelService::class.java)
        .setAction(TunnelService.ACTION_SWITCH_PROTO)
        .putExtra(TunnelService.EXTRA_PROTO, proto)
    if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
}

/** v0.9.7: текущий транспорт из единого резолва (tcp по умолчанию, ws = WebSocket). */
internal fun MainActivity.currentTransport(): String = when (val res = resolvedConfig()) {
    is ConfigResult.Valid -> res.cfg.transport
    else -> RrpUri.TRANSPORT_TCP
}

/**
 * v0.9.7 (роадмап): выбор транспорта tcp/ws из UI. Параметр уже был
 * в ссылке — теперь есть переключатель; ссылка остаётся источником правды.
 * Применение — при следующем Старте (сервис читает транспорт при старте).
 */
internal fun MainActivity.showTransportPicker() {
    val cfg = when (val res = resolvedConfig()) {
        is ConfigResult.Valid -> res.cfg
        else -> null
    }
    if (cfg == null) {
        Toast.makeText(this, R.string.link_status_bad, Toast.LENGTH_SHORT).show()
        return
    }
    val options = arrayOf(
        getString(R.string.transport_tcp_label),
        getString(R.string.transport_ws_label),
    )
    val checked = if (cfg.transport == RrpUri.TRANSPORT_WS) 1 else 0
    MaterialAlertDialogBuilder(this)
        .setTitle(R.string.transport_switch)
        .setSingleChoiceItems(options, checked) { dialog, which ->
            dialog.dismiss()
            val picked = if (which == 1) RrpUri.TRANSPORT_WS else RrpUri.TRANSPORT_TCP
            if (picked == cfg.transport) {
                Toast.makeText(this, R.string.transport_same, Toast.LENGTH_SHORT).show()
                return@setSingleChoiceItems
            }
            applyTransport(cfg, picked)
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

internal fun MainActivity.applyTransport(cfg: RrpUriConfig, transport: String) {
    val label = getString(
        if (transport == RrpUri.TRANSPORT_WS) R.string.transport_ws_label else R.string.transport_tcp_label,
    )
    val canonical = cfg.copy(transport = transport).serialize()
    prefs().edit().putString(TunnelService.KEY_CONFIG, canonical).apply()
    // v1.8.6: писатель ссылки обязан синхронизировать единый источник протокола
    ProtocolState.sync(canonical, prefs().getBoolean(TunnelService.KEY_PROTO_ROTATE, false))
    syncPrimaryProfileUri(canonical)
    updateLinkValueView(canonical)
    refreshConnLine()
    val msg = getString(R.string.transport_applied, label)
    LogStore.push(msg, LogKind.INFO, LogStore.Channel.STATUS)
    Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}

// ================================================================= Ссылка (авто-починка)

/** Вставили/ввели ссылку → приложение САМО чинит, сохраняет и подтверждает. */
internal fun MainActivity.applyPastedConfig(content: String, announce: Boolean, silentFail: Boolean = false) {
    // v1.8.4: единая валидация — ConfigSource.validate (раньше try/catch parse
    // в каждой зоне отдельно; теперь все зовут одну точку).
    when (val res = ConfigSource.validate(content)) {
        is ConfigResult.Valid -> {
            val canonical = res.canonical
            prefs().edit().putString(TunnelService.KEY_CONFIG, canonical).apply()
            ProtocolState.sync(canonical, prefs().getBoolean(TunnelService.KEY_PROTO_ROTATE, false))
            syncPrimaryProfileUri(canonical)
            updateLinkValueView(canonical)
            setLinkStatus(getString(R.string.link_status_ok))
            refreshConnLine()
            if (announce) {
                Toast.makeText(this, R.string.link_saved, Toast.LENGTH_SHORT).show()
                probeConfig(canonical) // v1.3.0: тестовый прогон после принятия ссылки
            }
        }
        is ConfigResult.Invalid -> {
            setLinkStatus(getString(R.string.link_status_bad))
            if (announce || !silentFail) {
                Toast.makeText(this, getString(R.string.invalid_config, res.reason), Toast.LENGTH_LONG).show()
            }
        }
        ConfigResult.Empty -> {
            setLinkStatus(getString(R.string.link_status_bad))
            if (announce || !silentFail) {
                Toast.makeText(this, getString(R.string.invalid_config, getString(R.string.status_no_config)), Toast.LENGTH_LONG).show()
            }
        }
    }
}

internal fun MainActivity.setLinkStatus(okText: String?) {
    // v0.8.2: пустой статус НЕ занимает место — никаких «пустых полей»
    if (okText == null) {
        linkStatusView.visibility = View.GONE
        return
    }
    linkStatusView.visibility = View.VISIBLE
    linkStatusView.text = okText
    linkStatusView.setTextColor(0xFF2E7D32.toInt())
}

/** Очистить поле — только с подтверждением (канон UX v0.8). */
internal fun MainActivity.updateLinkValueView(value: String? = null) {
    val cur = value ?: prefs().getString(TunnelService.KEY_CONFIG, "") ?: ""
    linkValueView.text = if (cur.isBlank()) getString(R.string.link_empty) else cur
}

/** v1.3.0: диалог правки ссылки — Отмена / Очистить / ОК (+ тестовый прогон). */
internal fun MainActivity.showEditLinkDialog() {
    val cur = prefs().getString(TunnelService.KEY_CONFIG, "") ?: ""
    val input = TextInputEditText(this).apply {
        setText(cur)
        minLines = 2
        minHeight = dp(96)
        setTextSize(12f)
        setTypeface(Typeface.MONOSPACE)
    }
    val container = TextInputLayout(this).apply {
        hint = getString(R.string.config_hint)
    }
    container.addView(input)
    val dialog = MaterialAlertDialogBuilder(this)
        .setTitle(R.string.link_edit_title)
        .setView(container)
        .setPositiveButton(R.string.link_ok, null)
        .setNeutralButton(R.string.link_clear, null)
        .setNegativeButton(R.string.link_cancel, null)
        .create()
    dialog.setOnShowListener {
        dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
            input.setText("")
        }
        dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val text = input.text?.toString()?.trim().orEmpty()
            dialog.dismiss()
            if (text.isBlank()) {
                prefs().edit().remove(TunnelService.KEY_CONFIG).apply()
                ProtocolState.sync("", false)
                // v1.5.0: очистка ссылки = очистка профилей (single-server UX как в v1.3.0)
                try {
                    val store = SessionStore(PrefsBackend(prefs()))
                    store.migrateLegacy(prefs().getString(TunnelService.KEY_CONFIG, null))
                    for (pr in store.profiles()) store.remove(pr.id)
                } catch (_: Exception) {}
                updateLinkValueView("")
                setLinkStatus(null)
                Toast.makeText(this, R.string.link_clear, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            when (val res = ConfigSource.validate(text)) {
                is ConfigResult.Valid -> {
                    val canonical = res.canonical
                    prefs().edit().putString(TunnelService.KEY_CONFIG, canonical).apply()
                    ProtocolState.sync(canonical, prefs().getBoolean(TunnelService.KEY_PROTO_ROTATE, false))
                    syncPrimaryProfileUri(canonical)
                    updateLinkValueView(canonical)
                    setLinkStatus(getString(R.string.link_status_ok))
                    refreshConnLine()
                    probeConfig(canonical) // тестовый прогон + уведомление внизу экрана
                }
                is ConfigResult.Invalid ->
                    Toast.makeText(this, getString(R.string.invalid_config, res.reason), Toast.LENGTH_LONG).show()
                ConfigResult.Empty ->
                    Toast.makeText(this, getString(R.string.invalid_config, getString(R.string.status_no_config)), Toast.LENGTH_LONG).show()
            }
        }
    }
    dialog.show()
}

/** v1.3.0: тестовый прогон конфигурации — TCP+TLS (пин SPKI) + HELLO/HELLO_OK. */
internal fun MainActivity.probeConfig(canonical: String) {
    kotlin.concurrent.thread {
        val (ok, msg) = try {
            val cfg = RrpUri.parse(canonical)
            probeServer(cfg)
        } catch (e: Exception) {
            ProbeOut(false, e.message ?: e.javaClass.simpleName)
        }
        runOnUiThread {
            if (ok) {
                Toast.makeText(this, R.string.probe_ok, Toast.LENGTH_LONG).show()
                setLinkStatus(getString(R.string.probe_ok_short))
            } else {
                Toast.makeText(this, getString(R.string.probe_fail, msg), Toast.LENGTH_LONG).show()
                setLinkStatus(getString(R.string.probe_fail_short))
            }
        }
    }
}

internal data class ProbeOut(val ok: Boolean, val msg: String)

internal fun MainActivity.probeServer(cfg: RrpUriConfig): ProbeOut {
    val want: ByteArray? = try {
        cfg.pin?.let {
            android.util.Base64.decode(it, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
        }
    } catch (e: Exception) {
        return ProbeOut(false, "bad pin: " + (e.message ?: ""))
    }
    var last = "unreachable"
    for (port in cfg.ports) {
        var raw: java.net.Socket? = null
        try {
            raw = java.net.Socket()
            raw.connect(java.net.InetSocketAddress(cfg.host, port), 10_000)
            raw.soTimeout = 10_000
            val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {
                    val ca = chain?.lastOrNull() ?: throw java.security.cert.CertificateException("no chain")
                    if (want != null) {
                        // SPKI DER = encoded публичного ключа сертификата
                        val sum = java.security.MessageDigest.getInstance("SHA-256")
                            .digest(ca.publicKey.encoded)
                        if (!sum.contentEquals(want)) {
                            throw java.security.cert.CertificateException("SPKI pin mismatch")
                        }
                    }
                }
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
            }), java.security.SecureRandom())
            val s = ctx.socketFactory.createSocket(raw, cfg.host, port, true) as javax.net.ssl.SSLSocket
            s.startHandshake()
            val out = s.getOutputStream()
            out.write(
                RrpFrame.Hello(
                    agent = "reverseray-probe",
                    protocolVersion = RrpFrame.VERSION,
                    device = "probe",
                    caps = listOf(),
                    maxStreams = 1,
                ).encode()
            )
            out.flush()
            val f = RrpFrame.parse(s.getInputStream())
            val ok = f.type == RrpFrame.TYPE_HELLO_OK
            try { s.close() } catch (_: Exception) {}
            raw = null
            if (ok) return ProbeOut(true, "")
            last = "unexpected reply type"
        } catch (e: Exception) {
            last = e.message ?: e.javaClass.simpleName
        } finally {
            try { raw?.close() } catch (_: Exception) {}
        }
    }
    return ProbeOut(false, last)
}
