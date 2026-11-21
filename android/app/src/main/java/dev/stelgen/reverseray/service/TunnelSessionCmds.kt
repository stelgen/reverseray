// v1.9.0: зона «session-команды/смена протокола» вынесена из TunnelService.kt
// (транш-2): валидационный switchProtocol (kill → validate → commit → spawn),
// коммит протокола, камуфляж 0x2A, дашборд-команды сессии, probe профиля.
// Pure refactor: private → internal у задетых членов, поведение не меняется.
package dev.stelgen.reverseray.service

import android.content.Intent
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.ConfigResult
import dev.stelgen.reverseray.core.ConnectionManager
import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.RrpUriConfig
import dev.stelgen.reverseray.core.SessionStore

// ------------------------------------------------------------------ смена протокола (валидация → коммит, иначе откат) и session-команды

    /**
     * Валидационная смена протокола:
     * 1) provisional-коннект с новым протоколом + PROBE реального хоста;
     * 2) успех → коммит: сохраняем протокол и обновляем ссылку в конфиге;
     * 3) неудача (3 ретрая) → мгновенный откат UI на текущий протокол,
     *    ссылка НЕ меняется; cooldown, чтобы не молотить по rate-limit.
     */
    internal fun TunnelService.switchProtocol(newProtoRaw: String) {
        // v1.8.0: «Ротация» — отдельный режим выбора (взаимоисключающ с авто):
        // включаем флаг и выходим — смены делает rotateTick (каждые 30 мин,
        // строго по порядку, причины в журнале). Ссылку НЕ меняем: ротация —
        // режим ПОВЕДЕНИЯ поверх текущего подключения.
        if (newProtoRaw == TunnelService.PROTO_ROTATE) {
            prefs().edit().putBoolean(TunnelService.KEY_PROTO_ROTATE, true).apply()
            rotators.clear() // якорь расписания заново (первый тик якорит)
            TunnelService.pushLog(getString(R.string.log_proto_rotation_on, TunnelService.ROTATE_INTERVAL_MS / 60_000), LogKind.INFO)
            updateStatus(TunnelService.STATE_INFO, getString(R.string.status_rotate_on, TunnelService.ROTATE_INTERVAL_MS / 60_000))
            startRotateTick()
            return
        }
        // обычный выбор (протокол/AUTO) выключает ротацию (взаимоисключение)
        if (prefs().getBoolean(TunnelService.KEY_PROTO_ROTATE, false)) {
            prefs().edit().putBoolean(TunnelService.KEY_PROTO_ROTATE, false).apply()
            TunnelService.pushLog(getString(R.string.log_proto_rotation_off), LogKind.INFO)
        }
        // v0.9.5: "auto" — явный режим «лучший общий протокол» (ссылка без proto=).
        val isAuto = newProtoRaw == TunnelService.PROTO_AUTO
        val newProto = if (isAuto) TunnelService.PROTO_AUTO else RrpProtocols.normalize(newProtoRaw)
        val oldProto = currentProto()
        val p = prefs()
        if (isAuto && claimedProto().isBlank()) {
            updateStatus(TunnelService.STATE_INFO, getString(R.string.status_switch_same, protoDisplayName(TunnelService.PROTO_AUTO)))
            return
        }
        if (switchingProto) {
            updateStatus(TunnelService.STATE_INFO, getString(R.string.status_switch_busy))
            return
        }
        val now = System.currentTimeMillis()
        if (now < TunnelService.nextSwitchAllowedAt) {
            updateStatus(TunnelService.STATE_INFO, getString(R.string.status_switch_cooldown, (TunnelService.nextSwitchAllowedAt - now) / 1000))
            return
        }
        if (!isAuto && newProto == oldProto) {
            updateStatus(TunnelService.STATE_INFO, getString(R.string.status_switch_same, RrpProtocols.labelWithVer(newProto)))
            return
        }
        // v0.9.5: "auto" — режим без proto= в ссылке; валидируем предпочтительным,
        // в ссылку AUTO не пишем (proto= не появляется).
        val commitProtoId = if (newProto == TunnelService.PROTO_AUTO) "" else newProto
        val validateProto = if (newProto == TunnelService.PROTO_AUTO) RrpProtocols.PREFERRED_AUTO else newProto
        switchingProto = true
        // v1.8.4: DEBUG — начало смены протокола (от → до) для диагностики свитчей.
        TunnelService.pushLog(
            "switch begin: " + (if (oldProto.isBlank()) "-" else RrpProtocols.labelWithVer(oldProto)) +
                " → " + (if (isAuto) "AUTO" else RrpProtocols.labelWithVer(newProto)),
            LogKind.DEBUG,
        )
        // v1.5.0: смена протокола — ОПЕРАЦИЯ НАД PRIMARY (главная кнопка/пикер);
        // другие сессии живут своей жизнью (изоляция).
        val primarySess = sessionStore.activeId()?.let { sessById[it] }
        switchingSessionId = sessionStore.activeId()
        try {
            val cfg = when (val res = resolvedConfig()) {
                is ConfigResult.Valid -> res.cfg
                is ConfigResult.Invalid -> {
                    updateStatus(TunnelService.STATE_ERROR, getString(R.string.invalid_config, res.reason))
                    return
                }
                ConfigResult.Empty -> {
                    updateStatus(TunnelService.STATE_ERROR, getString(R.string.status_no_config))
                    return
                }
            }
            updateStatus(TunnelService.STATE_CONNECTING, getString(R.string.status_switch_trying, protoDisplayName(newProto)))
            // v0.9.2 (R1): АТОМАРНОСТЬ ПЕРЕКЛЮЧЕНИЯ — старые коннекты PRIMARY
            // гарантированно закрыты ДО provisional-коннекта с новым протоколом.
            // Теперь: kill → validate → commit → spawn (только PRIMARY-сессия).
            primarySess?.let { killRunnersOf(it) }
            var lastErr = ""
            for (attempt in 1..TunnelService.SWITCH_RETRIES) {
                val client = buildClient(cfg, validateProto, validate = true)
                try {
                    client.connect()
                    // валидация (PROBE) уже прошла внутри connect() — коммитим.
                    // v1.8.6: коммитим СОГЛАСОВАННЫЙ протокол (не запрошенный):
                    // сервер мог согласовать вниз (просили bittorrent — получил
                    // wireguard), тогда ссылка и весь UI обязаны показывать
                    // фактический протокол — канон единого источника правды.
                    val agreed = client.negotiatedProto
                    commitProto(if (isAuto) "" else agreed, cfg, primarySess)
                    if (!isAuto && agreed != commitProtoId) {
                        TunnelService.pushLog(
                            getString(R.string.log_proto_agreed, RrpProtocols.labelWithVer(agreed), RrpProtocols.labelWithVer(commitProtoId)),
                            LogKind.INFO,
                        )
                    }
                    updateStatus(TunnelService.STATE_CONNECTED, getString(R.string.status_switch_done, protoDisplayName(agreed)))
                    try { client.close() } catch (_: Exception) {}
                    primarySess?.let { spawnRunnersFor(it) }
                    return
                } catch (e: Exception) {
                    lastErr = e.message ?: "?"
                    TunnelService.pushLog(getString(R.string.log_proto_attempt, attempt, TunnelService.SWITCH_RETRIES, lastErr))
                    updateStatus(TunnelService.STATE_ERROR, getString(R.string.status_switch_fail, protoDisplayName(newProto), lastErr))
                } finally {
                    try { client.close() } catch (_: Exception) {}
                }
                if (attempt < TunnelService.SWITCH_RETRIES) {
                    try { Thread.sleep(TunnelService.SWITCH_RETRY_PAUSE_MS) } catch (_: InterruptedException) { break }
                }
            }
            // откат: UI вернёт выбор на старый протокол сразу, не дожидаясь реконнекта
            TunnelService.nextSwitchAllowedAt = System.currentTimeMillis() + TunnelService.SWITCH_COOLDOWN_MS
            updateStatus(TunnelService.STATE_ERROR, getString(R.string.status_switch_rolled_back, protoDisplayName(newProto), RrpProtocols.labelWithVer(oldProto), lastErr))
            sendBroadcast(
                Intent(TunnelService.ACTION_STATUS).setPackage(packageName)
                    .putExtra(TunnelService.EXTRA_STATE, TunnelService.STATE_PROTO_ROLLBACK)
                    .putExtra(TunnelService.EXTRA_STATUS, getString(R.string.status_switch_rolled_back, newProto, oldProto, lastErr))
                    .putExtra(TunnelService.EXTRA_PROTO, oldProto)
            )
            // v0.9.2 (R1): откат — рабочие коннекты старого протокола возрождаются
            if (!stopping) primarySess?.let { spawnRunnersFor(it) }
        } finally {
            switchingProto = false
            switchingSessionId = null
        }
    }

    /**
     * Коммит ПОСЛЕ успешной валидации: протокол отражается в ссылке
     * (v0.9.2: единый источник — ссылка, KEY_PROTO больше не пишется).
     */
    /**
     * Коммит ПОСЛЕ успешной валидации: протокол отражается в URI профиля
     * (v1.5.0: профиль — источник правды; зеркало TunnelService.KEY_CONFIG — для PRIMARY).
     */
    internal fun TunnelService.commitProto(proto: String, cfg: RrpUriConfig, sess: TunnelService.Sess?) {
        val updated = cfg.copy(proto = proto).serialize()
        if (sess != null) {
            sessionStore.update(sess.profile.copy(uri = updated))
            if (sess.id == sessionStore.activeId()) {
                prefs().edit().putString(TunnelService.KEY_CONFIG, updated).apply()
            }
        } else {
            prefs().edit().putString(TunnelService.KEY_CONFIG, updated).apply()
        }
        TunnelService.pushLog(getString(R.string.log_proto_applied, proto))
        syncProtoState()
    }

    internal fun TunnelService.applyCamouflage(enabled: Boolean, done: (String) -> Unit) {
        prefs().edit().putBoolean(TunnelService.KEY_CAMO_OFF, !enabled).apply()
        val label = RrpProtocols.camouflageLabel()
        val what = getString(if (enabled) R.string.modules_camo_on else R.string.modules_camo_off, label)
        TunnelService.pushLog(what, if (enabled) LogKind.INFO else LogKind.WARN)
        var sent = false
        synchronized(runners) {
            runners.forEach { r ->
                val c = r.client
                if (c != null && c.state == RrpClient.State.READY) {
                    try {
                        c.sendCamCtl(enabled)
                        sent = true
                    } catch (_: Exception) {
                    }
                }
            }
        }
        done(if (sent) getString(R.string.modules_camo_applied) else getString(R.string.modules_camo_deferred))
    }

    /**
     * v1.5.0: команды дашборда по сессии: connect/disconnect/reconnect/probe/
     * primary. Изолированно — затрагивается только одна сессия.
     */
    internal fun TunnelService.handleSessionCommand(id: String, cmd: String) {
        val profile = profileById(id) ?: return
        val mgr = manager
        when (cmd) {
            "connect" -> {
                if (mgr == null || !sessById.containsKey(id)) {
                    if (mgr != null && mgr.count() >= ConnectionManager.MAX_SESSIONS) {
                        TunnelService.pushLog(getString(R.string.dash_sessions_limit, ConnectionManager.MAX_SESSIONS), LogKind.WARN)
                        return
                    }
                    sessionStore.setEnabled(id, true)
                    if (mgr != null) mgr.start(sessionStore.byId(id) ?: return)
                    else startTunnel()
                }
            }
            "disconnect" -> {
                sessionStore.setEnabled(id, false)
                mgr?.stop(id)
                sessById.remove(id)
            }
            "reconnect" -> {
                sessionStore.setEnabled(id, true)
                mgr?.stop(id)
                sessById.remove(id)
                if (mgr == null) startTunnel() else mgr.start(sessionStore.byId(id) ?: return)
            }
            "probe" -> probeProfile(sessionStore.byId(id) ?: return)
            "primary" -> {
                sessionStore.setActive(id)
                TunnelService.pushLog(getString(R.string.sess_primary_set, profile.name), LogKind.WARN)
                sendBroadcast(
                    Intent(TunnelService.ACTION_STATUS).setPackage(packageName)
                        .putExtra(TunnelService.EXTRA_STATE, TunnelService.STATE_INFO)
                        .putExtra(TunnelService.EXTRA_STATUS, getString(R.string.sess_primary_set, profile.name))
                        .putExtra(TunnelService.EXTRA_SESSION_ID, id)
                        .putExtra(TunnelService.EXTRA_PROFILE_NAME, profile.name),
                )
            }
        }
    }

    /** Валидационный прогон профиля (TCP+TLS+пин+HELLO+PROBE) без подъёма сессии. */
    internal fun TunnelService.probeProfile(profile: SessionStore.Profile) {
        val cfg = try {
            RrpUri.parse(profile.uri)
        } catch (e: Exception) {
            TunnelService.pushLog("[${profile.name}] ${e.message}", LogKind.ERROR)
            return
        }
        TunnelService.pushLog("[${profile.name}] ${getString(R.string.log_probe_running)}")
        val client = buildClient(cfg, RrpProtocols.PREFERRED_AUTO, validate = true)
        try {
            client.connect()
            TunnelService.pushLog("[${profile.name}] ${getString(R.string.log_probe_ok)}", LogKind.OK)
        } catch (e: Exception) {
            TunnelService.pushLog("[${profile.name}] ${e.message}", LogKind.ERROR)
        } finally {
            try { client.close() } catch (_: Exception) {}
        }
    }

