// v1.9.0: зона «раннеры/спавн/run-loop» вынесена из TunnelService.kt
// (дробление по зонам ответственности, транш-2). Pure refactor:
// private → internal у задетых членов, поведение не меняется.
// Тот же пакет — extension-функции сервиса, вызовы из TunnelService,
// SessionWorker и sessionOwner без импортов.
package dev.stelgen.reverseray.service

import android.content.Intent
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.ConnectionManager
import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.Negotiation
import dev.stelgen.reverseray.core.ProtoFallback
import dev.stelgen.reverseray.core.RrpAuthException
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.SessionStore

// ------------------------------------------------------------------ раннеры (по одному на порт), спавн, run-loop

    /** Первый живой клиент сессии (для healthSample/proto снапшотов). */
    internal fun TunnelService.firstClientOf(sess: TunnelService.Sess): RrpClient? =
        synchronized(runners) { runners.firstOrNull { it.sess === sess }?.client }

    internal fun TunnelService.runnersOf(sess: TunnelService.Sess): List<TunnelService.Runner> =
        synchronized(runners) { runners.filter { it.sess === sess } }

    internal fun TunnelService.killRunnersOf(sess: TunnelService.Sess) {
        val active = synchronized(runners) {
            val list = runners.filter { it.sess === sess }
            runners.removeAll { it.sess === sess }
            list
        }
        active.forEach {
            it.kick = true
            it.retired = true
            try { it.client?.close() } catch (_: Exception) {}
        }
    }

    /** Старт одной сессии (изолированно: неудача не роняет другие). */
    internal fun TunnelService.startSession(p: SessionStore.Profile) {
        manager?.start(p)
    }

    /** Все сессии из реестра (для kickAll-поднятия после Wi-Fi). */
    internal fun TunnelService.startAllSessions() {
        for (p in sessionStore.profiles()) {
            if (p.enabled || p.id == sessionStore.activeId()) {
                if (sessById.containsKey(p.id)) continue
                if (sessById.size >= ConnectionManager.MAX_SESSIONS) break
                startSession(p)
            }
        }
    }

    /** Раннеры ОДНОЙ сессии (по портам профиля) — v1.5.0. */
    internal fun TunnelService.spawnRunnersFor(sess: TunnelService.Sess) {
        val cfg = try {
            RrpUri.parse(sess.profile.uri)
        } catch (_: Exception) {
            return
        }
        for (port in cfg.ports) {
            val r = this.Runner(TunnelService.Target(cfg.host, port))
            r.sess = sess
            synchronized(runners) { runners.add(r) }
            val stateKey = "${sess.id}|$port"
            Thread({
                runnerStateKey.set(stateKey)
                try {
                    runLoop(r)
                } finally {
                    sessionStates.remove(stateKey)
                }
            }, "rrp-conn-${sess.id.take(4)}-$port").start()
        }
    }

    internal fun TunnelService.runLoop(r: TunnelService.Runner) {
        var lastError = "?"
        // v0.8.1: подряд идущие неудачи на ТЕКУЩЕМ протоколе (для фоллбека)
        var failStreak = 0
        // v0.9.7: дедуп уведомления о согласовании — одна и та же пара
        // «просили → дали» не спамит при каждом реконнекте
        var lastNegotiationNotice: String? = null
        while (!stopping) {
            // v1.5.0: конфиг сессии — ИЗ ПРОФИЛЯ (не из зеркала TunnelService.KEY_CONFIG;
            // зеркало держим синхронным только для legacy-кода).
            val profile = r.sess?.profile ?: return
            val cfg = try {
                RrpUri.parse(profile.uri)
            } catch (_: Exception) {
                return
            }
            // v0.9.2 (R1): ГЕЙТ смены протокола — во время валидационного
            // provisional-коннекта СЕССИИ-СВИТЧА реконнект-луп не молотит свои
            // попытки (атомарность: kill → validate → commit → spawn);
            // другие сессии живут своей жизнью (изоляция v1.5.0).
            while (switchingProto && r.sess?.id == switchingSessionId && !stopping) {
                try { Thread.sleep(200) } catch (_: InterruptedException) { return }
            }
            if (stopping || r.retired) return
            // протокол перечитываем КАЖДУЮ итерацию: так подхватывается
            // и смена протокола, и фоллбек, и заморозка обновлений (без пересоздания)
            val useProto = protoOf(profile.uri)
            val claimed = claimedOf(profile.uri)
            // v0.9.2 (R9): честный лог — протокол заявлен модулем/ссылкой,
            // но эта сборка его ещё не исполняет → коннект на rrp1.
            if (claimed.isNotBlank() && claimed != useProto) {
                TunnelService.pushLog(
                    getString(R.string.log_proto_not_executable, RrpProtocols.labelWithVer(claimed), RrpProtocols.labelWithVer(useProto)),
                    LogKind.WARN,
                )
            }
            val client = RrpClient(
                host = r.target.host,
                port = r.target.port,
                token = cfg.token,
                pin = cfg.pin,
                allowLan = allowLan(),
                listener = clientListener,
                deviceName = (cfg.name?.takeIf { it.isNotBlank() } ?: profile.name).ifBlank { "phone-1" },
                transport = cfg.transport,
                agentName = "ReverseRay-Android/" + appVersion(),
                noisePolicy = buildNoisePolicy(),
                protoId = useProto,
                initialCamCtl = camCtlFlag(),
            )
            r.client = client
            try {
                client.connect()
                // v1.5.0: успех коннекта — сброс пер-сессионного backoff
                r.sess?.id?.let { manager?.workerConnected(it) }
                // v0.9.7 (канон «явные статусы согласования»): сервер ответил
                // ДРУГИМ протоколом, чем запрошен (AUTO-предпочтение или явный
                // proto=) — честный WARN вместо молчаливого даунгрейда.
                Negotiation.notice(useProto, client.negotiatedProto, claimed)?.let { notice ->
                    if (notice != lastNegotiationNotice) {
                        lastNegotiationNotice = notice
                        TunnelService.pushLog(notice, LogKind.WARN)
                    }
                }
                failStreak = 0
                updateStatus(TunnelService.STATE_CONNECTED, getString(R.string.status_connected, r.target.port))
                while (!stopping && !switchingProto && client.state == RrpClient.State.READY) {
                    try {
                        Thread.sleep(500)
                    } catch (_: InterruptedException) {
                        break
                    }
                }
            } catch (e: RrpAuthException) {
                // v0.9.4 КАНОН: auth failed — токен/ссылка устарели, это НЕ сетевой
                // сбой. Ретраи бессмысленны и зарабатывают IP-локаут на сервере
                // (5 неудач → клиент видит «TLS handshake_failure(40)» вместо
                // причины). Останавливаем авто-реконнект честным статусом;
                // обновление ссылки + кнопка Старт начинают новую серию.
                lastError = e.message ?: "?"
                TunnelService.pushLog(getString(R.string.status_auth_failed), LogKind.ERROR)
                updateStatus(TunnelService.STATE_ERROR, getString(R.string.status_auth_failed))
                r.client = null
                r.sess?.id?.let { manager?.workerFatal(it, getString(R.string.status_auth_failed)) }
                return
            } catch (e: Exception) {
                lastError = e.message ?: "?"
                failStreak++
                // v1.5.1 FIX: счётчик/backoff ведёт ТОЛЬКО workerFailed ниже
                // (после цикла) — двойной инкремент задваивал errors и
                // разгонял backoff вдвое быстрее (выглядело как «не подключается»).
                updateStatus(TunnelService.STATE_ERROR, getString(R.string.status_error, r.target.port, lastError))
                // v0.8.1 КАНОН ФОЛЛБЕКА: новый модуль протокола сломал клиент →
                // откатываемся на предыдущий рабочий (rrp1). Сервер НЕ откатываем
                // (анти-цикл: обновления рассинхронизированы, авто-обновление
                // может быть отключено — модули заморожены, это не должно ломать).
                // v0.9.2 (R1): во время смены протокола фоллбек не срабатывает —
                // откат сделает switchProtocol после валидации.
                if (r.sess?.id != switchingSessionId && ProtoFallback.shouldFallback(useProto, failStreak)) {
                    TunnelService.pushLog(ProtoFallback.fallbackReason(useProto), LogKind.WARN)
                    applyProtoFallback(r.sess, useProto)
                    return
                }
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
            r.client = null
            if (stopping || r.retired) return
            if (r.sess?.id == switchingSessionId) {
                // переход занят валидацией: попытка не считается, backoff сбросится
                failStreak = 0
                continue
            }
            // v1.5.0: пер-сессионный backoff ведёт ConnectionManager
            val delay = r.sess?.let { manager?.workerFailed(it.id, lastError) }
                ?: RrpClient.backoffDelayMs(0, rnd)
            // ERROR держится на экране минимум HOLD_ERROR_MS, чтобы юзер
            // успел прочитать причину, а не мигал «реконнект».
            try { Thread.sleep(TunnelService.ERROR_HOLD_MS) } catch (_: InterruptedException) {}
            if (stopping) break
            updateStatus(TunnelService.STATE_RETRY, getString(R.string.status_retry_last, r.target.port, delay / 1000, lastError))
            sleepWithKick(r, delay)
        }
    }

    /**
     * v0.8.1: клиентский фоллбек на фундамент (rrp1) — сохраняем протокол и
     * ссылку (proto= отражает реально работающий), перезапускаем коннекты.
     * UI получает TunnelService.STATE_PROTO_ROLLBACK и обновляет строку протокола.
     */
    /**
     * v0.8.1: клиентский фоллбек на фундамент (rrp1) — SCOPE ОДНОЙ СЕССИИ
     * (v1.5.0): протокол отражается в URI профиля (и в зеркале — если сессия
     * PRIMARY), перезапускаются только раннеры этой сессии.
     */
    internal fun TunnelService.applyProtoFallback(sess: TunnelService.Sess?, brokenProto: String) {
        // v0.9.2 (R2): протокол живёт только в ссылке
        try {
            val cfg = RrpUri.parse(sess?.profile?.uri ?: "")
            if (cfg.proto != RrpProtocols.DEFAULT) {
                val updated = cfg.copy(proto = RrpProtocols.DEFAULT).serialize()
                if (sess != null) {
                    sessionStore.update(sess.profile.copy(uri = updated))
                    if (sess.id == sessionStore.activeId()) {
                        prefs().edit().putString(TunnelService.KEY_CONFIG, updated).apply()
                        syncProtoState()
                    }
                }
            }
        } catch (_: Exception) {
        }
        syncProtoState()
        sendBroadcast(
            Intent(TunnelService.ACTION_STATUS).setPackage(packageName)
                .putExtra(TunnelService.EXTRA_STATE, TunnelService.STATE_PROTO_ROLLBACK)
                .putExtra(TunnelService.EXTRA_STATUS, ProtoFallback.fallbackReason(brokenProto))
                .putExtra(TunnelService.EXTRA_PROTO, RrpProtocols.DEFAULT)
        )
        if (!stopping && sess != null) {
            killRunnersOf(sess)
            spawnRunnersFor(sess)
        }
    }

    /** Сон с прерыванием по kick (мгновенный retry после появления сети). */
    internal fun TunnelService.sleepWithKick(r: TunnelService.Runner, ms: Long) {
        val deadline = System.currentTimeMillis() + ms
        while (!stopping) {
            if (r.kick) {
                r.kick = false
                return
            }
            val now = System.currentTimeMillis()
            if (now >= deadline) return
            try {
                Thread.sleep(minOf(250L, deadline - now))
            } catch (_: InterruptedException) {
                return
            }
        }
    }
