// v1.9.0: зона «конфиг/фабрика клиента» вынесена из TunnelService.kt (транш-2):
// резолв ссылки (proto/claimed/current/зеркало+профиль), коммит PRIMARY-URI,
// сборка RrpClient (валидационный и боевой), политика шума/камуфляжа, версия.
// Pure refactor: private → internal у задетых членов, поведение не меняется.
package dev.stelgen.reverseray.service

import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.Apimask
import dev.stelgen.reverseray.core.ConfigResult
import dev.stelgen.reverseray.core.ConfigSource
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.RrpUriConfig
import dev.stelgen.reverseray.core.SessionStore

// ------------------------------------------------------------------ конфиг (резолв/коммит) и фабрика клиента

    /**
     * v0.9.2 (R2): ЕДИНЫЙ источник правды протокола — ССЫЛКА (proto=).
     * Раньше протокол читался из отдельного KEY_PROTO, который перекрывал
     * вставленную ссылку: после смены протокола новая ссылка с proto=rrp1
     * продолжала подключаться mtproto2. Теперь proto всегда из ссылки;
     * KEY_PROTO выведен из употребления (не читается).
     */
    /** Протокол ИЗ URI профиля (исполняемая нормализация) — v1.5.0. */
    internal fun TunnelService.protoOf(uri: String): String = try {
        RrpProtocols.normalizeExecutable(RrpUri.parse(uri).proto)
    } catch (_: Exception) {
        RrpProtocols.PREFERRED_AUTO
    }

    /** Заявленный протокол ИЗ URI профиля ("" = AUTO) — v1.5.0. */
    internal fun TunnelService.claimedOf(uri: String): String = try {
        RrpUri.parse(uri).proto.trim()
    } catch (_: Exception) {
        ""
    }

    internal fun TunnelService.currentProto(): String {
        val cfg = try {
            RrpUri.parse(prefs().getString(TunnelService.KEY_CONFIG, null) ?: "")
        } catch (_: Exception) {
            null
        }
        return RrpProtocols.normalizeExecutable(cfg?.proto)
    }

    /**
     * Заявленный (отображаемый) протокол из ссылки: новый протокол модуля
     * честно виден в GUI, даже если эта сборка ещё не умеет его исполнять
     * (тогда коннект идёт на rrp1 — см. RrpProtocols.normalizeExecutable).
     */
    internal fun TunnelService.claimedProto(): String {
        val cfg = try {
            RrpUri.parse(prefs().getString(TunnelService.KEY_CONFIG, null) ?: "")
        } catch (_: Exception) {
            null
        }
        // v0.9.5: возвращаем КАК В ССЫЛКЕ ("" = AUTO) — GUI честно показывает
        // режим AUTO, warning «не исполняется» только для явных протоколов.
        return cfg?.proto?.trim() ?: ""
    }

    /**
     * v1.8.4: ЕДИНЫЙ резолв конфига сервиса (активный PRIMARY-профиль →
     * зеркало TunnelService.KEY_CONFIG) + self-heal зеркала каноном. Раньше switchProtocol
     * читал только зеркало — после добавления сервера (профиль есть, зеркало
     * пусто) смены протокола отвечали «Нет конфига», хотя ссылка валидна.
     */
    internal fun TunnelService.resolvedConfig(): ConfigResult {
        ensureStore()
        val fromProfile = try { sessionStore.active()?.uri } catch (_: Exception) { null }
        val fromMirror = prefs().getString(TunnelService.KEY_CONFIG, null)
        val res = ConfigSource.firstValid(fromProfile, fromMirror)
        val canon = (res as? ConfigResult.Valid)?.canonical
        if (canon != null && canon != fromMirror) {
            prefs().edit().putString(TunnelService.KEY_CONFIG, canon).apply()
            syncProtoState()
        }
        return res
    }

    /**
     * Обновить URI PRIMARY-профиля + зеркало TunnelService.KEY_CONFIG (единая точка для
     * всех legacy-писателей конфига: accept-pin, вставка ссылки в UI).
     */
    internal fun TunnelService.commitPrimaryUri(canonical: String) {
        ensureStore()
        prefs().edit().putString(TunnelService.KEY_CONFIG, canonical).apply()
        syncProtoState()
        val active = sessionStore.active() ?: return
        sessionStore.update(active.copy(uri = canonical))
    }

    /** Перезапуск рабочих коннектов с новым протоколом (без смены статуса). */
    internal fun TunnelService.buildClient(cfg: RrpUriConfig, proto: String, validate: Boolean): RrpClient {
        // v1.0.0: гейт UDP-релея — единая точка для боевого и валидационного клиентов
        val client = RrpClient(
            host = cfg.host,
            port = cfg.ports.firstOrNull() ?: 4433,
            token = cfg.token,
            pin = cfg.pin,
            allowLan = allowLan(),
            listener = clientListener,
            deviceName = cfg.name?.takeIf { it.isNotBlank() } ?: "phone-1",
            transport = cfg.transport,
            agentName = "ReverseRay-Android/" + appVersion(),
            noisePolicy = buildNoisePolicy(),
            protoId = proto,
            validateProbeTarget = if (validate) prefs().getString(TunnelService.KEY_PROBE_TARGET, TunnelService.DEFAULT_PROBE_TARGET) else null,
            initialCamCtl = camCtlFlag(),
        )
        client.udpEnabled = prefs().getBoolean(TunnelService.KEY_UDP_ENABLED, true)
        return client
    }

    /**
     * v0.8.2: политика шума камуфляжа «API Mask» из ОБЩЕГО манифеста
     * (включён манифестом + подтверждён сервером в READY). Шаблоны строк
     * лога — на языке приложения (ресурсы), честно: сколько байт, бюджет.
     */
    internal fun TunnelService.buildNoisePolicy(): Apimask.NoisePolicy? {
        // v1.7.0 КАНОН: API Mask — ТОЛЬКО протокол (proto=apimask), не модуль.
        // Шум живёт исключительно в сессиях, согласованных как apimask;
        // модульная секция манифеста больше не управляет шумом.
        if (claimedProto() != Apimask.FEATURE) return null
        val cfg = RrpProtocols.camouflageConfig().takeIf { it.enabled } ?: Apimask.Config(
            Apimask.FEATURE, "API Mask", "1", true, 300, 900, 256 * 1024,
        )
        val engine = Apimask.Engine(cfg)
        val label = RrpProtocols.camouflageLabel()
        return Apimask.NoisePolicy(engine) { bytes, used, budget ->
            if (bytes > 0) {
                getString(R.string.apimask_beat, label, bytes, fmtBytes(used), fmtBytes(budget.toLong()))
            } else {
                getString(R.string.apimask_budget_done, label, fmtBytes(used), fmtBytes(budget.toLong()))
            }
        }
    }

    /**
     * v0.9.5: начальный кадр 0x2A при подключении: отправляем ТОЛЬКО когда
     * локальный выбор существует (contains). Выбор персистентен на сервере:
     * переживает офлайн клиента, применяется будущим сессиям.
     */
    internal fun TunnelService.camCtlFlag(): Boolean? =
        // v1.7.0: 0x2A — только для proto=apimask (включить серверный шум).
        if (claimedProto() == Apimask.FEATURE) true else null

    /** v1.6.0: дефолтная политика шума для proto=apimask (без манифеста). */
    /**
     * Управление камуфляжем из GUI (v0.9.5): сохранить выбор + честный лог +
     * немедленный кадр 0x2A живой сессии (если есть); иначе применится при
     * следующем подключении. GUI показывает итог тостом.
     */
    internal fun TunnelService.appVersion(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
    } catch (_: Exception) {
        "?"
    }

