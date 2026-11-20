package dev.stelgen.reverseray.core

/**
 * Умный балансер протоколов auto-режима (v0.10).
 *
 * Сигнал деградации — скользящее окно пробников (PING-потери, RTT EWMA,
 * PROBE-провалы). Решение о смене принимается ТОЛЬКО при совокупности
 * условий — канон анти-мигания (пользователь: «не скакать каждые 100 мс
 * или каждые 5 секунд»):
 *
 *  - **Гистерезис деградации**: связь обязана быть плохой ПОДРЯД не меньше
 *    [Cfg.degradeWindowMs] и не меньше [Cfg.minSamples] проб;
 *  - **Стабилизация после смены**: [Cfg.stabilityWindowMs] «отработки» —
 *    новые смены не производятся (кроме полного обрыва);
 *  - **Кулдаун**: смена не чаще [Cfg.minSwitchIntervalMs]; каждая неудачная
 *    смена удваивает кулдаун до [Cfg.maxCooldownMs] (экспоненциальный backoff);
 *  - **Память провалов**: протокол, провалившийся на этой связи, остывает
 *    [Cfg.failCooldownMs] и не выбирается round-robin'ом;
 *  - **Round-robin**: кандидаты = executable ∩ реестр сервера, начиная
 *    СЛЕДУЮЩЕГО после текущего («по очереди»).
 *
 * Чистая логика без Android — решение по снимкам проб (тестируется юнит-ами,
 * A/B в TunnelService): планировщик кормит [onSample], сервис исполняет свитч.
 *
 * v1.8.0: снимок может нести исход end-to-end пробника полезной нагрузки
 * ([Sample.e2e], сквозной путь OPEN→DATA→ответ): ReadTimeout/Rst — мёртвый
 * путь, кормится как deadLoss (смена вне гистерезиса, кулдаун уважается);
 * Throttle — деградация через обычный гистерезис; Ok — не мешает.
 *
 * v1.8.10 (анти-молотьба): мёртвый/троттлинг-вердикт пробника — СВИДЕТЕЛЬСТВО
 * со сроком годности. После смены конверта клиент обнуляет последний исход
 * (RrpClient.unparkAndFlush), а вердикт старше [Cfg.deadFreshMs] секунд не
 * считается мёртвым путём: он уже не про текущий конверт. Иначе один
 * просроченный dead-сэмпл (E2E_STALE_MS = 3 мин) гнал свитчи каждые ~30 с
 * без свежих доказательств — «деградация подключения» на реальных сетях.
 */
class AutoBalancer(private val cfg: Cfg = Cfg()) {

    /** Параметры гистерезиса/кулдаунов (инъекция для тестов). */
    data class Cfg(
        /** Порог потерь (доля unanswered ping) в окне. */
        val lossThreshold: Double = 0.15,
        /** Порог RTT EWMA, мс. */
        val rttThresholdMs: Long = 1500,
        /** Сколько мс связь обязана быть плохой ПОДРЯД. */
        val degradeWindowMs: Long = 10_000,
        /** Минимум проб в деградационном окне (анти-шум). */
        val minSamples: Int = 3,
        /** «Отработка» после смены, мс. */
        val stabilityWindowMs: Long = 30_000,
        /** Базовый кулдаун смены, мс. */
        val minSwitchIntervalMs: Long = 30_000,
        /** Потолок кулдауна (экспоненциальный рост), мс. */
        val maxCooldownMs: Long = 600_000,
        /** Память провала протокола, мс. */
        val failCooldownMs: Long = 300_000,
        /** Доля потерь, считающаяся полным обрывом (смена вне гистерезиса). */
        val deadLoss: Double = 0.9,
        /** v1.8.10: срок годности dead/throttle-вердикта E2E-пробника, мс.
         * Вердикт старше — не свидетельство о текущем конверте (анти-молотьба). */
        val deadFreshMs: Long = 90_000,
    )

    /** Снимок качества из пробника. */
    data class Sample(
        val atMs: Long,
        /** RTT EWMA пробника (мс; null — ещё нет данных). */
        val rttMs: Long?,
        /** Потери в окне пробника (0..1). */
        val lossRatio: Double,
        /** Последний PROBE (null — ещё не было). */
        val probeOk: Boolean?,
        /** v1.8.0: исход E2E-пробника полезной нагрузки (null — нет данных/старый детект). */
        val e2e: E2eProbe.Outcome? = null,
        /** v1.8.10: момент пробы e2e (epoch мс); null — без таймстампа
         * (старые фикстуры/старый клиент: свежесть не проверяем — прежнее
         * поведение, A/B-совместимость). */
        val e2eAtMs: Long? = null,
    )

    /** Решение балансера. */
    sealed class Decision {
        /** Ничего не делать. */
        object Nothing : Decision()

        /** Сменить протокол на target (reason — строка лога). */
        data class Switch(val target: String, val reason: String) : Decision()

        /** Деградация есть, но гистерезис/кулдаун молчат (reason для DEBUG-лога). */
        data class Wait(val reason: String) : Decision()
    }

    private class SamplePoint(val s: Sample, val bad: Boolean)

    private val points = ArrayDeque<SamplePoint>()
    /** Протоколы-кандидаты (порядок round-robin); задаётся сервисом. */
    @Volatile var candidates: List<String> = emptyList()

    /** Текущий протокол (кто виноват — тот и сменится первым). */
    @Volatile var current: String = RrpProtocols.PREFERRED_AUTO

    // состояние анти-мигания
    private var lastSwitchAtMs = 0L
    private var hasSwitched = false
    private var stabilityUntilMs = 0L
    private var cooldownPenaltyMs = 0L
    private val failUntil = HashMap<String, Long>()

    /** Приземление с пробника: rtt/loss/probe за тик. Возвращает решение. */
    @Synchronized
    fun onSample(s: Sample): Decision {
        val bad = isBad(s)
        points.addLast(SamplePoint(s, bad))
        val horizon = s.atMs - cfg.degradeWindowMs
        while (points.isNotEmpty() && points.first().s.atMs < horizon) points.removeFirst()
        // v1.8.0: мёртвый E2E-пробник (payload режется) = полный обрыв —
        // смена вне гистерезиса, кулдаун уважается (анти-молотьба).
        // v1.8.10: verdict живёт не дольше deadFreshMs с момента пробы —
        // просроченный dead не гонит свитчи без свежих доказательств.
        val dead = s.lossRatio >= cfg.deadLoss || (s.e2e?.isDead == true && e2eUsable(s))
        if (!bad && !dead) return Decision.Nothing
        val sinceSwitch = s.atMs - lastSwitchAtMs
        // Стабилизация после смены (гистерезис): полный обрыв НЕ ждёт
        // «отработку», но кулдаун уважают ВСЕ сигналы (анти-молотьба).
        if (!dead && s.atMs < stabilityUntilMs) {
            return Decision.Wait("stability window: ${(stabilityUntilMs - s.atMs) / 1000}s")
        }
        if (hasSwitched && sinceSwitch < cfg.minSwitchIntervalMs + cooldownPenaltyMs) {
            return Decision.Wait("cooldown: ${(cfg.minSwitchIntervalMs + cooldownPenaltyMs - sinceSwitch) / 1000}s")
        }
        if (!dead) {
            // деградация обязана держаться всё окно подряд (гистерезис)
            val window = points.filter { it.s.atMs >= s.atMs - cfg.degradeWindowMs }
            if (window.size < cfg.minSamples || window.any { !it.bad }) {
                return Decision.Wait("degradation not sustained (${window.size} samples)")
            }
        }
        val target = nextCandidate(s.atMs) ?: return Decision.Wait("no other candidate")
        return Decision.Switch(target, "loss=%.0f%% rtt=${s.rttMs ?: "?"}ms probe=${s.probeOk ?: "?"} e2e=${s.e2e ?: "-"}")
    }

    /** Результат смены: успех сбрасывает пенальти, провал — растит кулдаун. */
    @Synchronized
    fun onSwitchResult(atMs: Long, target: String, ok: Boolean) {
        lastSwitchAtMs = atMs
        hasSwitched = true
        if (ok) {
            cooldownPenaltyMs = 0
            points.clear() // новая связь — новое окно (гистерезис с чистого листа)
            stabilityUntilMs = atMs + cfg.stabilityWindowMs
            current = target
        } else {
            cooldownPenaltyMs = minOf(cfg.maxCooldownMs, maxOf(cfg.minSwitchIntervalMs, cooldownPenaltyMs * 2))
            failUntil[target] = atMs + cfg.failCooldownMs
        }
    }

    /** Ручное включение auto (сброс состояния, без пенальти). */
    @Synchronized
    fun reset(atMs: Long) {
        points.clear()
        cooldownPenaltyMs = 0
        failUntil.clear()
        stabilityUntilMs = atMs
        lastSwitchAtMs = 0
        hasSwitched = false
    }

    private fun isBad(s: Sample): Boolean {
        val loss = s.lossRatio >= cfg.lossThreshold
        val rtt = (s.rttMs ?: 0) >= cfg.rttThresholdMs
        val probe = s.probeOk == false
        // v1.8.0: резкое падение сквозной скорости — деградация (гистерезис)
        // v1.8.10: throttle-вердикт тоже со сроком годности (см. deadFreshMs)
        val throttle = s.e2e is E2eProbe.Outcome.Throttle && e2eUsable(s)
        return loss || rtt || probe || throttle
    }

    /** v1.8.10: вердикт e2e применим как свидетельство о ТЕКУЩЕМ конверте?
     * Без таймстампа (старый формат Sample) — применим всегда (совместимость). */
    private fun e2eUsable(s: Sample): Boolean =
        s.e2eAtMs == null || s.atMs - s.e2eAtMs <= cfg.deadFreshMs

    /** Следующий кандидат round-robin: после current, без остывающих. */
    private fun nextCandidate(atMs: Long): String? {
        if (candidates.size < 2) return null
        val idx = candidates.indexOf(current)
        for (i in 1..candidates.size) {
            val c = candidates[(idx + i).mod(candidates.size)]
            if (c == current) continue
            val until = failUntil[c]
            if (until == null || atMs >= until) return c
        }
        // все кандидаты остывают — вернуть самого «старого» по остыванию
        val best = candidates.filter { it != current }.minByOrNull { failUntil[it] ?: 0L }
        return best?.takeIf { (failUntil[it] ?: 0L) <= atMs + 60_000 } // не молотим: ждём
    }

    /** Для UI: остаток кулдауна свитча, сек (0 — можно менять). */
    @Synchronized
    fun cooldownLeftSec(atMs: Long): Long {
        val left = cfg.minSwitchIntervalMs + cooldownPenaltyMs - (atMs - lastSwitchAtMs)
        return if (left <= 0) 0 else left / 1000
    }
}
