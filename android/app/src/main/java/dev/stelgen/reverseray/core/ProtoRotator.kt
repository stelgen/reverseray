package dev.stelgen.reverseray.core

/**
 * v1.8.0: режим «Ротация» — автосмена протоколов строго по расписанию.
 *
 * Каждые [intervalMs] (канон — 30 минут) протокол меняется на СЛЕДУЮЩИЙ
 * по порядку round-robin по кандидатам (executable ∩ реестру сервера),
 * начиная со следующего после текущего. АЛЬТЕРНАТИВА auto-режиму
 * ([AutoBalancer]): режимы выбора взаимоисключающие — ротация не смотрит
 * на качество связи, авто не смотрит на расписание. Причины переключений
 * в журнал пишет исполнитель (TunnelService.pushLog).
 *
 * Чистая логика без Android/сети — юнит-тесты на расписание/порядок;
 * исполнение (тик, бесшовная смена 0x2C) — в TunnelService.
 */
class ProtoRotator(internal val intervalMs: Long = DEFAULT_INTERVAL_MS) {

    companion object {
        /** Канон режима: смена каждые 30 минут. */
        const val DEFAULT_INTERVAL_MS = 30 * 60 * 1000L
    }

    /** Якорь расписания (мс; 0 — ещё не заякорен). */
    @Volatile private var lastSwitchAtMs = 0L

    /**
     * Тик ротатора. Возвращает целевой протокол или null (рано — расписание,
     * или кандидатов меньше двух — менять не на кого). Первый тик только
     * ЯКОРИТ расписание: включение режима ≠ немедленная смена.
     * Порядок строгий: без пропусков и без памяти провалов (это не авто).
     */
    @Synchronized
    fun onTick(atMs: Long, current: String, candidates: List<String>): String? {
        if (candidates.size < 2) return null
        if (lastSwitchAtMs == 0L) {
            lastSwitchAtMs = atMs
            return null
        }
        if (atMs - lastSwitchAtMs < intervalMs) return null
        // строго следующий после текущего; current вне кандидатов → первый
        val idx = candidates.indexOf(current)
        lastSwitchAtMs = atMs
        return candidates[(idx + 1).mod(candidates.size)]
    }

    /** Сброс расписания (повторное включение режима). */
    @Synchronized
    fun reset() {
        lastSwitchAtMs = 0
    }
}
