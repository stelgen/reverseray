package dev.stelgen.reverseray.core

/**
 * v0.8.1: Особенные константы/переменные защиты — единая точка правды для
 * вкладки «О приложении» (канон «ничего не прячем»: пользователь видит,
 * ЧЕМ именно защищён его трафик). Все значения — публичные, секретов здесь нет.
 */
object SecurityFacts {

    // ---------- транспорт/туннель ----------
    const val TLS_MIN_VERSION = "TLS 1.3 (минимум; TLS 1.2 разрешён только в compat-профиле)"
    const val ALPN = "reverseray/1"
    const val TLS_PROVIDER = "BouncyCastle BcTlsCrypto (lightweight, без платформенного JCA)"
    const val CERT_MODEL = "self-signed CA (10 лет) → лист 3 года; пин = SHA256(SPKI CA)"
    const val PIN_POLICY = "строгий: пин задан и не совпал → соединение отклоняется (анти-MITM); TOFU только для первой дружбы (пина нет)"
    const val ZERO_RTT = "0-RTT/early data не используется; resumption не пропускает AUTH"

    // ---------- хендшейк/аутентификация ----------
    const val TOKEN_STORAGE = "сервер хранит только SHA256(token); токен никогда не покидает устройство"
    const val HANDSHAKE = "HMAC-SHA256(key=SHA256(token), msg=nonce‖session_id), сравнение constant-time"
    const val NONCE = "одноразовый 128-бит nonce (crypto/rand), TTL 60 с, replay → отказ"
    const val RATE_LIMIT = "≤120 рукопожатий/мин/IP; lockout только за невалидный HMAC: 5 неудач → 30с·2^n (до 10 мин)"

    // ---------- payload/крипто (mtproto2) ----------
    const val MTPROTO2 = "MTProto 2.0: DH-2048 на официальном dh_prime Telegram (safe prime, anti-logjam), AES-256-IGE, msg_key SHA-256"
    const val FRAME_LIMITS = "DATA ≤ 65535 Б; прочие кадры ≤ 4096 Б; окно стрима 512 КБ→4 МБ; бюджет сессии 16 МБ"

    // ---------- WAN/анти-скан ----------
    const val WAN_HARDENING = "первый байт ≠ TLS → tarpit + тишина (0 байт ответа); глобальный + per-IP лимиты параллельности"
    const val SSRF_GUARD = "блэклист приватных диапазонов на клиенте (DNS-rebinding защищён пострезолвной проверкой адресов)"

    // ---------- обновления/целостность ----------
    const val MODULES_MANIFEST = "манифест modules.json: schema-чек, семвер, sha256, даунгрейд запрещён, мусор не применяется"
    const val APK_INTEGRITY = "релиз подписан v1+v2+v3; SHA256SUMS релиза сверяется перед установкой APK"

    /** Все константы списком для «О приложении» (мэппинг заголовков — в UI-слое,
     *  core остаётся чистым Kotlin без android.*). */
    fun values(): List<String> = listOf(
        TLS_MIN_VERSION,
        ALPN,
        TLS_PROVIDER,
        CERT_MODEL,
        PIN_POLICY,
        ZERO_RTT,
        TOKEN_STORAGE,
        HANDSHAKE,
        NONCE,
        RATE_LIMIT,
        MTPROTO2,
        FRAME_LIMITS,
        WAN_HARDENING,
        SSRF_GUARD,
        MODULES_MANIFEST,
        APK_INTEGRITY,
    )
}
