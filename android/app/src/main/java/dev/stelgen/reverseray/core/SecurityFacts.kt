package dev.stelgen.reverseray.core

/**
 * v0.8.1: Особенные константы/переменные защиты — единая точка правды для
 * вкладки «О приложении» (канон «ничего не прячем»: пользователь видит,
 * ЧЕМ именно защищён его трафик). Все значения — публичные, секретов здесь нет.
 */
object SecurityFacts {

    // ---------- транспорт/туннель ----------
    val TLS_MIN_VERSION = Msgs.SF_TLS_MIN.t()
    const val ALPN = "reverseray/1"
    val TLS_PROVIDER = Msgs.SF_TLS_LIB.t()
    val CERT_MODEL = Msgs.SF_PKI.t()
    val PIN_POLICY = Msgs.SF_PIN.t()
    val ZERO_RTT = Msgs.SF_NO_0RTT.t()

    // ---------- хендшейк/аутентификация ----------
    val TOKEN_STORAGE = Msgs.SF_TOKEN_HASH.t()
    val HANDSHAKE = Msgs.SF_HMAC.t()
    val NONCE = Msgs.SF_NONCE.t()
    val RATE_LIMIT = Msgs.SF_LOCKOUT.t()

    // ---------- payload/крипто (mtproto2) ----------
    val MTPROTO2 = Msgs.SF_MTPROTO.t()
    val FRAME_LIMITS = Msgs.SF_LIMITS.t()

    // ---------- WAN/анти-скан ----------
    val WAN_HARDENING = Msgs.SF_HARDENING.t()
    val SSRF_GUARD = Msgs.SF_SSRF.t()

    // ---------- обновления/целостность ----------
    val MODULES_MANIFEST = Msgs.SF_MANIFEST.t()
    val APK_INTEGRITY = Msgs.SF_UPDATES.t()

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
