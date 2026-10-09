package dev.stelgen.reverseray.core

import java.security.MessageDigest
import java.util.Base64

/**
 * v0.9.0: КАНОН СПКИ-ПИНА — ОДИН ДЛЯ ВСЕХ СТОРОН.
 *
 * Пин = SHA256(SPKI ПОСЛЕДНЕГО сертификата цепочки (CA)):
 *  - сервер: enroll/Go (tlscert.SPKIPin) печатают пин CA;
 *  - клиент: notifyServerCertificate хеширует chain.last() (до 0.9.0 был баг:
 *    хешировался ЛИСТ chain[0] — лист ротируется «заранее», CA не меняется,
 *    поэтому честные ссылки ломались ложным «pin mismatch» на проде);
 *  - формат пина в ссылке — base64url БЕЗ паддинга (RawURL) — тот же, что
 *    печатает enroll; hex (64 симв.) тоже принимается для совместимости.
 *
 * KAT-тест: RrpPinTest (цепочка leaf+CA → берётся CA).
 */
object RrpPin {

    /** SHA256(SPKI) последнего сертификата цепочки [der-сертификаты лист→…→CA]. */
    fun caSha256(chainDer: List<ByteArray>): ByteArray {
        require(chainDer.isNotEmpty()) { "empty certificate chain" }
        // BouncyCastle уже в ядре (RrpClient/TLS): ASN.1-разбор доверяем ему.
        val last = org.bouncycastle.asn1.x509.Certificate.getInstance(chainDer.last())
        val spki = last.subjectPublicKeyInfo.encoded
        return MessageDigest.getInstance("SHA-256").digest(spki)
    }

    /** Пин → формат ссылки: base64url без паддинга (как печатает enroll). */
    fun toLinkPin(sha256Bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(sha256Bytes)

    /**
     * Пин из ссылки → 32 байта: hex (64 симв.) или base64 (std/url, с/без
     * паддинга). Мусор → null (никогда не бросаем).
     */
    fun fromLinkPin(raw: String?): ByteArray? {
        val s = raw?.trim() ?: return null
        if (s.length == 64 && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
            return runCatching { hexToBytes(s) }.getOrNull()
        }
        val normalized = s.replace('-', '+').replace('_', '/')
            .removeSuffix("=").let { it + "=".repeat((4 - it.length % 4) % 4) }
        return runCatching {
            Base64.getDecoder().decode(normalized)
        }.getOrNull()?.takeIf { it.size == 32 }
    }

    private fun hexToBytes(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(s[2 * i], 16) shl 4) + Character.digit(s[2 * i + 1], 16)).toByte()
        }
        return out
    }
}