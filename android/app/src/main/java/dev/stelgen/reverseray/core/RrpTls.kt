// RrpTls.kt — зона «TLS (BC 1.80)»: сборка клиента TLS 1.3/1.2, пин SPKI-CA
// (v0.9.0 канон), TOFU-фиксация самоподписанной цепочки, запоминание срока
// действия серта. Pure move из RrpClient.kt (v1.8.3, дробление по зонам;
// поведение не меняется; члены private→internal — тот же пакет).
package dev.stelgen.reverseray.core

import java.security.MessageDigest
import java.util.Vector
import org.bouncycastle.tls.AlertDescription
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.ProtocolName
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsFatalAlert
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.crypto.TlsCrypto
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto

// ------------------------------------------------------------------ TLS (BC 1.80)

internal fun RrpClient.buildTlsClient(): DefaultTlsClient {
    RrpClient.ensureFullBouncyCastle()
    // BcTlsCrypto — лёгкий (lightweight) бэкенд без JCA: не зависит от
    // провайдера "BC" платформы (на Android он урезан; v0.5.1 не чинит
    // все устройства). Работает на всех Android начиная с API 14.
    val crypto: TlsCrypto = RrpClient.defaultCrypto()
    return object : DefaultTlsClient(crypto) {
        override fun getProtocolVersions(): Array<ProtocolVersion> =
            arrayOf(ProtocolVersion.TLSv13, ProtocolVersion.TLSv12)

        // Chacha20 в приоритете, далее AES-GCM
        override fun getCipherSuites(): IntArray = intArrayOf(
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        )

        // ALPN: BC 1.80 — клиент предлагает имена через getProtocolNames()
        override fun getProtocolNames(): Vector<ProtocolName> =
            Vector(listOf(ProtocolName.asUtf8Encoding(RrpClient.ALPN_PROTOCOL)))

        override fun getAuthentication(): TlsAuthentication = object : TlsAuthentication {
            override fun notifyServerCertificate(serverCertificate: TlsServerCertificate) {
                val chain = serverCertificate.certificate.certificateList
                if (chain.isEmpty()) throw TlsFatalAlert(AlertDescription.bad_certificate)
                // v0.9.0 КАНОН ПИНА: SHA256(SPKI ПОСЛЕДНЕГО серта цепочки (CA)).
                // До 0.9.0 хешировался ЛИСТ (chain[0]) — лист ротируется «заранее»,
                // CA не меняется: честные ссылки ломались ложным «pin mismatch»
                // на проде после перевыпуска листа (TLS bad_certificate(42)).
                val chainDer = chain.map { it.encoded }
                val actual = RrpPin.caSha256(chainDer)
                val actualB64 = RrpPin.toLinkPin(actual)

                // Строгий путь: пин из конфига совпал.
                if (pin != null) {
                    val expected = RrpPin.fromLinkPin(pin)
                    if (expected == null) {
                        log(Msgs.PIN_FORMAT.t())
                        throw TlsFatalAlert(AlertDescription.bad_certificate)
                    }
                    if (MessageDigest.isEqual(actual, expected)) {
                        acceptedPin = actualB64
                        rememberServerCert(chain)
                        return
                    }
                    // v0.8.1 КАНОН: пин задан и не совпал → ОТКАЗ. Это либо
                    // смена CA владельцем (нужен re-enroll), либо MITM —
                    // другим сертификатам мы НЕ доверяем никогда.
                    if (!trustSelfSigned) {
                        log(Msgs.TLS_PIN_MISMATCH.t(actualB64))
                        // v0.9.0: UI может предложить владельцу ЯВНО принять
                        // новый пин (анти-MITM канон: молча не доверяем никогда)
                        listener?.onPinMismatch(this@buildTlsClient, actualB64)
                        throw TlsFatalAlert(AlertDescription.bad_certificate)
                    }
                }
                // TOFU: (а) пина нет — первая «дружба» клиент↔сервер: принимаем
                // валидную самоподписанную цепочку и ФИКСИРУЕМ пин — дальше
                // шифруемся только с ним; (б) явный trustSelfSigned=true
                // (override для тестов/параноидального режима).
                // При заданном пине (дефолт) чужой самоподписанный сервер сюда
                // НЕ попадает: строкой выше соединение уже отклонено.
                if ((pin == null || trustSelfSigned) && isSelfSignedChain(chain)) {
                    if (pin == null) {
                        log(Msgs.TLS_TOFU_FIRST.t(actualB64))
                    } else {
                        log(Msgs.TLS_TOFU_OVERRIDE.t(actualB64))
                    }
                    acceptedPin = actualB64
                    rememberServerCert(chain)
                    listener?.onPinAccepted(this@buildTlsClient, actualB64)
                    return
                }
                throw TlsFatalAlert(AlertDescription.bad_certificate)
            }

            override fun getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials? =
                null
        }
    }
}

/**
 * Запоминает срок действия серверного сертификата из цепочки — честно
 * показываем пользователю (лог + «О приложении»): кем подписан и до какого
 * числа действителен.
 */
internal fun RrpClient.rememberServerCert(chain: Array<org.bouncycastle.tls.crypto.TlsCertificate>) {
    try {
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        val leaf = cf.generateCertificate(java.io.ByteArrayInputStream(chain[0].getEncoded()))
            as java.security.cert.X509Certificate
        serverCertValidUntilMs = leaf.notAfter.time
        RrpClient.lastServerCertNotAfterMs = leaf.notAfter.time
        log(
            Msgs.TLS_CERT_VALID.t(
                java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(leaf.notAfter),
                leaf.issuerX500Principal.name?.take(60) ?: "?",
            ),
        )
    } catch (_: Exception) {
    }
}

/**
 * Проверка self-signed цепочки без JCA-провайдера "BC": leaf подписан
 * последним сертификатом цепочки, последний — CA (IsCA) и подписан сам собой.
 * Достаточно для TOFU: мы не пытаемся построить WebPKI-доверие, мы лишь
 * фиксируем, что сервер предъявил валидную самоподписанную иерархию.
 */
internal fun RrpClient.isSelfSignedChain(
    chain: Array<org.bouncycastle.tls.crypto.TlsCertificate>,
): Boolean {
    return try {
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        val javaChain = chain.map { c ->
            cf.generateCertificate(java.io.ByteArrayInputStream(c.getEncoded()))
        }
        if (javaChain.isEmpty()) {
            false
        } else {
            val leaf = javaChain.first() as java.security.cert.X509Certificate
            val top = javaChain.last() as java.security.cert.X509Certificate
            // verify() бросает исключение при плохой подписи — ловится ниже
            leaf.verify(top.publicKey)
            top.subjectX500Principal == top.issuerX500Principal
        }
    } catch (e: Exception) {
        false
    }
}
