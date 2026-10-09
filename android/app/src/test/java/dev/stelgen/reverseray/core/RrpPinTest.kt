package dev.stelgen.reverseray.core

import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * v0.9.0 KAT: канон пина = SHA256(SPKI ПОСЛЕДНЕГО серта цепочки (CA)).
 * Регресс-тест прод-инцидента: лист ротируется → пин CA НЕ должен меняться;
 * до 0.9.0 клиент хешировал ЛИСТ → честные ссылки падали с ложным
 * «pin mismatch» (TLS bad_certificate(42)).
 */
class RrpPinTest {

    private fun genKey(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private val caKey = genKey()
    private val ca: X509Certificate = cert("CN=ReverseRay Root CA", caKey, null, caKey, ca = true)

    private fun cert(
        subject: String,
        key: KeyPair,
        issuerCert: X509Certificate?,
        issuerKey: KeyPair,
        ca: Boolean,
    ): X509Certificate {
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            issuerCert?.subjectX500Principal ?: X500Principal(subject),
            BigInteger.valueOf(now % 100000L + 1),
            Date(now - 60_000L),
            Date(now + 365L * 24 * 3600 * 1000),
            X500Principal(subject),
            key.public,
        )
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, BasicConstraints(ca))
        builder.addExtension(
            org.bouncycastle.asn1.x509.Extension.keyUsage,
            true,
            KeyUsage(KeyUsage.keyCertSign or KeyUsage.digitalSignature),
        )
        if (!ca) {
            builder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                false,
                ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
            )
        }
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    /** Порядок как на проводе: [leaf, CA]. */
    private fun chain(): List<ByteArray> = listOf(leaf(genKey()).encoded, ca.encoded)

    private fun leaf(key: KeyPair): X509Certificate = cert("CN=ReverseRay Server", key, ca, caKey, ca = false)

    private fun spkiSha256(der: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256")
            .digest(org.bouncycastle.asn1.x509.Certificate.getInstance(der).subjectPublicKeyInfo.encoded)

    @Test
    fun `pin is taken from CA (last cert), not leaf`() {
        val chainDer = chain()
        val got = RrpPin.caSha256(chainDer)
        assertArrayEquals(spkiSha256(chainDer.last()), got)
        val leafHash = spkiSha256(chainDer.first())
        assertTrue("пин не должен равняться хэшу листа", !MessageDigest.isEqual(got, leafHash))
    }

    @Test
    fun `leaf rotation does not change the pin`() {
        val pin1 = RrpPin.caSha256(chain())
        // плановая ротация листа: новая пара ключей, ТОТ ЖЕ CA
        val pin2 = RrpPin.caSha256(listOf(leaf(genKey()).encoded, ca.encoded))
        assertArrayEquals("ротация листа НЕ должна менять пин CA", pin1, pin2)
    }

    @Test
    fun `link pin format is raw base64url without padding`() {
        val link = RrpPin.toLinkPin(RrpPin.caSha256(chain()))
        assertTrue("нет паддинга", !link.contains('='))
        assertTrue("только URL-safe алфавит", link.none { it == '+' || it == '/' })
        assertEquals(43, link.length)
        assertNotNull(RrpPin.fromLinkPin(link))
    }

    @Test
    fun `fromLinkPin accepts rawurl, std, hex and rejects garbage`() {
        val data = ByteArray(32) { it.toByte() }
        val raw = RrpPin.toLinkPin(data)
        assertArrayEquals(data, RrpPin.fromLinkPin(raw))
        val std = java.util.Base64.getEncoder().encodeToString(data)
        assertArrayEquals(data, RrpPin.fromLinkPin(std))
        val hex = data.joinToString("") { "%02x".format(it) }
        assertArrayEquals(data, RrpPin.fromLinkPin(hex))
        assertArrayEquals(data, RrpPin.fromLinkPin(hex.uppercase()))
        assertNull(RrpPin.fromLinkPin(null))
        assertNull(RrpPin.fromLinkPin(""))
        assertNull(RrpPin.fromLinkPin("!!!not base64!!!"))
        assertNull(RrpPin.fromLinkPin(RrpPin.toLinkPin(ByteArray(16))))
    }
}