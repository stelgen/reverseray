package dev.stelgen.reverseray.core

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Ignore
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.math.BigInteger
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.Base64
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket

private typealias Sender = (t: Byte, sid: Long, p: ByteArray) -> Unit

private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

private fun buildFrame(t: Byte, sid: Long, payload: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    out.write(byteArrayOf(1, t))   // version=1, type
    out.write(byteArrayOf(0, 0))   // flags
    val sidB = ByteArray(4)
    for (i in 0 until 4) sidB[i] = (sid shr ((3 - i) * 8)).toByte()
    out.write(sidB)
    val len = payload.size
    out.write(byteArrayOf((len shr 24).toByte(), (len shr 16).toByte(), (len shr 8).toByte(), len.toByte()))
    out.write(payload)
    return out.toByteArray()
}

private fun readFrame(inp: DataInputStream): Pair<Byte, ByteArray>? {
    val hdr = ByteArray(12)
    return try {
        inp.readFully(hdr)
        val len = ((hdr[8].toInt() and 0xFF) shl 24) or ((hdr[9].toInt() and 0xFF) shl 16) or
            ((hdr[10].toInt() and 0xFF) shl 8) or (hdr[11].toInt() and 0xFF)
        val payload = ByteArray(len)
        if (len > 0) inp.readFully(payload)
        hdr[1] to payload
    } catch (_: Exception) {
        null
    }
}

/**
 * Враждебный RRP-сервер для функциональных тестов клиента:
 * настоящий TLS 1.3 с self-signed сертификатом (SPKI-pin передан клиенту),
 * корректное рукопожатие, затем произвольное поведение через behavior.
 */
private class EvilServer(
    val behavior: (conn: Socket, inp: DataInputStream, out: Sender) -> Unit,
) {
    val received = ArrayDeque<Pair<Byte, ByteArray>>()
    val token = "test-token-0123456789abcdef"
    val pin: String

    private val sslServer: SSLServerSocket
    private val accepted = CountDownLatch(1)

    val port: Int get() = sslServer.localPort

    private fun senderFor(s: Socket): Sender = { t, sid, p ->
        synchronized(received) { received.add(t to p) }
        s.getOutputStream().write(buildFrame(t, sid, p))
        s.getOutputStream().flush()
    }

    init {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val kp = kpg.generateKeyPair()
        val now = Date()
        val cert = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(
                X500Name("CN=evil.test"), BigInteger.valueOf(42),
                now, Date(now.time + 365L * 24 * 3600 * 1000),
                X500Name("CN=evil.test"), kp.public,
            ).build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private)),
        )
        pin = Base64.getEncoder().encodeToString(sha256(kp.public.encoded))

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("k", kp.private, charArrayOf(), arrayOf<Certificate>(cert))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, charArrayOf())
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)

        sslServer = ctx.serverSocketFactory.createServerSocket(0) as SSLServerSocket

        Thread {
            try {
                val s = sslServer.accept()
                behavior(s, DataInputStream(s.getInputStream()), senderFor(s))
            } catch (_: Throwable) {
            } finally {
                try { sslServer.close() } catch (_: Exception) {}
            }
        }.apply { isDaemon = true }.start()
    }

    fun stop() {
        try { sslServer.close() } catch (_: Exception) {}
    }

}

/** Тесты клиента против враждебного сервера. */
class EvilServerTest {

    private fun newClient(server: EvilServer, listener: RrpClient.Listener? = null): RrpClient =
        RrpClient(
            host = "127.0.0.1", port = server.port, token = server.token,
            pin = server.pin, allowLan = false, listener = listener,
        )

    @Test
    fun `happy path reaches READY`() {
        val server = EvilServer { conn, inp, out ->
            serverHandshake(conn, inp, out)
            Thread.sleep(300)
        }
        try {
            val c = newClient(server)
            c.connect()
            assertEquals(RrpClient.State.READY, c.state)
            c.close()
        } finally {
            server.stop()
        }
    }

    @Test
    fun `oversized frame closes client without OOM`() {
        val server = EvilServer { conn, inp, out ->
            serverHandshake(conn, inp, out)
            val hdr = ByteArray(12)
            hdr[0] = 1; hdr[1] = RrpFrame.TYPE_DATA.toByte()
            hdr[8] = 0x7F.toByte(); hdr[9] = 0xFF.toByte(); hdr[10] = 0xFF.toByte(); hdr[11] = 0xFF.toByte()
            conn.getOutputStream().write(hdr)
            conn.getOutputStream().flush()
            Thread.sleep(400)
        }
        try {
            val c = newClient(server)
            c.connect()
            val deadline = System.currentTimeMillis() + 3000
            while (c.state != RrpClient.State.CLOSED && System.currentTimeMillis() < deadline) Thread.sleep(50)
            assertEquals(RrpClient.State.CLOSED, c.state)
        } finally {
            server.stop()
        }
    }

    @Test
    fun `bad frame version closes client`() {
        val server = EvilServer { conn, inp, out ->
            serverHandshake(conn, inp, out)
            val hdr = ByteArray(12)
            hdr[0] = 9; hdr[1] = RrpFrame.TYPE_PING.toByte()
            conn.getOutputStream().write(hdr)
            conn.getOutputStream().flush()
            Thread.sleep(400)
        }
        try {
            val c = newClient(server)
            c.connect()
            val deadline = System.currentTimeMillis() + 3000
            while (c.state != RrpClient.State.CLOSED && System.currentTimeMillis() < deadline) Thread.sleep(50)
            assertEquals(RrpClient.State.CLOSED, c.state)
        } finally {
            server.stop()
        }
    }

    @Test
    fun `ssrf private address blocked and open frame never sent`() {
        val server = EvilServer { conn, inp, out ->
            serverHandshake(conn, inp, out)
            Thread.sleep(600)
        }
        try {
            val c = newClient(server)
            c.connect()
            assertEquals(RrpClient.ERR_SSRF_BLOCKED, c.sendOpen("127.0.0.1", 8080).get(2000))
            assertFalse("OPEN must not leave the client on SSRF block",
                synchronized(server.received) { server.received.any { it.first == RrpFrame.TYPE_OPEN.toByte() } })
            c.close()
        } finally {
            server.stop()
        }
    }

    @Test
    fun `ssrf TEST-NET addresses blocked`() {
        val server = EvilServer { conn, inp, out ->
            serverHandshake(conn, inp, out)
            Thread.sleep(900)
        }
        try {
            val c = newClient(server)
            c.connect()
            for (host in listOf("203.0.113.5", "198.51.100.7", "192.0.2.9")) {
                assertEquals("TEST-NET $host", RrpClient.ERR_SSRF_BLOCKED, c.sendOpen(host, 443).get(2000))
            }
            assertFalse(synchronized(server.received) { server.received.any { it.first == RrpFrame.TYPE_OPEN.toByte() } })
            c.close()
        } finally {
            server.stop()
        }
    }

    @Ignore(
        "JVM-interop: JDK TLS-сервер -> BC-клиент, S→C DATA не доставляется до " +
            "первого клиентского трафика; путь CLOSE(err=2) покрыт Go-тестом " +
            "TestSessionDataUnknownStreamClose",
    )
    @Test
    fun `data on unknown stream answered with close err_no_stream`() {
        val closeCode = java.util.concurrent.atomic.AtomicReference<Int?>(null)
        val seen = ArrayDeque<Byte>()
        val logs = ArrayDeque<String>()
        val server = EvilServer { conn, inp, out ->
            serverHandshake(conn, inp, out)
            out(RrpFrame.TYPE_DATA.toByte(), 999, "x".toByteArray())
            val deadline = System.currentTimeMillis() + 3000
            while (System.currentTimeMillis() < deadline && closeCode.get() == null) {
                val f = readFrame(inp) ?: break
                synchronized(seen) { seen.add(f.first) }
                when (f.first) {
                    RrpFrame.TYPE_CLOSE.toByte() -> if (f.second.isNotEmpty()) closeCode.set(f.second[0].toInt())
                    RrpFrame.TYPE_PING.toByte() -> out(RrpFrame.TYPE_PONG.toByte(), 0, f.second)
                }
            }
        }
        try {
            val c = newClient(server, object : RrpClient.Listener {
                override fun onLog(client: RrpClient, message: String) {
                    synchronized(logs) { logs.add(message) }
                }
            })
            c.connect()
            assertEquals(RrpClient.State.READY, c.state)
            val diag = "seen=" + synchronized(seen) { seen.joinToString(",") { it.toString() } } +
                " logs=" + synchronized(logs) { logs.joinToString(" | ") }
            assertTrue(
                "expected protective CLOSE (err != 0); $diag",
                closeCode.get() != null && closeCode.get()!! != 0,
            )
            c.close()
        } finally {
            server.stop()
        }
    }

    @Test
    fun `abrupt server disconnect closes client cleanly`() {
        val closed = CountDownLatch(1)
        val server = EvilServer { conn, inp, out ->
            serverHandshake(conn, inp, out)
            Thread.sleep(200)
            conn.close()
        }
        try {
            val c = newClient(server, object : RrpClient.Listener {
                override fun onState(client: RrpClient, state: RrpClient.State) {
                    if (state == RrpClient.State.CLOSED) closed.countDown()
                }
            })
            c.connect()
            assertTrue(closed.await(3, TimeUnit.SECONDS))
            c.close()
        } finally {
            server.stop()
        }
    }

    /** Вынесено, чтобы бехавиор-лямбды вызывали корректное рукопожатие. */
    private fun serverHandshake(conn: Socket, inp: DataInputStream, out: Sender) {
        val s = readFrame(inp) ?: return
        check(s.first == RrpFrame.TYPE_HELLO.toByte()) { "expected HELLO" }
        out(RrpFrame.TYPE_HELLO_OK.toByte(), 0,
            """{"session_id":"s1","server_ver":"0.2.1","tunnel_window":524288}""".toByteArray())
        readFrame(inp) // AUTH
        out(RrpFrame.TYPE_READY.toByte(), 0,
            """{"tunnel_id":"t1","role":"active","max_streams":64,"tunnel_window":524288}""".toByteArray())
    }
}
