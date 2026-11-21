package dev.stelgen.reverseray.core

// Диагностический JVM-тест реального RrpClient против прода. Ссылка — только
// через env RR_PROBE_LINK (без env тесты SKIPPED через Assume — CI-безопасно).
// Использование: RR_PROBE_LINK="rrp://..." ./gradlew :app:testDebugUnitTest --tests "*ProdJvmProbeTest"
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class ProdJvmProbeTest {

    private fun runOne(proto: String) {
        assumeTrue("RR_PROBE_LINK env is required — skip", System.getenv("RR_PROBE_LINK") != null)
        val link = System.getenv("RR_PROBE_LINK")
            ?: error("RR_PROBE_LINK env is required")
        val cfg = RrpUri.parse(link)
        val client = RrpClient(
            host = cfg.host,
            port = cfg.ports.firstOrNull() ?: 4433,
            token = cfg.token,
            pin = cfg.pin,
            allowLan = false,
            listener = object : RrpClient.Listener {
                override fun onLog(client: RrpClient, message: String, kind: LogKind) {
                    println("[${kind}] $message")
                }
                override fun onState(client: RrpClient, state: RrpClient.State) {
                    println("[STATE] $state")
                }
            },
            deviceName = cfg.name ?: "phone-1",
            transport = cfg.transport,
            protoId = proto,
            validateProbeTarget = "connectivitycheck.gstatic.com:80",
        )
        client.udpEnabled = true
        try {
            client.connect()
            Thread.sleep(500)
            val pr = client.probeOnce("connectivitycheck.gstatic.com:80", 5000)
            println("PROBE $proto: $pr")
            val e2e = client.e2eProbeOnce("connectivitycheck.gstatic.com:80", 8000)
            println("E2E   $proto: $e2e")
            val (loss, rtt) = client.healthWindow()
            println("RESULT $proto: CONNECT OK, healthWindow loss=$loss rtt=$rtt")
        } catch (e: Throwable) {
            println("RESULT $proto: FAIL ${e.javaClass.simpleName}: ${e.message}")
            throw e
        } finally {
            try { client.close() } catch (_: Throwable) {}
        }
    }

    @Test fun probeMtp() { runOne("mtproto2") }
    @Test fun probeWg() { runOne("wireguard") }
    @Test fun probeRrp1() { runOne("rrp1") }
    @Test fun probeBt() { runOne("bittorrent") }

    /**
     * v1.9.3: 0x2C удалён — смена протокола = ОБЫЧНЫЙ РЕКОННЕКТ. Прода-проба
     * «ротации»: цепочка независимых клиентов (AUTO → mtproto2 → bittorrent
     * → wireguard), после каждого подъёма — e2e-проба в новом конверте.
     */
    @Test fun reconnectChain() {
        assumeTrue("RR_PROBE_LINK env is required — skip", System.getenv("RR_PROBE_LINK") != null)
        val link = System.getenv("RR_PROBE_LINK") ?: error("RR_PROBE_LINK env is required")
        val cfg = RrpUri.parse(link)
        for (t in listOf("", "mtproto2", "bittorrent", "wireguard")) {
            val client = RrpClient(
                host = cfg.host, port = cfg.ports.firstOrNull() ?: 4433,
                token = cfg.token, pin = cfg.pin, allowLan = false,
                listener = object : RrpClient.Listener {
                    override fun onLog(client: RrpClient, message: String, kind: LogKind) { println("[${kind}] $message") }
                    override fun onState(client: RrpClient, state: RrpClient.State) { println("[STATE] $state") }
                },
                deviceName = cfg.name ?: "phone-1", transport = cfg.transport,
                protoId = t, validateProbeTarget = "connectivitycheck.gstatic.com:80",
            )
            try {
                client.connect()
                val e2e = client.e2eProbeOnce("connectivitycheck.gstatic.com:80", 8000)
                println("RECONNECTTEST proto='$t' negotiated=${client.negotiatedProto} e2e=$e2e (state=${client.state})")
            } finally {
                try { client.close() } catch (_: Throwable) {}
            }
        }
    }
}
