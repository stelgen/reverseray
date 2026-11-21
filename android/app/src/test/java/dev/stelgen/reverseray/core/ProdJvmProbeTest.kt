package dev.stelgen.reverseray.core

// ВРЕМЕННЫЙ диагностический тест (не коммитится): JVM-прогон реального
// RrpClient против прода. Ссылка приходит через env RR_PROBE_LINK.
// Использование: RR_PROBE_LINK="rrp://..." ./gradlew :app:testDebugUnitTest --tests "*ProdJvmProbeTest"
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class ProdJvmProbeTest {

    private fun runOne(proto: String) {
        val link = System.getenv("RR_PROBE_LINK")
            ?: error("RR_PROBE_LINK env is required")
        val cfg = RrpUri.parse(link)
        val states = CountDownLatch(1)
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

    @Test fun switchChain() {
        val link = System.getenv("RR_PROBE_LINK") ?: error("RR_PROBE_LINK env is required")
        val cfg = RrpUri.parse(link)
        val client = RrpClient(
            host = cfg.host, port = cfg.ports.firstOrNull() ?: 4433,
            token = cfg.token, pin = cfg.pin, allowLan = false,
            listener = object : RrpClient.Listener {
                override fun onLog(client: RrpClient, message: String, kind: LogKind) { println("[${kind}] $message") }
                override fun onState(client: RrpClient, state: RrpClient.State) { println("[STATE] $state") }
            },
            deviceName = cfg.name ?: "phone-1", transport = cfg.transport,
            protoId = "", validateProbeTarget = "connectivitycheck.gstatic.com:80",
        )
        client.connect()
        println("SWITCHTEST start negotiated=${client.negotiatedProto}")
        val steps = listOf("mtproto2", "bittorrent", "apimask", "mtproto2")
        for (t in steps) {
            val ok = client.switchProto(t)
            println("SWITCHTEST switch->$t ok=$ok")
            Thread.sleep(3500) // перехендшейк
            val e2e = client.e2eProbeOnce("connectivitycheck.gstatic.com:80", 8000)
            println("SWITCHTEST e2e after->$t = $e2e (state=${client.state}, negotiated=${client.negotiatedProto})")
        }
        client.close()
    }
}
