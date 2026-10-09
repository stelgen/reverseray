package dev.stelgen.reverseray.core

// Кросс-языковой e2e (v0.9.6): НАСТОЯЩИЙ Kotlin RrpClient против НАСТОЯЩЕГО
// Go-сервера (reverseray run) — все исполняемые протоколы по очереди, плюс
// РЕАЛЬНЫЙ трафик DATA через SOCKS5-mixed (конверты WG/IGE в оба направления).
//
// Запуск (сервер должен быть поднят, ссылка передана окружением):
//   RR_E2E_LINK='rrp://…@127.0.0.1:14433/?pin=…&name=e2e' \
//     [RR_E2E_PROTOS=rrp1,mtproto2,wireguard] [RR_E2E_MIXED=host:port] \
//     [RR_E2E_TARGET=host:port] ./gradlew :app:testDebugUnitTest --tests '*CrossLangE2e*'
//
// Без RR_E2E_LINK тесты ДЕАССУМЯТСЯ (пропустятся) — гейт не флейчит
// локальные сборки. CI поднимает сервер и включает гейт.
// Ссылка с токеном в env — не секрет в репо; литералов токенов в файле нет.

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNotNull
import org.junit.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

class CrossLangE2eTest {

    private val link: String? = System.getenv("RR_E2E_LINK")?.takeIf { it.startsWith("rrp://") }
    private val mixed: String? = System.getenv("RR_E2E_MIXED")
    private val wantProtos: List<String> =
        System.getenv("RR_E2E_PROTOS")?.split(',')
            ?.map { it.trim() }?.filter { it.isNotEmpty() }
            ?: listOf(RrpProtocols.DEFAULT, MtProto.PROTO_ID, Wg.PROTO_ID)

    private fun cryptoActive(client: RrpClient, proto: String): Boolean = when (proto) {
        MtProto.PROTO_ID -> client.mtProtoActive
        Wg.PROTO_ID -> client.wgActive
        else -> true
    }

    /** Ждёт апгрейд крипты до timeoutMs (KEY_REQ/WG_RESP — асинхронно после READY). */
    private fun awaitCrypto(client: RrpClient, proto: String, timeoutMs: Long, logs: List<String>) {
        if (proto == RrpProtocols.DEFAULT) return
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (cryptoActive(client, proto)) return
            Thread.sleep(50)
        }
        assertTrue(
            "крипта $proto не активна через ${timeoutMs}мс после READY\n--- client log ---\n${logs.joinToString("\n")}",
            cryptoActive(client, proto),
        )
    }

    /** Полный коннект + READY; возвращает клиента (не закрывает!). */
    private fun connectProto(
        proto: String,
        logs: CopyOnWriteArrayList<String>,
        validate: Boolean,
        allowLan: Boolean,
    ): RrpClient {
        val cfg = RrpUri.parse(link!!)
        val client = RrpClient(
            host = cfg.host,
            port = cfg.ports.first(),
            token = cfg.token,
            pin = cfg.pin,
            allowLan = allowLan,
            deviceName = cfg.name?.takeIf { it.isNotBlank() } ?: "phone-e2e",
            protoId = proto,
            validateProbeTarget = if (validate) "1.1.1.1:443" else null,
            listener = object : RrpClient.Listener {
                override fun onLog(client: RrpClient, message: String) {
                    logs.add(message)
                }
            },
        )
        try {
            client.connect()
        } catch (e: Exception) {
            val dump = logs.joinToString("\n")
            try { client.close() } catch (_: Exception) {}
            throw AssertionError("proto=$proto connect failed: ${e.message}\n--- session log ---\n$dump", e)
        }
        return client
    }

    /** SOCKS5-коннект через mixed-инбокс: GET target, возвращает тело ответа. */
    private fun socksGet(mixedAddr: String, host: String, port: Int, path: String): String {
        val parts = mixedAddr.split(":")
        val s = Socket()
        s.tcpNoDelay = true
        s.connect(InetSocketAddress(parts[0], parts[1].toInt()), 5000)
        s.soTimeout = 10_000
        val out = s.getOutputStream()
        val inp = s.getInputStream()
        // SOCKS5: приветствие без аутентификации
        out.write(byteArrayOf(5, 1, 0)); out.flush()
        val gr = inp.readNBytes(2)
        assertEquals("socks5 greeting", "0500", gr.joinToString("") { "%02x".format(it) })
        // CONNECT (ATYP=1, IPv4)
        val tgt = InetAddress.getByName(host).address
        val req = byteArrayOf(5, 1, 0, 1) + tgt + byteArrayOf((port ushr 8).toByte(), (port and 0xFF).toByte())
        out.write(req); out.flush()
        val resp = inp.readNBytes(10)
        assertEquals("socks5 reply ver", 5, resp[0].toInt())
        assertEquals("socks5 reply code", 0, resp[1].toInt())
        // HTTP GET
        out.write(("GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n").toByteArray()); out.flush()
        val sb = StringBuilder()
        val buf = ByteArray(4096)
        while (true) {
            val n = inp.read(buf)
            if (n < 0) break
            sb.append(String(buf, 0, n))
        }
        s.close()
        return sb.toString()
    }

    @Test
    fun e2e_allExecutableProtocolsAgainstRealGoServer() {
        assumeNotNull("RR_E2E_LINK не задан — пропуск (локальная сборка без сервера)", link)
        val results = mutableListOf<String>()
        for (p in wantProtos) {
            val logs = CopyOnWriteArrayList<String>()
            val client = connectProto(RrpProtocols.normalize(p), logs, validate = false, allowLan = false)
            try {
                assertEquals("proto $p: сервер выбрал другое", p, client.negotiatedProto)
                awaitCrypto(client, p, 5000, logs)
                results.add("E2E OK: $p → ${client.negotiatedProto} crypto=${client.tunnelCryptoActive}")
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
        }
        println(results.joinToString("\n"))
    }

    /** РЕАЛЬНЫЙ DATA-трафик через конверты (WG/IGE) в обе стороны + PROBE-валидация. */
    @Test
    fun e2e_dataPathThroughMixedProxyWithCrypto() {
        assumeNotNull("RR_E2E_LINK не задан — пропуск", link)
        val mixedAddr = mixed ?: return
        for (p in wantProtos) {
            val logs = CopyOnWriteArrayList<String>()
            val proto = RrpProtocols.normalize(p)
            // Валидационный коннект = ровно тот путь, что идёт при смене протокола
            // в GUI. allowLan=true: цель DATA-ноги — LAN-заглушка на этом же хосте
            // (SSRF-гвард при allowLan=false приватные диапазоны закрывает — это
            // отдельный канон-тест), здесь нам нужен реальный DATA через конверты.
            val client = connectProto(proto, logs, validate = true, allowLan = true)
            try {
                awaitCrypto(client, proto, 8000, logs)
                val tgt = (System.getenv("RR_E2E_TARGET")?.split(":")
                    ?: firstLanAddr18099())
                val html = try {
                    socksGet(mixedAddr, tgt[0], tgt[1].toInt(), "/")
                } catch (e: Exception) {
                    throw AssertionError(
                        "proto=$proto: socksGet failed: $e\n--- client log ---\n${logs.joinToString("\n")}",
                        e,
                    )
                }
                assertTrue(
                    "proto=$proto: DATA-путь через mixed не отработал (логи:\n${logs.joinToString("\n")})",
                    html.contains("HTTP/1.") && html.contains("200"),
                )
                println("E2E DATA OK: $proto (crypto=${client.tunnelCryptoActive})")
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
        }
    }

    /** Первый не-loopback IPv4 хоста + порт 18099 (LAN-заглушка e2e). */
    private fun firstLanAddr18099(): List<String> =
        java.net.NetworkInterface.getNetworkInterfaces().asSequence()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.asSequence() }
            .filter { it is java.net.Inet4Address }
            .map { listOf(it.hostAddress, "18099") }
            .firstOrNull() ?: listOf("127.0.0.1", "19090")
}
