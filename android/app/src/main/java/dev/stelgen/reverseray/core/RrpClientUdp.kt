// v1.9.0: зона «UDP-канал» вынесена из RrpClient.kt (транш-2): UDP_ASSOC,
// приёмный loop ассоциаций, UP/DOWN прокидка UDP_DATA (+DPI-шапка 0x2B).
// Pure refactor: private → internal у задетых членов, поведение не меняется.
package dev.stelgen.reverseray.core

import java.net.DatagramPacket
import java.net.InetSocketAddress

    internal fun RrpClient.handleIncomingUdpAssoc(frame: RrpFrame.UdpAssoc) {
        val id = frame.streamId
        if (!udpEnabled) {
            // v1.0.0: UDP-модуль выключен галочкой владельца — ровно ноль дейтаграмм
            sendOpenOk(id, RrpClient.ERR_CONNECT_FAILED)
            log(Msgs.UDP_DISABLED.t())
            return
        }
        if (udpAssocs.size >= maxStreams) {
            sendOpenOk(id, RrpClient.ERR_TOO_MANY_STREAMS)
            return
        }
        val assoc = try {
            RrpClient.UdpAssoc(id)
        } catch (e: Exception) {
            log(Msgs.UDP_ASSOC_FAILED.t(e.message), LogKind.WARN)
            sendOpenOk(id, RrpClient.ERR_CONNECT_FAILED)
            return
        }
        udpAssocs[id] = assoc
        sendOpenOk(id, RrpClient.ERR_OK)
        Thread({ udpReceiveLoop(assoc) }, "rrp-udp-$id").apply { isDaemon = true }.start()
    }

    /** Приём дейтаграмм из интернета → UDP_DATA C→S (источник = фактический отправитель). */
    internal fun RrpClient.udpReceiveLoop(assoc: RrpClient.UdpAssoc) {
        val buf = ByteArray(RrpClient.UDP_RECV_BUFFER)
        while (running.get() && !assoc.closed.get()) {
            val pkt = DatagramPacket(buf, buf.size)
            try {
                assoc.socket.receive(pkt)
            } catch (_: Exception) {
                break
            }
            if (pkt.length <= 0) continue
            val src = pkt.address
            val atyp = if (src.address.size == 4) RrpAddress.ATYP_IPV4 else RrpAddress.ATYP_IPV6
            sendFrameQuiet(RrpFrame.UdpData(assoc.id, atyp, src.address, pkt.port, buf.copyOf(pkt.length)))
        }
    }

    /** S→C UDP_DATA: дейтаграмма на адрес назначения (с SSRF-guard; порт 53 = DNS+ разрешён). */
    internal fun RrpClient.handleUdpData(frame: RrpFrame.UdpData) {
        val assoc = udpAssocs[frame.streamId]
        if (assoc == null || assoc.closed.get()) return
        val targetHost = try {
            RrpAddress.decodeAddr(frame.atyp, frame.addr)
        } catch (e: Exception) {
            return
        }
        // Порт 53 разрешён даже в приватные сети: это DNS-релей телефона,
        // тот же резолвер, которым телефон пользуется сам (документировано в protocol.md).
        val allow = allowLan || frame.port == 53
        if (SsrfGuard.isBlocked(targetHost, allow)) {
            log(Msgs.UDP_SSRF.t("$targetHost:${frame.port}"), LogKind.WARN)
            return
        }
        val dst: java.net.InetAddress = when (frame.atyp) {
            RrpAddress.ATYP_IPV4, RrpAddress.ATYP_IPV6 -> try {
                java.net.InetAddress.getByAddress(frame.addr)
            } catch (e: Exception) {
                return
            }
            else -> {
                // домен: резолвим сами и проверяем каждый адрес (DNS-rebinding)
                val resolved = try {
                    java.net.InetAddress.getAllByName(targetHost)
                        .firstOrNull { !SsrfGuard.isBlockedAddress(it, allow) }
                } catch (e: Exception) {
                    null
                }
                if (resolved == null) {
                    log(Msgs.UDP_RESOLVE_SSRF.t("$targetHost:${frame.port}"), LogKind.WARN)
                    return
                }
                resolved
            }
        }
        if (SsrfGuard.isBlockedAddress(dst, allow)) {
            log(Msgs.UDP_ADDR_SSRF.t("$targetHost:${frame.port}"), LogKind.WARN)
            return
        }
        if (frame.bytes.isEmpty()) return
        try {
            assoc.socket.send(DatagramPacket(frame.bytes, frame.bytes.size, dst, frame.port))
        } catch (e: Exception) {
            log("udp send failed: ${e.message}", LogKind.WARN)
        }
    }

    /** Локальная UDP-ассоциация: DatagramSocket + поток приёма. */
