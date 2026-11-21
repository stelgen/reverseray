// v1.9.0: зона «стримы и паркинг сокетов» вынесена из RrpClient.kt (транш-2):
// исходящий/входящий OPEN и OPEN_RESUME, реестр стримов, pump данных,
// park/closeParked (TCP-сессии переживают смерть транспорта), closeStream.
// Pure refactor: private → internal у задетых членов, поведение не меняется.
package dev.stelgen.reverseray.core

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

// ------------------------------------------------------------------ OPEN / стримы / паркинг

    internal fun RrpClient.flushPendingCamCtl() {
        val want = pendingCamCtl ?: return
        pendingCamCtl = null
        if (state == RrpClient.State.READY) {
            debug(Msgs.CAM_CTL_SENT.t(if (want) "on" else "off"))
            try {
                sendFrame(RrpFrame.CamCtl(want))
            } catch (e: IOException) {
                log(Msgs.CAM_CTL_FAILED.t(e.message ?: "?"), LogKind.WARN)
            }
        }
    }

    // ------------------------------------------------------------------ OPEN

    /**
     * Исходящий OPEN (по ТЗ): отправить кадр и дождаться OPEN_OK.
     * Возвращает err_code (RrpClient.ERR_OK = 0); без отправки — RrpClient.ERR_NOT_READY /
     * RrpClient.ERR_SSRF_BLOCKED / RrpClient.ERR_BAD_ADDRESS. Отменяется таймаутом RrpClient.OPEN_TIMEOUT_MS → RrpClient.ERR_TIMEOUT.
     */
    internal fun RrpClient.sendOpen(addr: String, port: Int, onStreamId: ((Long) -> Unit)? = null): OpenFuture {
        // v1.8.1: onStreamId вызывается ДО отправки OPEN — подписчик успевает
        // зарегистрировать стрим (E2E-пробник: socketpair), входящие DATA
        // попадают по адресу. Id — ЧЁТНЫЙ (см. RrpClient.phoneStreamId).
        val future = OpenFuture()
        if (state != RrpClient.State.READY) {
            future.complete(RrpClient.ERR_NOT_READY)
            return future
        }
        if (SsrfGuard.isBlocked(addr, allowLan)) {
            log(Msgs.SEND_OPEN_SSRF.t(addr), LogKind.WARN)
            future.complete(RrpClient.ERR_SSRF_BLOCKED)
            return future
        }
        val encoded = try {
            RrpAddress.encodeAddr(addr)
        } catch (e: Exception) {
            future.complete(RrpClient.ERR_BAD_ADDRESS)
            return future
        }
        val streamId = RrpClient.phoneStreamId(nextStreamId.getAndIncrement())
        onStreamId?.invoke(streamId)
        pendingOpens[streamId] = future
        try {
            sendFrame(RrpFrame.Open(streamId, encoded.atyp, encoded.bytes, port))
        } catch (e: IOException) {
            pendingOpens.remove(streamId)
            future.complete(RrpClient.ERR_CONNECT_FAILED)
            return future
        }
        try {
            pingExecutor.schedule({
                pendingOpens.remove(streamId)?.complete(RrpClient.ERR_TIMEOUT)
            }, RrpClient.OPEN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
            // клиент уже закрыт — future завершён в close()
        }
        return future
    }

    /** S→C OPEN: сервер просит телефон диалить цель. Ответ — OPEN_OK c err_code. */
    internal fun RrpClient.handleIncomingOpen(frame: RrpFrame.Open) {
        val streamId = frame.streamId
        val targetHost = try {
            RrpAddress.decodeAddr(frame.atyp, frame.addr)
        } catch (e: Exception) {
            sendOpenOk(streamId, RrpClient.ERR_BAD_ADDRESS)
            return
        }
        if (SsrfGuard.isBlocked(targetHost, allowLan)) {
            log(Msgs.OPEN_SSRF.t("$targetHost:${frame.port}"), LogKind.WARN)
            sendOpenOk(streamId, RrpClient.ERR_SSRF_BLOCKED)
            return
        }
        if (streams.size >= maxStreams) {
            sendOpenOk(streamId, RrpClient.ERR_TOO_MANY_STREAMS)
            return
        }
        // DNS-resolve выполняем сами и проверяем КАЖДЫЙ адрес по байтам:
        // hostname может резолвиться в приватный IP (DNS-rebinding bypass строки-гварда)
        val allowedAddr = try {
            java.net.InetAddress.getAllByName(targetHost)
                .firstOrNull { !SsrfGuard.isBlockedAddress(it, allowLan) }
        } catch (e: Exception) {
            sendOpenOk(streamId, RrpClient.ERR_BAD_ADDRESS)
            return
        }
        if (allowedAddr == null) {
            log(Msgs.OPEN_RESOLVES_SSRF.t("$targetHost:${frame.port}"), LogKind.WARN)
            sendOpenOk(streamId, RrpClient.ERR_SSRF_BLOCKED)
            return
        }
        try {
            relayExecutor.execute {
                var sock: Socket? = null
                try {
                    val s = Socket()
                    // коннект на уже проверенный адрес — без повторного DNS-резолва
                    s.connect(InetSocketAddress(allowedAddr, frame.port), RrpClient.CONNECT_TIMEOUT_MS)
                    s.tcpNoDelay = true
                    sock = s
                    val st = registerStream(streamId, s)
                    sendOpenOk(streamId, RrpClient.ERR_OK)
                    pumpOutgoing(st) // цель → DATA → сервер; блокируется до закрытия стрима
                } catch (e: Exception) {
                    closeQuietly(sock)
                    sendOpenOk(streamId, RrpClient.ERR_CONNECT_FAILED)
                }
            }
        } catch (_: RejectedExecutionException) {
            sendOpenOk(streamId, RrpClient.ERR_GENERAL)
        }
    }

    internal fun RrpClient.registerStream(id: Long, sock: Socket): RrpClient.Stream {
        val window = tunnelWindow.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
        val st = RrpClient.Stream(id, sock, Semaphore(window))
        if (ackCapable) st.ledger = RrpAckLedger() // v1.9.8 Buffer/2
        streams[id] = st
        return st
    }

    // ------------------------------------------------------------------ PARK / RESUME (v1.3.0)

    internal fun RrpClient.tokenKey(tok: ByteArray): String =
        tok.joinToString("") { ((it.toInt() and 0xFF)).toString(16).padStart(2, '0') }

    /** Паркинг сокета при смерти транспорта: TCP-сессия с сайтом сохраняется. */
    internal fun RrpClient.parkSocket(st: RrpClient.Stream) {
        val tok = st.resumeToken ?: return // старый сервер — закрываем как раньше
        val key = tokenKey(tok)
        // v1.9.8 Buffer/2: LEDGER p→c и consumedTotal (c→p) переживают смерть
        // транспорта — досыл/дедуп при OPEN_RESUME.
        parkedSockets[key] = RrpClient.ParkedSock(
            st.socket, System.currentTimeMillis(), st.consumedTotal, st.ledger,
        )
        try {
            parkExecutor.schedule({ closeParked(key) }, RrpClient.STREAM_PARK_MS, TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {}
        debug(Msgs.SOCKET_PARKED.t(st.id))
    }

    internal fun RrpClient.closeParked(key: String) {
        parkedSockets.remove(key)?.let {
            try { it.socket.close() } catch (_: Exception) {}
            debug(Msgs.PARK_EXPIRED.t())
        }
    }

    /** OPEN_RESUME: сервер просит привязать запаркованный сокет к новому стриму. */
    internal fun RrpClient.handleOpenResume(frame: RrpFrame.OpenResume) {
        val sock = parkedSockets.remove(tokenKey(frame.token))
        if (sock == null) {
            debug(Msgs.RESUME_NO_SOCKET.t())
            sendFrameQuiet(RrpFrame.OpenOk(frame.streamId, RrpClient.ERR_NO_PARKED))
            return
        }
        if (streams[frame.streamId] != null) {
            sendFrameQuiet(RrpFrame.OpenOk(frame.streamId, RrpClient.ERR_GENERAL))
            return
        }
        try { sock.socket.soTimeout = 0 } catch (_: Exception) {}
        val st = registerStream(frame.streamId, sock.socket)
        st.resumeToken = frame.token
        // v1.9.8 Buffer/2: продолжаем нумерацию старого стрима — LEDGER с
        // неподтверждённым хвостом и абсолют consumedTotal (база дедупа c→p).
        st.consumedTotal = sock.consumedTotal
        st.ledger = sock.ledger
        relayExecutor.execute { pumpOutgoing(st) }
        // ack-режим: расширенный OPEN_OK [err][u64be K] — сервер продолжает
        // свою c→p LEDGER-нумерацию с K (его досыл отфильтрует всё ≤ K).
        sendFrameQuiet(
            if (ackCapable) RrpFrame.OpenOk(frame.streamId, RrpClient.ERR_OK, k = st.consumedTotal)
            else RrpFrame.OpenOk(frame.streamId, RrpClient.ERR_OK),
        )
        debug(Msgs.RESUME_ATTACHED.t(frame.streamId))
    }

    /** Поток: сокет цели → DATA кадры (с учётом окна flow-control).
     *  acquire с таймаутом: если сервер умер и не наращивает окно — поток не висит вечно. */
    internal fun RrpClient.pumpOutgoing(st: RrpClient.Stream) {
        val buf = ByteArray(16 * 1024)
        var sendFailed = false // v1.9.6: ошибка отправки → Close(ERR_GENERAL), не ERR_OK
        try {
            // v1.9.8 Buffer/2 (ack-режим, отправитель p→c): (1) досыл LEDGER —
            // отправленное-но-не-ACKнутое с теми же оффсетами (сервер-читатель
            // дропает всё ≤ baseIn — дубли безопасны); (2) живое чтение: оффсет
            // назначает LEDGER (append ПЕРЕД отправкой — неуспешный чанк остаётся
            // в LEDGER и переживает паркинг). ACK(0x2F) от сервера вытесняет.
            val ledger = st.ledger
            if (ledger != null) {
                val acked = st.ackedOffset
                for (c in ledger.replayFrom(acked)) { // floor=max(k,base): подтверждённое отсекает сам LEDGER
                    try {
                        sendFrame(RrpFrame.Data(st.id, 0, withOffset(c.offset, c.bytes)))
                    } catch (_: Exception) {
                        // чанк уже в LEDGER — досыл при следующем resume
                        break
                    }
                }
            } else {
                // v1.9.6 канон Buffer/1: досыл in-flight p→c ДО новых чтений
                // (FIFO); при повторной смерти чанк возвращается в голову.
                while (true) {
                    val chunk = st.outBuf.poll() ?: break
                    try {
                        sendFrame(RrpFrame.Data(st.id, 0, chunk))
                    } catch (_: Exception) {
                        st.outBuf.pushFront(chunk)
                        break
                    }
                }
            }
            val input = st.socket.getInputStream()
            while (running.get() && !st.closed.get() && !st.parked.get()) {
                // Такт чтения: pump обязан просыпаться и проверять parked —
                // при паркинге он выходит БЕЗ закрытия сокета (второй читатель
                // на резюмированном сокете недопустим).
                try { st.socket.soTimeout = RrpClient.PUMP_POLL_MS } catch (_: Exception) {}
                val n = try {
                    input.read(buf)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                }
                if (n < 0) break
                if (n == 0) continue
                if (!st.sendWindow.tryAcquire(n, RrpClient.WINDOW_ACQUIRE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                    debug(Msgs.WINDOW_NOT_GROWN.t(st.id, RrpClient.WINDOW_ACQUIRE_TIMEOUT_MS))
                    sendFrameQuiet(RrpFrame.Close(st.id, RrpClient.ERR_TIMEOUT))
                    break
                }
                // Копия чанка до отправки: LEDGER должен владеть своими байтами.
                val chunk = buf.copyOf(n)
                if (ledger != null) {
                    val off = ledger.append(chunk)
                    try {
                        sendFrame(RrpFrame.Data(st.id, 0, withOffset(off, chunk)))
                    } catch (_: Exception) {
                        // Buffer/2 MODE_FAIL: чанк в LEDGER — досыл при resume
                        break
                    }
                } else {
                    try {
                        sendFrame(RrpFrame.Data(st.id, 0, chunk))
                    } catch (_: Exception) {
                        // v1.9.6 канон Buffer/1 (MODE_FAIL): прочитанный чанк НЕ
                        // теряется — в буфер стрима; OPEN_RESUME досылает первым.
                        st.outBuf.push(chunk)
                        sendFailed = true
                        break
                    }
                }
            }
            if (sendFailed) {
                sendFrameQuiet(RrpFrame.Close(st.id, RrpClient.ERR_GENERAL))
            } else if (!st.closed.get() && !st.parked.get()) {
                sendFrameQuiet(RrpFrame.Close(st.id, RrpClient.ERR_OK))
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (e: Exception) {
            sendFrameQuiet(RrpFrame.Close(st.id, RrpClient.ERR_GENERAL))
        } finally {
            // Паркинг: сокет продолжает жить (TTL-рипер/OPEN_RESUME).
            if (!st.parked.get()) closeStreamInternal(st)
        }
    }

    /** v1.9.8 Buffer/2: DATA-payload ack-режима = [u64be offset][байты]. */
    private fun withOffset(off: Long, bytes: ByteArray): ByteArray =
        ByteArray(8 + bytes.size).also {
            putU64(it, 0, off)
            bytes.copyInto(it, 8)
        }

    // ------------------------------------------------------------------ DATA / WINDOW

    internal fun RrpClient.handleData(frame: RrpFrame.Data) {
        val st = streams[frame.streamId]
        if (st == null) {
            sendFrameQuiet(RrpFrame.Close(frame.streamId, RrpClient.ERR_NO_STREAM))
            return
        }
        try {
            val out = st.socket.getOutputStream()
            // v1.9.8 Buffer/2 (ack-режим, c→p приёмник): DATA = [u64be off][байты].
            // Дубль (off+len ≤ consumedTotal) — скип; гэп — дроп с журналом
            // (порядок in-order, гэп возможен только в гонке при resume).
            val off: Long; var payload: ByteArray
            if (ackCapable) {
                val split = splitDataOffset(frame.bytes)
                off = split.first
                payload = split.second
                val end = off + payload.size
                if (end <= st.consumedTotal) {
                    debug(Msgs.DATA_OFFSET_DUP.t(off))
                    return
                }
                if (off > st.consumedTotal) {
                    debug(Msgs.DATA_OFFSET_GAP.t(off))
                    return
                }
                if (off < st.consumedTotal) { // straddle — пишем только хвост
                    payload = payload.copyOfRange((st.consumedTotal - off).toInt(), payload.size)
                }
            } else {
                off = 0; payload = frame.bytes
            }
            out.write(payload)
            out.flush()
            st.consumedTotal = maxOf(st.consumedTotal, off + payload.size)
            val consumed = st.remoteConsumed + payload.size
            val threshold = (tunnelWindow / 2).coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
            if (consumed >= threshold) {
                st.remoteConsumed = 0
                sendFrameQuiet(RrpFrame.Window(st.id, consumed.toLong()))
            } else {
                st.remoteConsumed = consumed
            }
        } catch (e: IOException) {
            closeStream(frame.streamId, notify = true)
        }
    }

    internal fun RrpClient.closeStream(id: Long, errCode: Int = RrpClient.ERR_GENERAL, notify: Boolean) {
        val st = streams.remove(id) ?: return
        st.closed.set(true)
        closeQuietly(st.socket)
        if (notify) sendFrameQuiet(RrpFrame.Close(id, errCode))
    }

    internal fun RrpClient.closeStreamInternal(st: RrpClient.Stream) {
        streams.remove(st.id)?.let {
            it.closed.set(true)
            it.outBuf.clear() // канон Buffer/1: окончательное закрытие → очистка
            closeQuietly(it.socket)
        }
    }

    internal fun RrpClient.sendOpenOk(streamId: Long, errCode: Int) {
        sendFrameQuiet(RrpFrame.OpenOk(streamId, errCode))
    }

    // ------------------------------------------------------------------ UDP (v0.7)

    /** v1.0.0: гейт UDP-релея (галочка владельца в APK; живая сессия тоже). */
