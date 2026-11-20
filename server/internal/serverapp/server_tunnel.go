// Package serverapp — зона «Туннельная сторона» (приём TLS/ALPN-коннектов,
// рукопожатие RAW/ws-транспорта, rejects). Pure move из server.go (v1.8.3,
// дробление по зонам ответственности — поведение не меняется).
package serverapp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/stelgen/reverseray/server/internal/bt"
	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
	"github.com/stelgen/reverseray/server/internal/wg"
)

// ---- tunnel side ----

func (a *App) acceptTunnels(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			a.log.Warn("tunnel accept", "err", err)
			return
		}
		tuneTCP(conn)
		go a.handleTunnelRaw(conn)
	}
}

// tuneTCP (v0.9.6, скорость rrp1): TCP_NODELAY (мелкие кадры DATA/PING не
// ждут Nagle — до 40мс задержки на кадр в WAN) и увеличенные сокет-буферы
// (throughput на LRTT-линках). Ошибки тихо: это best-effort тюнинг.
func tuneTCP(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(512 * 1024)
		_ = tc.SetWriteBuffer(512 * 1024)
	}
}

func (a *App) tunnelTLSConfig() *tls.Config {
	// Present [leaf, CA] so clients can verify against the pinned CA SPKI.
	// v1.7.0: лист читается под RLock — перевыпуск подменяет его атомарно,
	// живые коннекты не рвутся, новые идут уже с обновлённым листом.
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	leaf := a.bundle.Leaf
	chain := make([][]byte, 0, 2)
	chain = append(chain, leaf.Certificate...)
	chain = append(chain, a.bundle.CA.Raw)
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: chain,
			PrivateKey:  leaf.PrivateKey,
			Leaf:        leaf.Leaf,
		}},
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"reverseray/1"},
	}
}

// handleTunnelRaw — входная точка: hardening-гейт до TLS (v0.8).
// Сканеры/мусор здесь заканчиваются тишиной, реальные TLS-клиенты — далее.
func (a *App) handleTunnelRaw(raw net.Conn) {
	defer a.recoverGoroutine("handleTunnelRaw")
	ip := remoteIP(raw)
	if !a.gate.Admit(ip) {
		_ = raw.Close()
		return
	}
	defer a.gate.Release(ip)
	conn, ok := a.gate.Classify(raw)
	if !ok {
		return // tarpit/тихое закрытие: ни одного ответного байта
	}
	if a.hardSt != nil {
		a.met.HardeningScans.Store(a.hardSt.Scans.Load())
		a.met.HardeningDropped.Store(a.hardSt.Dropped.Load())
		a.met.HardeningLimited.Store(a.hardSt.Limited.Load())
	}
	if !a.store.AllowHandshake(ip) {
		a.met.AuthFailures.Add(1)
		_ = conn.Close()
		return
	}
	a.handleTunnel(conn)
}

func (a *App) handleTunnel(conn net.Conn) {
	defer a.recoverGoroutine("handleTunnel")
	ip := remoteIP(conn)
	conn = tls.Server(conn, a.tunnelTLSConfig())

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	tc := conn.(*tls.Conn)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		// мусорный TLS из WAN — только метрика: lockout за это лочил бы
		// легитимных клиентов за общим NAT по вине одного сканера
		a.met.AuthFailures.Add(1)
		_ = conn.Close()
		return
	}

	// ALPN: require reverseray/1 when the client offers any ALPN. Some legacy
	// pure-Java stacks (BC on API 14) cannot send ALPN — accept no-ALPN, keep the
	// strict gate for ALPN-capable clients.
	if alpn := tc.ConnectionState().NegotiatedProtocol; alpn != "" && alpn != "reverseray/1" {
		a.met.AuthFailures.Add(1)
		_ = conn.Close()
		return
	}

	// Транспорт поверх одного TLS-порта (v0.7): HTTP GET в начале потока —
	// WebSocket-апгрейд /rrp, иначе — сырой RRP/1 (старые клиенты).
	br := bufio.NewReaderSize(tc, 32*1024)
	var framed io.ReadWriteCloser = &bufferedConn{r: br, w: tc, c: tc}
	transport := "tcp"
	if rrp.IsWsPeek(br) {
		wsc, werr := rrp.WsHandshakeServer(tc, br)
		if werr != nil {
			a.met.AuthFailures.Add(1)
			a.log.Warn("websocket handshake failed", "err", werr)
			return
		}
		framed = wsc
		transport = "ws"
		a.met.WsTunnels.Add(1)
		defer a.met.WsTunnels.Add(-1)
	}

	hello, err := readJSON[*rrp.Hello](framed)
	if err != nil || hello == nil || hello.Device == "" || len(hello.Device) > 64 {
		a.rejectHandshake(ip, framed, "bad HELLO")
		return
	}
	// Согласование протокола: мусор от клиента сводится к дефолту, никогда не ошибка.
	proto := rrp.Negotiate(hello.Proto.String(), hello.Protocols, a.cfg.DefaultProtocol)
	nonce, err := rrp.NewNonce()
	if err != nil {
		_ = conn.Close()
		return
	}
	sid := rrp.NewID()
	writeJSONTyped(framed, rrp.TypeHelloOK, &rrp.HelloOK{
		SessionID: sid,
		ServerVer: Version,
		Nonce:     nonce,
		// v0.9.3 (канон flow-control): кредит телефона ≤ буферу приёма.
		// Буфер DATA на стрим — capIn 1МБ (session.go pushIn, анти-абьюз);
		// кредит больше буфера = медленный читатель убивает стрим close(4)
		// и рвёт закачку. StreamWindow*2 = 1МБ при дефолте 512КБ — ровно capIn,
		// честный клиент (Kotlin Semaphore) capIn достичь не может.
		TunnelWindow: toU32(a.cfg.Limits.StreamWindow) * 2,
		Proto:        proto,
		Protocols:    rrp.SupportedIDs(),
	})
	a.store.PutNonce(nonce, 60*time.Second)

	au, err := readJSON[*rrp.Auth](framed)
	if err != nil || au == nil || au.Mode != "token-hmac" {
		a.rejectHandshake(ip, framed, "bad AUTH")
		return
	}
	device, ok := a.store.Verify(nonce, sid, au.HMAC)
	if !ok {
		a.rejectHandshake(ip, conn, "auth failed")
		return
	}
	a.store.ResetFailures(ip)
	a.met.AuthOK.Add(1)

	scfg := rrp.DefaultSessionConfig()
	scfg.MaxStreams = a.cfg.Limits.MaxStreams
	scfg.StreamWindow = toU32(a.cfg.Limits.StreamWindow)
	scfg.MaxStreamWin = toU32(a.cfg.Limits.MaxStreamWindow)
	scfg.Budget = int64(a.cfg.Limits.DeviceBudget)
	// v1.2.0: тот же стартовый грант, что уходит в HELLO_OK/READY tunnel_window —
	// rrp-сессия должна знать, каким окном реально располагает телефон.
	scfg.TunnelWindow = toU32(a.cfg.Limits.StreamWindow) * 2
	scfg.IdleTimeout = a.cfg.IdleTimeout()
	scfg.PingInterval = a.cfg.PingInterval()
	scfg.Protocol = proto
	// v1.6.0: proto=apimask — камуфляж «API Mask» КАК ПРОТОКОЛ (изначальный
	// замысел): персистентно включаем камуфляж устройства (cam-override=ON),
	// READY заявляет features=["apimask"], NOISE ходят в обе стороны.
	// Явное «выкл» клиента (0x2A) уважаем — не включаем обратно (канон).
	if proto == rrp.ProtocolAPIMask.ID {
		if !a.CamouflageOverrides()[device] {
			a.setCamouflageOverride(device, true)
		}
		a.log.Info("rrp: apimask negotiated as protocol — camouflage ON", "device", device, "session", sid)
	}
	scfg.ProbeDialer = a.probeDialer()
	// v0.9.2: обмен ключами mtproto2 — ВНУТРИ сессии (KEY_REQ уходит после
	// старта Run, KEY_RESP читается Session.handle). Прежняя схема
	// (UpgradeServer в рукопожатии) гонялась с клиентским PROBE за один
	// сокет: PROBE мог быть съеден апгрейдом → «protocol error» на клиенте.
	if proto == mtproto.ProtoID {
		scfg.KeyPlan = mtproto.NewServerPlan(sid, a.log)
	}
	// v0.9.5: wireguard — настоящий Noise_IKpsk2-хендшейк внутри приватного
	// канала. PSK = SHA256(token) устройства (наш ключ доверия): WG-хендшейк
	// привязан к токену, данные — ChaCha20-Poly1305 со sliding-window.
	if proto == wg.ProtoID {
		if th := a.store.HashOf(device); len(th) == 32 {
			if plan, err := wg.NewServerPlan(sid, th, a.log); err == nil {
				scfg.KeyPlan = plan
			}
		}
	}
	// v0.10: bittorrent — канонный MSE/PE-хендшейк внутри приватного канала.
	// SKEY = SHA1("reverseray-bt:"+tokenHash) — «инфо-хеш торрента» устройства;
	// payload'ы — peer-wire piece-сообщения (для DPI — как BitTorrent).
	if proto == bt.ProtoID {
		if th := a.store.HashOf(device); len(th) == 32 {
			if plan, err := bt.NewServerPlan(sid, th, a.log); err == nil {
				scfg.KeyPlan = plan
			}
		}
	}
	// v0.10: бесшовная смена протокола (кадр 0x2C) — план целевого протокола
	// строится на месте, крипта подменяется атомарно по завершении обмена;
	// соединение и стримы переживают смену (паркинг payload-кадров).
	scfg.TokenHash = a.store.HashOf(device)
	scfg.Switchable = true
	scfg.SwitchPlanner = func(target string) (rrp.KeyPlan, error) {
		return a.switchKeyPlan(sid, device, target)
	}
	// v0.9.5: управление камуфляжем с клиента (0x2A) — персистентный выбор.
	scfg.CamCtl = func(enabled bool) {
		a.setCamouflageOverride(device, enabled)
	}
	// v1.8.0: учёт протокола apimask — метрики без IP/содержимого
	scfg.NoiseHook = func(req, resp int) {
		a.met.ApimaskPairs.Add(1)
		a.met.ApimaskBytes.Add(uint64(req + resp)) // #nosec G115: req/resp ≤ MaxControlPayload
	}

	_ = tc.SetDeadline(time.Time{})
	if err := writeJSONTyped(framed, rrp.TypeReady, &rrp.Ready{
		TunnelID:   sid,
		Role:       "active",
		MaxStreams: scfg.MaxStreams,
		// v0.9.3 (канон flow-control): кредит телефона ≤ буферу приёма.
		// Буфер DATA на стрим — capIn 1МБ (session.go pushIn, анти-абьюз);
		// кредит больше буфера = медленный читатель убивает стрим close(4)
		// и рвёт закачку. StreamWindow*2 = 1МБ при дефолте 512КБ — ровно capIn,
		// честный клиент (Kotlin Semaphore) capIn достичь не может.
		TunnelWindow: toU32(a.cfg.Limits.StreamWindow) * 2,
		Proto:        proto,
		Protocols:    rrp.SupportedIDs(),
		// v0.9.5: если клиент выключил apimask для этого устройства — features
		// не заявляем (и локально, и в будущих сессиях: выбор персистентен).
		// v1.6.0: proto=apimask — камуфляж КАК ПРОТОКОЛ: feature заявляем
		// ВСЕГДА для такой сессии, независимо от состояния манифеста.
		Features: func() []string {
			f := a.featuresFor(device)
			if proto == rrp.ProtocolAPIMask.ID && len(f) == 0 {
				f = []string{rrp.ProtocolAPIMask.ID}
			}
			return f
		}(),
	}); err != nil {
		_ = framed.Close()
		return
	}

	// v0.8/v0.9.2: mtproto2 — ключи перегенерируются DH-обменом ПОСЛЕ READY,
	// DATA/UDP_DATA уходят в MTProto 2.0-конверте (AES-256-IGE). Обмен ключами
	// и включение крипты теперь живут в rrp.Session (KeyPlan): рукопожатие
	// завершено, reject «protocol error» из-за гонки PROBE/KEY_RESP невозможен.
	if proto == mtproto.ProtoID || proto == wg.ProtoID || proto == bt.ProtoID {
		a.met.ProtoSessions.Add(1)
		defer a.met.ProtoSessions.Add(-1)
	}
	// v1.3.0: Logf для ВСЕХ сессий — ключевые события (обмен ключами, смена
	// протокола, паркинг) идут и в slog, и в кольцевой журнал веб-морды.
	scfg.Logf = func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		a.log.Info(msg, "device", device, "session", sid)
		a.ev.AddDev("info", "proto", msg, device)
	}
	// v1.3.0 «буфер трафика»: клиент объявил cap stream-resume в HELLO.
	for _, c := range hello.Caps {
		if c == "stream-resume" {
			scfg.ResumeCapable = true
			break
		}
	}
	// v0.9.2: честный лог даунгрейда — клиент попросил протокол, заявленный
	// в реестре, но не исполняемый этой сборкой (модуль прилетел раньше кода).
	if req := hello.Proto.String(); req != "" && rrp.IsSupported(req) && !rrp.IsExecutable(req) && proto != req {
		a.log.Warn("requested protocol is advertised but not executable on this build — negotiated default",
			"device", device, "requested", req, "negotiated", proto)
	}

	sess := rrp.NewSession(sid, device, framed, scfg)
	if err := a.hub.Attach(device, sess, a.cfg.Limits.MaxTunnelsPerDevice); err != nil {
		a.log.Warn("attach rejected", "device", device, "err", err)
		writeJSONTyped(framed, rrp.TypeHelloOK, map[string]string{"error": err.Error()})
		_ = framed.Close()
		return
	}
	a.met.TunnelsUp.Add(1)
	a.met.Reconnects.Add(1)
	a.log.Info("tunnel ready", "device", device, "session", sid, "transport", transport,
		"proto", proto, "proto_label", rrp.Label(proto), "proto_ver", rrp.Ver(proto), "camo_label", rrp.CamouflageLabel())
	a.ev.AddDev("info", "tunnel", "туннель подключён: "+rrp.Label(proto)+" · транспорт "+transport, device)
	defer func() {
		a.hub.Detach(device, sess)
		a.met.TunnelsUp.Add(-1)
		// v1.8.4: честная причина закрытия — молчаливое «tunnel closed»
		// мешало отладке (битый конверт после свитча не был виден).
		if cerr := sess.Err(); cerr != nil && !errors.Is(cerr, net.ErrClosed) &&
			cerr.Error() != "session ended" {
			a.log.Warn("tunnel closed with error", "device", device, "session", sid, "err", cerr.Error())
		}
		a.log.Info("tunnel closed", "device", device, "session", sid)
		a.ev.AddDev("warn", "tunnel", "туннель отключён — активные потоки в буфере, ожидание реконнекта", device)
	}()
	sess.Run()
}

// probeDialer возвращает диалер для PROBE-валидации (реальный egress сервера).
// PROBE — единичный TCP-коннект; цели клиента не логируются (redact by default).
func (a *App) probeDialer() func(ctx context.Context, target string, timeout time.Duration) error {
	return func(ctx context.Context, target string, timeout time.Duration) error {
		var d net.Dialer
		if timeout > 0 && timeout < a.cfg.DialTimeout() {
			d.Timeout = timeout
		} else {
			d.Timeout = a.cfg.DialTimeout()
		}
		c, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			return err
		}
		_ = c.Close() // достаточно факта установки TCP-соединения
		return nil
	}
}

func (a *App) rejectHandshake(ip string, framed io.ReadWriteCloser, why string) {
	a.met.AuthFailures.Add(1)
	// v1.3.0: классификация в журнале морды — сканерный шум не должен
	// выглядеть как авария; реальный источник виден в slog по IP.
	a.ev.Add("info", "auth", "рукопожатие отклонено: "+why+" (сканер или устаревший клиент)")
	// lockout — только за невалидный HMAC (брутфорс токена); прочие ошибки
	// рукопожатия (сканеры, кривые клиенты) не должны лочить NAT-клиентов
	locked := false
	if why == "auth failed" {
		locked = a.store.ReportFailure(ip)
	}
	a.log.Warn("tunnel handshake rejected", "ip", ip, "why", why, "locked", locked)
	var payload []byte
	if why == "auth failed" {
		payload = rrp.EncodeError(0x01, "auth failed")
	} else {
		payload = rrp.EncodeError(0x02, "protocol error")
	}
	_ = rrp.WriteFrame(framed, rrp.TypeError, 0, 0, payload)
	_ = framed.Close()
}

// bufferedConn читает через peek-буфер (WS-детект) и пишет напрямую в TLS-соединение.
type bufferedConn struct {
	r *bufio.Reader
	w io.Writer
	c io.Closer
}

func (b *bufferedConn) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *bufferedConn) Write(p []byte) (int, error) { return b.w.Write(p) }
func (b *bufferedConn) Close() error                { return b.c.Close() }

// udpBindPort выводит порт UDP-сокета SOCKS5-инбокса из listen-адреса mixed.
func udpBindPort(listen string) int {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		if n, perr := strconv.Atoi(port); perr == nil && n > 0 {
			return n
		}
	}
	return 1080
}
