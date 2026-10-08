// Package serverapp wires config, PKI, auth, hub, inbound and admin API
// into a runnable server.
package serverapp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/stelgen/reverseray/server/internal/auth"
	"github.com/stelgen/reverseray/server/internal/config"
	"github.com/stelgen/reverseray/server/internal/hardening"
	"github.com/stelgen/reverseray/server/internal/hub"
	"github.com/stelgen/reverseray/server/internal/inbound"
	"github.com/stelgen/reverseray/server/internal/modules"
	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
	"github.com/stelgen/reverseray/server/internal/tlscert"
)

// Version is set via -ldflags at build time.
var Version = "dev"

// Metrics is a minimal Prometheus-style counter set (stdlib only).
type Metrics struct {
	TunnelsUp    atomic.Int64
	StreamsOpen  atomic.Int64
	AuthFailures atomic.Int64
	AuthOK       atomic.Int64
	InboundConns atomic.Int64
	BytesRelayed atomic.Uint64
	Reconnects   atomic.Uint64
	WsTunnels    atomic.Int64
	// v0.8 hardening: WAN-атаки видимы в метриках (без IP и содержимого).
	HardeningScans   atomic.Uint64 // соединений классифицировано как скан/мусор
	HardeningDropped atomic.Uint64 // из них tarpit/тихо закрыто
	HardeningLimited atomic.Uint64 // отклонено лимитами параллельности
	ProtoSessions    atomic.Int64  // сессий с протоколом != rrp1 (например mtproto2)
}

// addInbound регистрирует inbound для метрик UDP (вызывается в Run).
func (a *App) addInbound(i *inbound.Inbound) {
	a.inbMu.Lock()
	a.inbounds = append(a.inbounds, i)
	a.inbMu.Unlock()
}

// udpDatagrams суммирует счётчики всех инбоксов.
func (a *App) udpDatagrams() uint64 {
	a.inbMu.Lock()
	defer a.inbMu.Unlock()
	var n uint64
	for _, i := range a.inbounds {
		n += i.UdpDatagrams.Load()
	}
	return n
}

// App is the assembled server.
type App struct {
	cfg    *config.Config
	log    *slog.Logger
	store  *auth.Store
	hub    *hub.Hub
	bundle *tlscert.Bundle
	met    *Metrics
	// egress — кешированный внешний IP сервера для /status и веб-морды
	egress egressIP

	// v0.8: hardening-гейт туннельного порта + синхронизатор модулей
	hardSt  *hardening.Stats
	gate    *hardening.Gate
	modSync *modules.Syncer

	inbMu    sync.Mutex
	inbounds []*inbound.Inbound

	// bootstrapToken не пуст, если tokens.json недоступен для записи:
	// устройство phone-1 живёт в памяти; reloadLoop допишет файл при
	// первой возможности (самовосстановление после починки прав).
	bootstrapToken string
}

// New assembles the app.
func New(cfg *config.Config, log *slog.Logger) (*App, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	store := auth.New()
	store.SetHandshakeLimit(cfg.Limits.HandshakesPerMin)
	var bootstrapToken string // задан, если устройство живёт только в памяти
	if err := store.LoadFile(cfg.TokensFile); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("tokens: %w", err)
		}
		// Первый запуск: сервер сам создаёт дефолтное устройство phone-1.
		// Ошибка записи НЕ фатальна (v0.7.1: фикс crash-loop "permission
		// denied"): токен регистрируется в памяти и печатается в лог.
		tok, _, berr := ensureDefaultDevice(cfg, log)
		if berr != nil {
			return nil, fmt.Errorf("tokens after bootstrap: %w", berr)
		}
		if lerr := store.LoadFile(cfg.TokensFile); lerr != nil {
			if tok == "" {
				return nil, fmt.Errorf("tokens after bootstrap: %w", lerr)
			}
			// Деградация: работаем с токеном в памяти до починки прав.
			store.UpsertDevice("phone-1", auth.HashToken(tok))
			bootstrapToken = tok
		}
	}
	// v0.8.1: SAN лист-сертификата — TLSHosts + PublicHost (DDNS-имя):
	// коннект по DNS-имени и по IP равноправны, оба адреса в сертификате.
	tlsHosts := dedupNonEmpty(append([]string{}, cfg.Listen.TLSHosts...), cfg.PublicHost)
	bundle, err := tlscert.LoadOrCreate(cfg.StateDir, tlsHosts)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	if bundle.Ephemeral {
		log.Warn("PKI is EPHEMERAL: state dir not writable — CA pin changes on every restart (clients need re-enroll); fix: compose user 0:0 or chown state dir to 65532")
	}
	log.Info("PKI ready",
		"ca_pin", bundle.CAPin,
		"leaf_not_after", bundle.Leaf.Leaf.NotAfter.UTC().Format(time.RFC3339),
		"tls_hosts", tlsHosts)
	hardSt := &hardening.Stats{}
	gate := hardening.NewGate(cfg.Hardening.Enabled, cfg.Hardening.TarpitSec,
		cfg.Hardening.MaxConns, cfg.Hardening.PerIPConns, hardSt)
	gate.Logf = func(f string, args ...any) {
		if cfg.Log.Redact {
			log.Info("hardening: non-TLS probe tarpitted (ip redacted)")
			return
		}
		log.Info(fmt.Sprintf(f, args...))
	}
	modSync := modules.NewSyncer(modules.ModulesConfig{
		URL:        cfg.Modules.URL,
		Auto:       cfg.Modules.Auto,
		CheckHours: cfg.Modules.CheckHours,
	}, log, cfg.StateDir)
	log.Info("hardening gate up", "profile", gate.Describe())
	return &App{
		cfg:            cfg,
		log:            log,
		store:          store,
		hub:            hub.New(),
		bundle:         bundle,
		met:            &Metrics{},
		bootstrapToken: bootstrapToken,
		hardSt:         hardSt,
		gate:           gate,
		modSync:        modSync,
	}, nil
}

// dedupNonEmpty — уникальные непустые строки (SAN: TLSHosts + PublicHost).
func dedupNonEmpty(in []string, extra ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in)+len(extra))
	for _, s := range append(in, extra...) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// CAPin exposes the CA SPKI pin for `enroll`.
func (a *App) CAPin() string { return a.bundle.CAPin }

// Devices lists known device names (для тестов bootstrap).
func (a *App) Devices() []string { return a.store.Devices() }

// Run starts all listeners and blocks until ctx or a signal stops it.
func (a *App) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go a.reloadLoop(ctx)
	go a.logConnectInfo(ctx)
	// v0.8: фоновая синхронизация модулей (первый прогон при старте)
	if a.cfg.Modules.Auto {
		go a.modSync.Run(ctx)
		// манифест, скачанный/сохранённый ранее, применяется сразу
		if m := a.modSync.Cached(); m != nil {
			rrp.SetRegistry(m.ProtocolRegistry(), m.Version)
			a.log.Info("modules: cached manifest applied", "version", m.Version, "protocols", m.EnabledProtocolIDs())
		}
	}

	errCh := make(chan error, 4)

	if ln := a.cfg.Listen.Tunnels; ln != "" {
		raw, err := net.Listen("tcp", ln)
		if err != nil {
			return fmt.Errorf("tunnels listen: %w", err)
		}
		a.log.Info("tunnel listener up", "addr", ln)
		go a.acceptTunnels(raw)
	}
	for _, spec := range []struct{ name, addr string }{
		{"mixed", a.cfg.Listen.Mixed},
		{"socks", a.cfg.Listen.Socks},
		{"http", a.cfg.Listen.HTTP},
	} {
		if spec.addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", spec.addr)
		if err != nil {
			return fmt.Errorf("%s listen: %w", spec.name, err)
		}
		a.log.Info("inbound up", "kind", spec.name, "addr", spec.addr)
		inb := a.inbound(ln)
		a.addInbound(inb)
		go func(i *inbound.Inbound, l net.Listener) {
			errCh <- i.Serve(l)
		}(inb, ln)
	}

	if addr := a.cfg.Listen.AdminTCP; addr != "" {
		mux := http.NewServeMux()
		a.mountAdmin(mux)
		al, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("admin listen: %w", err)
		}
		a.log.Info("admin up", "addr", addr)
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() { errCh <- srv.Serve(al) }()
		defer srv.Close()
	}
	if sock := a.cfg.Listen.AdminUnix; sock != "" {
		_ = os.Remove(sock)
		ul, err := net.Listen("unix", sock)
		if err != nil {
			return fmt.Errorf("admin unix listen: %w", err)
		}
		_ = os.Chmod(sock, 0o600)
		mux := http.NewServeMux()
		a.mountAdmin(mux)
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() { errCh <- srv.Serve(ul) }()
		defer func() { srv.Close(); os.Remove(sock) }()
	}
	if p := os.Getenv("RR_PPROF"); p != "" {
		m := http.NewServeMux()
		m.HandleFunc("/debug/pprof/", pprof.Index)
		m.HandleFunc("/debug/pprof/heap", pprof.Index)
		srv := &http.Server{Addr: p, Handler: m, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
		go func() { _ = srv.ListenAndServe() }()
		a.log.Info("pprof on", "addr", p)
	}

	a.log.Info("reverseray started", "version", Version)
	select {
	case <-ctx.Done():
		a.log.Info("shutdown")
		return nil
	case err := <-errCh:
		return err
	}
}

func (a *App) reloadLoop(ctx context.Context) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	defer signal.Stop(sig)

	// Автоподхват изменений tokens.json: enroll дописывает токен в файл,
	// сервер перечитывает его без SIGHUP (mtime poll каждые 3 с).
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var lastMod time.Time
	tokensPath := a.tokensPath()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sig:
			if err := a.Reload(); err != nil {
				a.log.Warn("SIGHUP reload failed", "err", err)
			}
		case <-ticker.C:
			// Самовосстановление: если bootstrap жил в памяти (нет прав на
			// запись) — дописываем tokens.json тем же токеном, как только
			// каталог стал записываемым.
			if a.bootstrapToken != "" && a.tryPersistBootstrapToken() {
				a.log.Info("bootstrap: tokens.json persisted (state dir writable now)")
			}
			if fi, err := os.Stat(tokensPath); err == nil {
				mod := fi.ModTime()
				if !mod.Equal(lastMod) {
					first := lastMod.IsZero()
					lastMod = mod
					if !first {
						if err := a.Reload(); err != nil {
							a.log.Warn("tokens auto-reload failed", "err", err)
						} else {
							a.log.Info("tokens auto-reloaded (file changed)")
						}
					}
				}
			}
		}
	}
}

// tokensPath возвращает путь к tokens.json (stateDir из конфигурации).
func (a *App) tokensPath() string {
	return a.cfg.TokensFile
}

// tryPersistBootstrapToken дописывает in-memory устройство в tokens.json.
// true — удалось (и стор перечитан).
func (a *App) tryPersistBootstrapToken() bool {
	if _, err := os.Stat(a.cfg.TokensFile); err == nil {
		return false // файл уже есть (написан кем-то другим) — не трогаем
	}
	hash := auth.HashToken(a.bootstrapToken)
	hashB64 := base64.RawURLEncoding.EncodeToString(hash[:])
	doc := struct {
		Devices map[string]string `json:"devices"`
	}{Devices: map[string]string{"phone-1": hashB64}}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false
	}
	if err := os.WriteFile(a.cfg.TokensFile, append(out, '\n'), 0o600); err != nil {
		return false
	}
	if err := a.Reload(); err != nil {
		return false
	}
	a.bootstrapToken = ""
	return true
}

// Reload re-reads tokens (SIGHUP path) without dropping tunnels.
func (a *App) Reload() error {
	st := auth.New()
	if err := st.LoadFile(a.cfg.TokensFile); err != nil {
		return err
	}
	st.SetHandshakeLimit(a.cfg.Limits.HandshakesPerMin)
	a.store = st
	a.log.Info("tokens reloaded", "devices", st.Devices())
	return nil
}

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
		go a.handleTunnelRaw(conn)
	}
}

func (a *App) tunnelTLSConfig() *tls.Config {
	// Present [leaf, CA] so clients can verify against the pinned CA SPKI.
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
		SessionID:    sid,
		ServerVer:    Version,
		Nonce:        nonce,
		TunnelWindow: toU32(a.cfg.Limits.StreamWindow) * 4,
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
	scfg.IdleTimeout = a.cfg.IdleTimeout()
	scfg.PingInterval = a.cfg.PingInterval()
	scfg.Protocol = proto
	scfg.ProbeDialer = a.probeDialer()

	_ = tc.SetDeadline(time.Time{})
	if err := writeJSONTyped(framed, rrp.TypeReady, &rrp.Ready{
		TunnelID:     sid,
		Role:         "active",
		MaxStreams:   scfg.MaxStreams,
		TunnelWindow: toU32(a.cfg.Limits.StreamWindow) * 4,
		Proto:        proto,
		Protocols:    rrp.SupportedIDs(),
	}); err != nil {
		_ = framed.Close()
		return
	}

	// v0.8: протокол mtproto2 — ПОСЛЕ READY (клиент ждёт READY, потом KEY_REQ)
	// ключи туннеля перегенерируются DH-обменом и DATA/UDP_DATA уходят
	// в MTProto 2.0-конверте (AES-256-IGE, см. internal/mtproto).
	if proto == mtproto.ProtoID {
		// дедлайн на обмен ключами: битый клиент не висит горутиной вечно
		_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
		upgraded, uerr := mtproto.UpgradeServer(framed, sid, a.log)
		if uerr != nil {
			a.log.Warn("mtproto upgrade failed", "device", device, "err", uerr)
			a.rejectHandshake(ip, framed, "protocol error")
			return
		}
		framed = upgraded
		a.met.ProtoSessions.Add(1)
		defer a.met.ProtoSessions.Add(-1)
		_ = tc.SetDeadline(time.Time{}) // дальше сессия ставит свои таймауты
		a.log.Info("mtproto2 transport engaged", "device", device, "session", sid)
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
		"proto", proto, "proto_label", rrp.Label(proto), "proto_ver", rrp.Ver(proto))
	defer func() {
		a.hub.Detach(device, sess)
		a.met.TunnelsUp.Add(-1)
		a.log.Info("tunnel closed", "device", device, "session", sid)
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

// ---- inbound ----

func (a *App) inbound(ln net.Listener) *inbound.Inbound {
	pass, err := a.cfg.LoadPassword()
	if err != nil {
		a.log.Warn("inbound password file unreadable; starting without inbound auth", "err", err)
	}
	return &inbound.Inbound{
		Dialer:      a.hub,
		Username:    a.cfg.Auth.Username,
		Password:    pass,
		Allowlist:   parseAllowlist(a.cfg.Allowlist),
		DialTimeout: a.cfg.DialTimeout(),
		UDPBindPort: udpBindPort(a.cfg.Listen.Mixed),
		Logf: func(f string, args ...any) {
			if a.cfg.Log.Redact {
				a.log.Info("inbound event redacted")
				return
			}
			a.log.Info(fmt.Sprintf(f, args...))
		},
	}
}

func parseAllowlist(specs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range specs {
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ---- admin ----

func (a *App) mountAdmin(mux *http.ServeMux) {
	a.mountUI(mux)
	mux.HandleFunc("/healthz", a.safeHandler("healthz", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})))
	mux.HandleFunc("/readyz", a.safeHandler("readyz", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if len(a.store.Devices()) == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"ready":false,"reason":"no tokens loaded"}`)
			return
		}
		fmt.Fprint(w, `{"ready":true}`)
	})))
	mux.HandleFunc("/metrics", a.safeHandler("metrics", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m := a.met
		fmt.Fprintf(w, "# HELP reverseray_tunnels_up active tunnels\n# TYPE reverseray_tunnels_up gauge\nreverseray_tunnels_up %d\n", m.TunnelsUp.Load())
		fmt.Fprintf(w, "# HELP reverseray_streams_open open streams\n# TYPE reverseray_streams_open gauge\nreverseray_streams_open %d\n", m.StreamsOpen.Load())
		fmt.Fprintf(w, "# HELP reverseray_auth_failures_total auth failures\n# TYPE reverseray_auth_failures_total counter\nreverseray_auth_failures_total %d\n", m.AuthFailures.Load())
		fmt.Fprintf(w, "# HELP reverseray_auth_ok_total successful auths\n# TYPE reverseray_auth_ok_total counter\nreverseray_auth_ok_total %d\n", m.AuthOK.Load())
		fmt.Fprintf(w, "# HELP reverseray_inbound_conns_total inbound connections\n# TYPE reverseray_inbound_conns_total counter\nreverseray_inbound_conns_total %d\n", m.InboundConns.Load())
		fmt.Fprintf(w, "# HELP reverseray_reconnects_total tunnel connects\n# TYPE reverseray_reconnects_total counter\nreverseray_reconnects_total %d\n", m.Reconnects.Load())
		fmt.Fprintf(w, "# HELP reverseray_udp_datagrams_total udp datagrams through tunnel\n# TYPE reverseray_udp_datagrams_total counter\nreverseray_udp_datagrams_total %d\n", a.udpDatagrams())
		fmt.Fprintf(w, "# HELP reverseray_ws_tunnels active websocket tunnels\n# TYPE reverseray_ws_tunnels gauge\nreverseray_ws_tunnels %d\n", m.WsTunnels.Load())
		// v0.8: hardening (анти-скан) и модули — наблюдаемость WAN-защиты
		fmt.Fprintf(w, "# HELP reverseray_hardening_scans_total non-TLS probes classified as scans\n# TYPE reverseray_hardening_scans_total counter\nreverseray_hardening_scans_total %d\n", m.HardeningScans.Load())
		fmt.Fprintf(w, "# HELP reverseray_hardening_dropped_total non-TLS probes tarpitted/closed silently\n# TYPE reverseray_hardening_dropped_total counter\nreverseray_hardening_dropped_total %d\n", m.HardeningDropped.Load())
		fmt.Fprintf(w, "# HELP reverseray_hardening_limited_total connections rejected by concurrency limits\n# TYPE reverseray_hardening_limited_total counter\nreverseray_hardening_limited_total %d\n", m.HardeningLimited.Load())
		fmt.Fprintf(w, "# HELP reverseray_proto_sessions_non_default sessions on non-default protocol\n# TYPE reverseray_proto_sessions_non_default gauge\nreverseray_proto_sessions_non_default %d\n", m.ProtoSessions.Load())
		if a.modSync != nil {
			fmt.Fprintf(w, "# HELP reverseray_modules_version modules manifest version\n# TYPE reverseray_modules_version gauge\nreverseray_modules_version{version=%q} 1\n", a.modSync.ActiveVersion())
			fmt.Fprintf(w, "# HELP reverseray_modules_last_check_success last modules sync ok\n# TYPE reverseray_modules_last_check_success gauge\nreverseray_modules_last_check_success %d\n", boolToInt(a.modSync.LastCheckOK()))
		}
	})))
	mux.HandleFunc("/sessions", a.safeHandler("sessions", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a.hub.Snapshot())
	})))
	mux.HandleFunc("/tokens/reload", a.safeHandler("tokens_reload", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		if err := a.Reload(); err != nil {
			// текст ошибки ТОЛЬКО в лог — наружу без деталей (canon: ноль утечек)
			a.log.Warn("tokens reload failed", "err", err)
			http.Error(w, "reload failed", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "reloaded")
	})))
	// v0.8: статус модулей (версия, протоколы, последний чек) — только чтение
	mux.HandleFunc("/modules", a.safeHandler("modules", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if a.modSync == nil {
			fmt.Fprint(w, `{"enabled":false}`)
			return
		}
		_ = json.NewEncoder(w).Encode(a.modSync.Status())
	})))
	mux.HandleFunc("/devices/kick", a.safeHandler("devices_kick", secureHeaders(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("device")
		if name == "" || containsAny(name, "..", "/", "\\") {
			http.Error(w, "bad device", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "kicked %d sessions", a.hub.Kick(name)) // #nosec G705: name не выводится в ответ, только валидируется
	})))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// toU32 — безопасная конверсия конфиг-лимитов (gosec G115): отрицательное -> 0, >MaxUint32 -> MaxUint32.
func toU32(v int) uint32 {
	if v <= 0 {
		return 0
	}
	if uint64(v) > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---- helpers ----

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

func readJSON[T any](r interface{ Read([]byte) (int, error) }) (T, error) {
	var zero T
	f, err := rrp.ReadFrame(r)
	if err != nil {
		return zero, err
	}
	if f.Type != rrp.TypeHello && f.Type != rrp.TypeAuth {
		return zero, rrp.ErrProtocolOrder
	}
	var v T
	if err := json.Unmarshal(f.Payload, &v); err != nil {
		return zero, fmt.Errorf("json: %w", err)
	}
	return v, nil
}

func writeJSONTyped(w interface{ Write([]byte) (int, error) }, t uint8, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return rrp.WriteFrame(w, t, 0, 0, b)
}

// tokenHashHex is used by enroll.
func tokenHashHex(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}
