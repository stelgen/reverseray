// Package serverapp wires config, PKI, auth, hub, inbound and admin API
// into a runnable server.
package serverapp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/stelgen/reverseray/server/internal/auth"
	"github.com/stelgen/reverseray/server/internal/config"
	"github.com/stelgen/reverseray/server/internal/hub"
	"github.com/stelgen/reverseray/server/internal/inbound"
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
}

// App is the assembled server.
type App struct {
	cfg    *config.Config
	log    *slog.Logger
	store  *auth.Store
	hub    *hub.Hub
	bundle *tlscert.Bundle
	met    *Metrics
}

// New assembles the app.
func New(cfg *config.Config, log *slog.Logger) (*App, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	store := auth.New()
	if err := store.LoadFile(cfg.TokensFile); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("tokens: %w", err)
		}
		log.Warn("tokens file missing; tunnel auth will reject everyone until SIGHUP with valid tokens.json",
			"path", cfg.TokensFile)
	}
	bundle, err := tlscert.LoadOrCreate(cfg.StateDir, cfg.Listen.TLSHosts)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	log.Info("PKI ready", "ca_pin", bundle.CAPin)
	return &App{
		cfg:    cfg,
		log:    log,
		store:  store,
		hub:    hub.New(),
		bundle: bundle,
		met:    &Metrics{},
	}, nil
}

// CAPin exposes the CA SPKI pin for `enroll`.
func (a *App) CAPin() string { return a.bundle.CAPin }

// Run starts all listeners and blocks until ctx or a signal stops it.
func (a *App) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go a.reloadLoop(ctx)

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
		go func(ln net.Listener) {
			errCh <- a.inbound(ln).Serve(ln)
		}(ln)
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
		go func() { _ = http.ListenAndServe(p, m) }()
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-sig:
			if err := a.Reload(); err != nil {
				a.log.Warn("SIGHUP reload failed", "err", err)
			}
		}
	}
}

// Reload re-reads tokens (SIGHUP path) without dropping tunnels.
func (a *App) Reload() error {
	st := auth.New()
	if err := st.LoadFile(a.cfg.TokensFile); err != nil {
		return err
	}
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
		go a.handleTunnel(conn)
	}
}

// tunnelTLSConfig is shared by the manual TLS wrap in handleTunnel.
func (a *App) tunnelTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{a.bundle.Leaf},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"reverseray/1"},
	}
}

func (a *App) handleTunnel(conn net.Conn) {
	ip := remoteIP(conn)
	if !a.store.AllowHandshake(ip) {
		a.met.AuthFailures.Add(1)
		_ = conn.Close()
		return
	}
	conn = tls.Server(conn, a.tunnelTLSConfig())

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	tc := conn.(*tls.Conn)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		a.met.AuthFailures.Add(1)
		a.store.ReportFailure(ip)
		_ = conn.Close()
		return
	}
	if alpn := tc.ConnectionState().NegotiatedProtocol; alpn != "reverseray/1" {
		a.met.AuthFailures.Add(1)
		_ = conn.Close()
		return
	}

	hello, err := readJSON[*rrp.Hello](conn)
	if err != nil || hello == nil || hello.Device == "" || len(hello.Device) > 64 {
		a.rejectHandshake(ip, conn, "bad HELLO")
		return
	}
	nonce, err := rrp.NewNonce()
	if err != nil {
		_ = conn.Close()
		return
	}
	sid := rrp.NewID()
	writeJSONTyped(conn, rrp.TypeHelloOK, &rrp.HelloOK{
		SessionID:    sid,
		ServerVer:    Version,
		Nonce:        nonce,
		TunnelWindow: uint32(a.cfg.Limits.StreamWindow) * 4,
	})
	a.store.PutNonce(nonce, 60*time.Second)

	au, err := readJSON[*rrp.Auth](conn)
	if err != nil || au == nil || au.Mode != "token-hmac" {
		a.rejectHandshake(ip, conn, "bad AUTH")
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
	scfg.StreamWindow = uint32(a.cfg.Limits.StreamWindow)
	scfg.MaxStreamWin = uint32(a.cfg.Limits.MaxStreamWindow)
	scfg.Budget = int64(a.cfg.Limits.DeviceBudget)
	scfg.IdleTimeout = a.cfg.IdleTimeout()
	scfg.PingInterval = a.cfg.PingInterval()

	sess := rrp.NewSession(sid, device, conn, scfg)
	if err := a.hub.Attach(device, sess, a.cfg.Limits.MaxTunnelsPerDevice); err != nil {
		a.log.Warn("attach rejected", "device", device, "err", err)
		writeJSONTyped(conn, rrp.TypeHelloOK, map[string]string{"error": err.Error()})
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if err := writeJSONTyped(conn, rrp.TypeReady, &rrp.Ready{
		TunnelID:     sid,
		Role:         "active",
		MaxStreams:   scfg.MaxStreams,
		TunnelWindow: uint32(a.cfg.Limits.StreamWindow) * 4,
	}); err != nil {
		_ = sess.Close()
		return
	}
	a.met.TunnelsUp.Add(1)
	a.met.Reconnects.Add(1)
	a.log.Info("tunnel ready", "device", device, "session", sid)
	defer func() {
		a.hub.Detach(device, sess)
		a.met.TunnelsUp.Add(-1)
		a.log.Info("tunnel closed", "device", device, "session", sid)
	}()
	sess.Run()
}

func (a *App) rejectHandshake(ip string, conn net.Conn, why string) {
	a.met.AuthFailures.Add(1)
	locked := a.store.ReportFailure(ip)
	a.log.Warn("tunnel handshake rejected", "ip", ip, "why", why, "locked", locked)
	var payload []byte
	if why == "auth failed" {
		payload = rrp.EncodeError(0x01, "auth failed")
	} else {
		payload = rrp.EncodeError(0x02, "protocol error")
	}
	_ = rrp.WriteFrame(conn, rrp.TypeError, 0, 0, payload)
	_ = conn.Close()
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
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if len(a.store.Devices()) == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"ready":false,"reason":"no tokens loaded"}`)
			return
		}
		fmt.Fprint(w, `{"ready":true}`)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m := a.met
		fmt.Fprintf(w, "# HELP reverseray_tunnels_up active tunnels\n# TYPE reverseray_tunnels_up gauge\nreverseray_tunnels_up %d\n", m.TunnelsUp.Load())
		fmt.Fprintf(w, "# HELP reverseray_streams_open open streams\n# TYPE reverseray_streams_open gauge\nreverseray_streams_open %d\n", m.StreamsOpen.Load())
		fmt.Fprintf(w, "# HELP reverseray_auth_failures_total auth failures\n# TYPE reverseray_auth_failures_total counter\nreverseray_auth_failures_total %d\n", m.AuthFailures.Load())
		fmt.Fprintf(w, "# HELP reverseray_auth_ok_total successful auths\n# TYPE reverseray_auth_ok_total counter\nreverseray_auth_ok_total %d\n", m.AuthOK.Load())
		fmt.Fprintf(w, "# HELP reverseray_inbound_conns_total inbound connections\n# TYPE reverseray_inbound_conns_total counter\nreverseray_inbound_conns_total %d\n", m.InboundConns.Load())
		fmt.Fprintf(w, "# HELP reverseray_reconnects_total tunnel connects\n# TYPE reverseray_reconnects_total counter\nreverseray_reconnects_total %d\n", m.Reconnects.Load())
	})
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a.hub.Snapshot())
	})
	mux.HandleFunc("/tokens/reload", func(w http.ResponseWriter, _ *http.Request) {
		if err := a.Reload(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "reloaded")
	})
	mux.HandleFunc("/devices/kick", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("device")
		if name == "" || containsAny(name, "..", "/", "\\") {
			http.Error(w, "bad device", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "kicked %d sessions", a.hub.Kick(name))
	})
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
