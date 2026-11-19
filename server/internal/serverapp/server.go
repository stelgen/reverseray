// Package serverapp wires config, PKI, auth, hub, inbound and admin API
// into a runnable server.
package serverapp

import (
	"context"
	"encoding/base64"
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

	// v1.8.0: apimask — протокол (proto=apimask); счётчики под протокол.
	ApimaskPairs atomic.Uint64 // обработано пар запрос/ответ NOISE протокола apimask
	ApimaskBytes atomic.Uint64 // суммарный объём payload'ов NOISE (байты)
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
	// v1.7.0: горячая замена TLS-листа (runtime-перевыпуск) — чтение
	// на каждом коннекте, запись при необходимости.
	bundleMu sync.RWMutex
	met      *Metrics
	// egress — кешированный внешний IP сервера для /status и веб-морды
	egress egressIP

	// startedAt — uptime для веб-морды (v0.9.1: паритет фактов с APK)
	startedAt time.Time
	// v0.9.1: кеш размера state-каталога для /status (SSD-дисциплина)
	stateDirMu   sync.Mutex
	stateDirSize float64
	stateDirAt   time.Time

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

	// v0.9.5: выбор камуфляжа КЛИЕНТОМ (кадр 0x2A): устройство → выключен ли
	// apimask. Хранится перманентно (state/camouflage.json) — переживает
	// реконнекты и офлайн клиента; применяется в READY.features будущих сессий.
	camoMu  sync.Mutex
	camoOff map[string]bool

	ev *EventLog // v1.3.0: кольцевой журнал ключевых событий для /ui
}

// New assembles the app.
func New(cfg *config.Config, log *slog.Logger) (*App, error) {
	startedAt := time.Now()
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
	app := &App{
		startedAt:      startedAt,
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
		ev:             NewEventLog(1024),
	}
	// v1.3.0 «буфер трафика»: TTL паркинга из конфига; события буфера — в журнал /ui.
	app.hub.ParkSec = cfg.Limits.StreamParkSec
	app.hub.Logf = func(level, kind, msg string) {
		if level == "warn" {
			log.Warn("park: " + msg)
		} else {
			log.Info("park: " + msg)
		}
		app.ev.Add(level, kind, msg)
	}
	app.loadCamouflage() // v0.9.5: перманентные выборы камуфляжа клиентов
	return app, nil
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
// certRenewLoop — суточный тикер перевыпуска TLS-листа (v1.7.0).
// Канон безопасности: CA не ротируется рантаймом (SPKI-пин клиентов жив),
// обновляется только лист. LoadOrCreate атомарно перезаписывает файлы;
// при ошибке — честный WARN и работа текущим листом (коннект не падает).
func (a *App) certRenewLoop(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.bundleMu.RLock()
		need := tlscert.LeafNeedsRenewal(a.bundle)
		a.bundleMu.RUnlock()
		if !need {
			continue
		}
		nb, err := tlscert.LoadOrCreate(a.cfg.StateDir, a.cfg.Listen.TLSHosts)
		if err != nil {
			a.log.Warn("TLS leaf renewal failed — serving current leaf", "err", err)
			continue
		}
		a.bundleMu.Lock()
		a.bundle = nb
		a.bundleMu.Unlock()
		a.log.Info("TLS leaf renewed", "not_after", nb.Leaf.Leaf.NotAfter.UTC().Format(time.RFC3339))
		a.ev.Add("info", "cert", "TLS-сертификат перевыпущен (лист), CA не менялся")
	}
}

func (a *App) CAPin() string {
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	return a.bundle.CAPin
}

// Devices lists known device names (для тестов bootstrap).
func (a *App) Devices() []string { return a.store.Devices() }

// Run starts all listeners and blocks until ctx or a signal stops it.
func (a *App) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go a.reloadLoop(ctx)
	go a.logConnectInfo(ctx)
	// v1.7.0: runtime-перевыпуск TLS-листа (CA НЕ меняется — пины живы;
	// неудача продления — фоллбек: продолжаем текущим листом).
	go a.certRenewLoop(ctx)
	// v0.8: фоновая синхронизация модулей (первый прогон при старте)
	if a.cfg.Modules.Auto {
		go a.modSync.Run(ctx)
		// манифест, скачанный/сохранённый ранее, применяется сразу
		if m := a.modSync.Cached(); m != nil {
			rrp.SetRegistry(m.ProtocolRegistry(), m.Version)
			rrp.SetCamouflage(m.CamouflageConfig())
			a.log.Info("modules: cached manifest applied", "version", m.Version, "protocols", m.EnabledProtocolIDs(), "camouflage", rrp.CamouflageLabel())
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
