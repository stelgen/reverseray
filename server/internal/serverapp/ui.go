package serverapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// ---- /status: сводка для веб-морды (/ui) и скриптов ----

type StatusReport struct {
	OK           bool     `json:"ok"`
	Version      string   `json:"version"`
	EgressIP     string   `json:"egress_ip,omitempty"`
	TunnelsUp    int64    `json:"tunnels_up"`
	StreamsOpen  int64    `json:"streams_open"`
	Devices      int      `json:"devices"`
	AuthOK       int64    `json:"auth_ok_total"`
	AuthFail     int64    `json:"auth_failures_total"`
	InboundConns int64    `json:"inbound_conns_total"`
	DefaultProto string   `json:"default_proto"`
	Protocols    []string `json:"protocols"`
	// v0.8.1: версии протоколов по всему стеку — метки и публичные версии
	// (id → "RRP/1" / "1"; пустая версия = «версии нет», показываем пусто).
	ProtoLabels map[string]string `json:"protocol_labels,omitempty"`
	ProtoVers   map[string]string `json:"protocol_vers,omitempty"`
	// v0.8.1: срок действия TLS-сертификата сервера (честно и наружу).
	CertNotAfter string           `json:"cert_not_after,omitempty"`
	Sessions     []map[string]any `json:"sessions"`
	// v0.8: WAN-защита и модули — та же открытость, что и в APK:
	// пользователь/админ видит, что защищает сервер и что он обновил.
	HardeningProfile string `json:"hardening_profile"`
	HardeningScans   uint64 `json:"hardening_scans_total"`
	HardeningDropped uint64 `json:"hardening_dropped_total"`
	HardeningLimited uint64 `json:"hardening_limited_total"`
	ModulesVersion   string `json:"modules_version,omitempty"`
	ModulesSource    string `json:"modules_source,omitempty"`
	ProtoSessions    int64  `json:"proto_sessions_non_default"` // уже int64
	Parked           int    `json:"parked_streams"`             // v1.3.0: стримов в буфере трафика
	EventInfo        int    `json:"events_info"`
	EventWarn        int    `json:"events_warn"`
	// v0.8.2: камуфляж протокола apimask (честно наружу: id/имя/версия/статус)
	Camouflage   *CamouflageInfo `json:"camouflage,omitempty"`
	ApimaskPairs uint64          `json:"apimask_pairs_total"`
	ApimaskBytes uint64          `json:"apimask_bytes_total"`
	// v0.9.5: выборы камуфляжа клиентов (кадр 0x2A): устройство → выключен.
	CamoOverrides map[string]bool `json:"camouflage_off,omitempty"`
	// v1.6.1: веб-управление телефонами — публичные материалы для «Копировать
	// подключение» (host:port слушателя туннелей + CA SPKI pin; сам токен
	// хранится ТОЛЬКО хэшем — полную ссылку выдаёт `enroll`, канон hash-only).
	Listen string `json:"listen_tunnels,omitempty"`
	CAPin  string `json:"ca_pin,omitempty"`
	// v1.6.1: живые WS-туннели (отдельно от TCP) для панели сети.
	WsTunnels int64 `json:"ws_tunnels,omitempty"`
	// v0.9.1: паритет фактов с APK — «О сервере» и «Константы защиты»
	GoVersion    string   `json:"go_version,omitempty"`
	GOOS         string   `json:"goos,omitempty"`
	GOARCH       string   `json:"goarch,omitempty"`
	MemAllocMB   float64  `json:"mem_alloc_mb,omitempty"`
	MemSysMB     float64  `json:"mem_sys_mb,omitempty"`
	StateDirMB   float64  `json:"state_dir_mb,omitempty"`
	UptimeSec    int64    `json:"uptime_sec,omitempty"`
	BytesRelayed uint64   `json:"bytes_relayed_total,omitempty"`
	UdpDatagrams uint64   `json:"udp_datagrams_total,omitempty"`
	Facts        []string `json:"facts,omitempty"`
}

// CamouflageInfo — открытая сводка модуля камуфляжа для /status и /ui.
type CamouflageInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Ver     string `json:"ver,omitempty"`
	Enabled bool   `json:"enabled"`
}

// egressIP caches the outbound IPv4 of the server (targets are never logged).
type egressIP struct {
	mu  sync.Mutex
	val string
	at  time.Time
}

func (e *egressIP) get() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.val != "" && time.Since(e.at) < 5*time.Minute {
		return e.val
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", "8.8.8.8:80")
	if err == nil {
		if addr, ok := c.LocalAddr().(*net.UDPAddr); ok && !addr.IP.IsLoopback() {
			e.val = addr.IP.String()
		}
		_ = c.Close()
	}
	e.at = time.Now()
	return e.val
}

// dirSizeMB — суммарный размер state-каталога (дисциплина SSD:
// ходим по файлам не чаще раза в минуту — кеш в App).
func dirSizeMB(dir string) float64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return float64(total) / 1024 / 1024
}

func (a *App) statusJSON() []byte {
	// v0.9.1: факты сервера (тот же паттерн открытости, что и в APK)
	a.stateDirMu.Lock()
	if time.Since(a.stateDirAt) > 60*time.Second {
		a.stateDirSize = dirSizeMB(a.cfg.StateDir)
		a.stateDirAt = time.Now()
	}
	a.stateDirMu.Unlock()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	facts := []string{
		"TLS 1.3 + ALPN; лист 3 года; пин = SHA256(SPKI CA) — ротация листа клиентов не ломает",
		"HMAC-SHA256(key=SHA256(token), msg=nonce‖session_id), constant-time; nonce TTL 60 с, replay → отказ",
		"≤120 рукопожатий/мин/IP; lockout за невалидный HMAC: 5 неудач → 30с·2^n (до 10 мин)",
		"MTProto 2.0: DH-2048 на официальном dh_prime Telegram, AES-256-IGE, msg_key SHA-256",
		"DATA ≤ 65535 Б; прочие кадры ≤ 4096 Б; окно стрима 1 МБ→4 МБ (BDP-автотюнинг); бюджет 32 МБ; буфер трафика до 600 с",
		"WAN-hardening: первый байт ≠ TLS → tarpit + тишина (0 байт ответа)",
		"Манифест modules.json: schema-чек, семвер, sha256, даунгрейд запрещён, мусор не применяется",
		"DNS/SNI резолвит телефон — сервер не знает хосты назначения (redact by default)",
	}
	s := StatusReport{
		OK:               true,
		Version:          Version,
		EgressIP:         a.egress.get(),
		TunnelsUp:        a.met.TunnelsUp.Load(),
		StreamsOpen:      a.met.StreamsOpen.Load(),
		Devices:          len(a.store.Devices()),
		AuthOK:           a.met.AuthOK.Load(),
		AuthFail:         a.met.AuthFailures.Load(),
		InboundConns:     a.met.InboundConns.Load(),
		DefaultProto:     rrp.NormalizeProto(a.cfg.DefaultProtocol),
		Protocols:        rrp.SupportedIDs(),
		ProtoLabels:      rrp.Labels(),
		ProtoVers:        rrp.Vers(),
		CertNotAfter:     a.bundle.Leaf.Leaf.NotAfter.UTC().Format(time.RFC3339),
		Sessions:         a.hub.Snapshot(),
		HardeningProfile: a.gate.Describe(),
		HardeningScans:   a.hardSt.Scans.Load(),
		HardeningDropped: a.hardSt.Dropped.Load(),
		HardeningLimited: a.hardSt.Limited.Load(),
		ProtoSessions:    a.met.ProtoSessions.Load(),
	}
	// v1.3.0: буфер трафика + сводка журнала событий
	s.Parked = a.hub.ParkedTotal()
	s.EventInfo, s.EventWarn, _ = a.ev.Counts()
	if a.modSync != nil {
		s.ModulesVersion = a.modSync.ActiveVersion()
		if ms := a.modSync.Status(); ms.Source != "" {
			s.ModulesSource = ms.Source
		}
	}
	// v0.8.2: камуфляж «API Mask» — та же открытость, что и в APK
	if camo := rrp.CamouflageConfig(); camo.ID != "" {
		s.Camouflage = &CamouflageInfo{ID: camo.ID, Name: camo.Name, Ver: camo.Ver, Enabled: camo.Enabled}
	}
	s.ApimaskPairs = a.met.ApimaskPairs.Load()
	s.ApimaskBytes = a.met.ApimaskBytes.Load()
	s.GoVersion = runtime.Version()
	s.GOOS = runtime.GOOS
	s.GOARCH = runtime.GOARCH
	s.MemAllocMB = float64(ms.Alloc) / 1024 / 1024
	s.MemSysMB = float64(ms.Sys) / 1024 / 1024
	s.StateDirMB = a.stateDirSize
	s.UptimeSec = int64(time.Since(a.startedAt) / time.Second)
	s.BytesRelayed = a.met.BytesRelayed.Load()
	s.UdpDatagrams = a.udpDatagrams()
	s.CamoOverrides = a.CamouflageOverrides() // v0.9.5: выборы клиентов
	s.Listen = a.cfg.Listen.Tunnels
	s.CAPin = a.CAPin()
	s.WsTunnels = a.met.WsTunnels.Load()
	s.Facts = facts
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return []byte(`{"ok":false}`)
	}
	return b
}

// ---- /ui: встроенная веб-морда (read-only, vanilla JS, без зависимостей) ----
// v0.9.5: дашборд 2026 — RT-график трафика, карточки клиентов со всей
// телеметрией (relay/телефон, стримы, UDP/DNS, крипта протокола), без
// «Константы защиты» (те остаются в APK и /status).
// v0.9.6: график детальнее (сетка 5 линий с подписями осей, градиентная
// заливка, сглаживание Катмулла-Рома, пунктирные EMA/пик, светлая тема);
// правило канона данных — пустое поле НЕ рендерится вовсе (ни нулём, ни «—»);
// карточки клиентов рендерит сервер (единый источник правды, тестируемо).
// Скейлится от узких телефонов до ультрашироких мониторов (CSS clamp/grid).

func (a *App) mountUI(mux *http.ServeMux) {
	mux.HandleFunc("/ui", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Robots-Tag", "noindex")
		_, _ = fmt.Fprint(w, uiHTML)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Robots-Tag", "noindex")
		_, _ = w.Write(a.statusJSON())
	})
	// v1.3.0: кольцевой журнал ключевых событий для дашборда.
	mux.HandleFunc("/ui/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Robots-Tag", "noindex")
		n := 200
		if v := r.URL.Query().Get("limit"); v != "" {
			if p, err := strconv.Atoi(v); err == nil && p > 0 && p <= 1000 {
				n = p
			}
		}
		_ = json.NewEncoder(w).Encode(a.ev.Snapshot(n))
	})
}
