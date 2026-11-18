package serverapp

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

// ---- серверный рендер карточек клиентов (/ui/cards) ----
// v0.9.6: единый источник правды — HTML собирает Go, поэтому «пустое поле
// не рендерится» проверяется юнит-тестом на честном выходе.

// uiNum — аккуратное чтение числа из снапшота хаба.
func uiNum(x map[string]any, key string) float64 {
	if v, ok := x[key].(float64); ok {
		return v
	}
	if v, ok := x[key].(int64); ok {
		return float64(v)
	}
	if v, ok := x[key].(int); ok {
		return float64(v)
	}
	return 0
}

// uiStr — чтение строки из снапшота хаба.
func uiStr(x map[string]any, key string) string {
	if v, ok := x[key].(string); ok {
		return v
	}
	return ""
}

// uiFmtBytes — человекочитаемые байты (Б/КБ/МБ/ГБ/ТБ).
func uiFmtBytes(b float64) string {
	units := []string{"Б", "КБ", "МБ", "ГБ", "ТБ"}
	i := 0
	for b >= 1024 && i < 4 {
		b /= 1024
		i++
	}
	if i == 0 {
		return strconv.FormatInt(int64(b), 10) + " " + units[i]
	}
	return strconv.FormatFloat(b, 'f', 1, 64) + " " + units[i]
}

// uiFmtUp — человекочитаемый аптайм.
func uiFmtUp(sec float64) string {
	s := int64(sec)
	d := s / 86400
	h := s % 86400 / 3600
	m := s % 3600 / 60
	parts := []string{}
	if d > 0 {
		parts = append(parts, fmt.Sprintf("%d д", d))
	}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%d ч", h))
	}
	parts = append(parts, fmt.Sprintf("%d мин", m))
	return strings.Join(parts, " ")
}

// uiRow — пара «ключ → значение»; пустое значение → пустая строка
// (строка вообще не попадает в HTML — канон v0.9.6).
func uiRow(k1, v1, k2, v2 string) string {
	if v1 == "" && v2 == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("<tr>")
	for _, kv := range [][2]string{{k1, v1}, {k2, v2}} {
		b.WriteString(`<td class="k">` + kv[0] + `</td>`)
		if kv[1] == "" {
			b.WriteString("<td></td>")
		} else {
			b.WriteString(`<td class="num">` + kv[1] + `</td>`)
		}
	}
	b.WriteString("</tr>")
	return b.String()
}

// clientCardHTML — карточка одного клиента; поля без данных отсутствуют.
func clientCardHTML(x map[string]any, s *StatusReport) string {
	device := html.EscapeString(uiStr(x, "device"))
	if device == "" {
		device = "—"
	}
	// крипта конверта протокола
	mt := `<span class="badge b-gray">без конверта</span>`
	if v, ok := x["mt_active"].(bool); ok && v {
		mt = `<span class="badge b-green" title="payload'ы DATA/UDP_DATA зашифрованы конвертом протокола">крипта вкл</span>`
	}
	// камуфляж: выбор клиента приоритетнее глобального статуса
	camo := ""
	if off, ok := s.CamoOverrides[uiStr(x, "device")]; ok && off {
		camo = `<span class="badge b-gray">API Mask выкл (клиентом)</span>`
	} else if s.Camouflage != nil && s.Camouflage.Enabled {
		camo = `<span class="badge b-blue">API Mask</span>`
	}
	// бейдж протокола; публичная версия показывается только если есть
	pid := uiStr(x, "proto")
	plabel := pid
	if s.ProtoLabels != nil {
		if l := s.ProtoLabels[pid]; l != "" {
			plabel = l
		}
	}
	if s.ProtoVers != nil {
		if v := s.ProtoVers[pid]; v != "" {
			plabel += " · v" + v
		}
	}
	var badge string
	switch pid {
	case "mtproto2":
		badge = `<span class="badge b-green">MTProto/2</span>`
	case "wireguard":
		badge = `<span class="badge b-purple">WireGuard/1</span>`
	default:
		if plabel != "" {
			badge = `<span class="badge b-blue">` + html.EscapeString(plabel) + `</span>`
		}
	}
	// строки таблицы: только непустые значения
	rows := ""
	if rtt := uiNum(x, "rtt_ms"); rtt > 0 {
		rows += uiRow("RTT", fmt.Sprintf("%.0f мс", rtt), "Uptime", uiFmtUp(uiNum(x, "uptime_sec")))
	} else if up := uiNum(x, "uptime_sec"); up > 0 {
		rows += uiRow("Uptime", uiFmtUp(up), "", "")
	}
	if st := uiNum(x, "streams"); st > 0 {
		rows += uiRow("Стримы", fmt.Sprintf("%.0f", st), "В полёте", func() string {
			if o := uiNum(x, "outstanding"); o > 0 {
				return uiFmtBytes(o)
			}
			return ""
		}())
	} else if o := uiNum(x, "outstanding"); o > 0 {
		rows += uiRow("В полёте", uiFmtBytes(o), "", "")
	}
	if ri := uiNum(x, "relay_in"); ri > 0 || uiNum(x, "relay_out") > 0 {
		ro := ""
		if o := uiNum(x, "relay_out"); o > 0 {
			ro = uiFmtBytes(o)
		}
		rows += uiRow("↓ relay", uiFmtBytes(ri), "↑ relay", ro)
	}
	if bi := uiNum(x, "bytes_in"); bi > 0 || uiNum(x, "bytes_out") > 0 {
		bo := ""
		if o := uiNum(x, "bytes_out"); o > 0 {
			bo = uiFmtBytes(o)
		}
		rows += uiRow("↓ телефон", uiFmtBytes(bi), "↑ телефон", bo)
	}
	// UDP/DNS: показываем только если трафик реально был
	if u := uiNum(x, "udp"); u > 0 || uiNum(x, "dns") > 0 {
		dn := ""
		if d := uiNum(x, "dns"); d > 0 {
			dn = fmt.Sprintf("%.0f", d)
		}
		rows += uiRow("UDP", fmt.Sprintf("%.0f", u), "DNS", dn)
	}
	// подвал карточки: сессия и время подключения
	foot := ""
	if sess := uiStr(x, "session"); sess != "" {
		foot += `сессия <code>` + html.EscapeString(sess) + `…</code>`
	}
	if ca := uiNum(x, "connected_at"); ca > 0 {
		t := time.Unix(int64(ca), 0).Format("15:04:05")
		if foot != "" {
			foot += " · "
		}
		foot += "с " + t
	}
	var b strings.Builder
	b.WriteString(`<div class="card">`)
	b.WriteString(`<div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline;flex-wrap:wrap">`)
	b.WriteString(`<div class="v" style="font-size:clamp(15px,1.8vw,19px)">` + device + `</div>` + mt + `</div>`)
	b.WriteString(`<div style="margin:6px 0 10px;display:flex;gap:6px;flex-wrap:wrap">` + badge + camo + `</div>`)
	if rows != "" {
		b.WriteString(`<table>` + rows + `</table>`)
	}
	if foot != "" {
		b.WriteString(`<div class="muted" style="margin-top:8px;font-size:11.5px">` + foot + `</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// cardsHTML — блок «Клиенты» целиком: серверный рендер всех карточек.
func (a *App) cardsHTML() string {
	sessions := a.hub.Snapshot()
	if len(sessions) == 0 {
		return `<div class="card muted">нет активных сессий — подключите APK (rrp:// ссылка)</div>`
	}
	var camo *CamouflageInfo
	if c := rrp.CamouflageConfig(); c.ID != "" {
		camo = &CamouflageInfo{ID: c.ID, Name: c.Name, Ver: c.Ver, Enabled: c.Enabled}
	}
	s := &StatusReport{
		ProtoLabels:   rrp.Labels(),
		ProtoVers:     rrp.Vers(),
		Camouflage:    camo,
		CamoOverrides: a.CamouflageOverrides(),
	}
	var b strings.Builder
	for _, x := range sessions {
		b.WriteString(clientCardHTML(x, s))
	}
	return b.String()
}

func (a *App) mountUI(mux *http.ServeMux) {
	mux.HandleFunc("/ui", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Robots-Tag", "noindex")
		_, _ = fmt.Fprint(w, uiHTML)
	})
	// v0.9.6: серверный рендер карточек клиентов (LAN-only, noindex)
	mux.HandleFunc("/ui/cards", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Robots-Tag", "noindex")
		_, _ = fmt.Fprint(w, a.cardsHTML())
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
