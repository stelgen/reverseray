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
	// v0.8.2: модуль камуфляжа «API Mask» (честно наружу: id/имя/версия/статус)
	Camouflage    *CamouflageInfo `json:"camouflage,omitempty"`
	ApimaskFrames uint64          `json:"apimask_frames_total"`
	ApimaskBytes  uint64          `json:"apimask_bytes_total"`
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
		"DATA ≤ 65535 Б; прочие кадры ≤ 4096 Б; окно стрима 512 КБ→4 МБ; бюджет сессии 16 МБ",
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
	s.ApimaskFrames = a.met.ApimaskFrames.Load()
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
	s.Facts = facts
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return []byte(`{"ok":false}`)
	}
	return b
}

// ---- /ui: встроенная веб-морда (read-only, vanilla JS, без зависимостей) ----

// uiHTML — самодостаточный дашборд: сессии, трафик, IP, протоколы.
// Скейлится от узких старых телефонов до ультрашироких мониторов (CSS clamp/flex).
const uiHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReverseRay · панель</title>
<style>
:root{--bg:#0b1020;--card:#121a30;--line:#1f2b4d;--tx:#dbe4ff;--mut:#8fa3d9;--ok:#39d98a;--warn:#f9a825;--err:#ff6b6b;--acc:#4fc3f7}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:clamp(8px,2vw,24px)}
h1{font-size:clamp(18px,3vw,26px);margin-bottom:2px}
.sub{color:var(--mut);font-size:clamp(11px,1.5vw,13px);margin-bottom:14px}
.grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;min-width:0}
.k{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.v{font-size:clamp(16px,2.4vw,22px);font-weight:700;font-variant-numeric:tabular-nums;word-break:break-all}
.ok{color:var(--ok)}.warn{color:var(--warn)}.err{color:var(--err)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--mut);text-align:left;font-weight:600;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:6px 8px;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums;word-break:break-word}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px;animation:p 1.6s infinite}
@keyframes p{50%{opacity:.35}}
footer{color:var(--mut);font-size:11px;margin-top:14px;text-align:center}
code{background:var(--line);padding:1px 6px;border-radius:6px;font-size:12px}
@media (max-width:420px){th:nth-child(5),td:nth-child(5){display:none}}
</style>
</head>
<body>
<h1><span class="dot"></span>ReverseRay — панель</h1>
<div class="sub" id="sub">загрузка…</div>
<div class="grid" id="cards"></div>
<div class="card"><table><thead><tr>
<th>Устройство</th><th>Сессия</th><th>Протокол</th><th>RTT</th><th>↓ вход</th><th>↑ выход</th><th>В полёте</th>
</tr></thead><tbody id="rows"><tr><td colspan="7" style="color:var(--mut)">нет активных сессий</td></tr></tbody></table></div>
<footer>авто-обновление 3 с · ReverseRay web UI</footer>
<script>
function fmtUp(sec){const h=Math.floor(sec/3600),m=Math.floor(sec%3600/60);return (h?h+" ч ":"")+m+" мин"}
function fmt(b){if(b==null||b===undefined)return"—";const u=["Б","КБ","МБ","ГБ"];let i=0,x=Number(b);while(x>=1024&&i<3){x/=1024;i++}return x.toFixed(i?1:0)+" "+u[i]}
function protoLabel(id,s){const l=(s.protocol_labels||{})[id]||id;const v=(s.protocol_vers||{})[id];return v?(l+' (v'+v+')'):l}
async function tick(){
 try{
  const r=await fetch('/status',{cache:'no-store'});const s=await r.json();
  document.getElementById('sub').textContent='сервер v'+s.version+' · протокол по умолчанию: '+protoLabel(s.default_proto,s)+' · egress IP: '+(s.egress_ip||'—')+(s.cert_not_after?(' · серт TLS до '+s.cert_not_after.slice(0,10)):'');
  const c=[
   ['Туннели',s.tunnels_up,s.tunnels_up>0?'ok':'warn'],
   ['Открытых стримов',s.streams_open,''],
   ['Устройств',s.devices,''],
   ['Auth OK / fail',s.auth_ok_total+' / '+s.auth_failures_total,s.auth_failures_total>0?'warn':'ok'],
   ['Inbound-подключений',s.inbound_conns_total,''],
   ['Egress IP',s.egress_ip||'—',''],
   ['Go / ОС',(s.go_version||'—')+' · '+((s.goos||'—')+'/'+(s.goarch||'—')),''],
   ['RAM (alloc)',fmt((s.mem_alloc_mb||0)*1048576),''],
   ['Диск state',fmt((s.state_dir_mb||0)*1048576),''],
   ['Uptime',fmtUp(s.uptime_sec||0),''],
   ['Релея всего',fmt(s.bytes_relayed_total||0),''],
   ['UDP-дейтаграмм',s.udp_datagrams_total||0,''],
  ];
  const hard=s.hardening_profile?('<div class="card"><div class="k">Hardening (WAN)</div><div class="v ok">'+s.hardening_profile+'</div>'+
   '<div class="k" style="margin-top:6px">Сканы отбито / лимит-дропов</div><div class="v">'+s.hardening_scans_total+' / '+s.hardening_limited_total+'</div></div>'):'';
  const mods=s.modules_version?('<div class="card"><div class="k">Модули (общий манифест APK↔сервер)</div><div class="v ok">'+s.modules_version+'</div><div class="k" style="margin-top:6px">Источник</div><div class="v">'+(s.modules_source||'builtin')+'</div></div>'):'';
  const facts=(s.facts&&s.facts.length)?('<div class="card" style="margin-bottom:10px"><div class="k">Константы защиты (тот же канон, что и в APK)</div>'+
   '<div style="margin-top:6px;font-size:12.5px;line-height:1.6">'+s.facts.map(f=>'• '+f).join('<br>')+'</div>'+
   '<div class="k" style="margin-top:8px">DNS / SNI</div><div style="font-size:12.5px">резолвит телефон — сервер хостов назначения не знает (redact by default)</div></div>'):'';
  const camo=(s.camouflage&&s.camouflage.enabled)?('<div class="card"><div class="k">Маскировка (API Mask)</div><div class="v ok">'+(s.camouflage.ver?('v'+s.camouflage.ver):'вкл')+'</div><div class="k" style="margin-top:6px">Кадров NOISE / байт</div><div class="v">'+s.apimask_frames_total+' / '+fmt(s.apimask_bytes_total)+'</div></div>'):'';
  document.getElementById('cards').innerHTML=c.map(([k,v,cls])=>
   '<div class="card"><div class="k">'+k+'</div><div class="v '+cls+'">'+v+'</div></div>').join('')+hard+mods+camo+facts;
  const rows=(s.sessions||[]).map(x=>
   '<tr><td>'+(x.device||'?')+'</td><td><code>'+String(x.session||'').slice(0,10)+'…</code></td>'+
   '<td>'+protoLabel(x.proto||'rrp1',s)+'</td><td>'+(x.rtt_ms!=null?x.rtt_ms+' мс':'—')+'</td>'+
   '<td class="ok">'+fmt(x.bytes_in)+'</td><td>'+fmt(x.bytes_out)+'</td>'+
   '<td>'+fmt(x.outstanding)+'</td></tr>').join('');
  document.getElementById('rows').innerHTML=rows||'<tr><td colspan="7" style="color:var(--mut)">нет активных сессий</td></tr>';
 }catch(e){document.getElementById('sub').textContent='ошибка: '+e}
}
tick();setInterval(tick,3000);
</script>
</body>
</html>`

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
}
