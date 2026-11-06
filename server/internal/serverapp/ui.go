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
	// v0.8.2: модуль камуфляжа «API Mask» (честно наружу: id/имя/версия/статус)
	Camouflage    *CamouflageInfo `json:"camouflage,omitempty"`
	ApimaskFrames uint64          `json:"apimask_frames_total"`
	ApimaskBytes  uint64          `json:"apimask_bytes_total"`
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

const uiHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReverseRay — панель управления</title>
<style>
:root{
 --bg:#111217;--panel:#181b1f;--panel2:#1f2126;--border:#2c3038;--txt:#d8d9dd;--dim:#8e9095;
 --green:#73bf69;--red:#f2495c;--yellow:#ff9830;--blue:#5794f2;--purple:#b877d9;--orange:#ffb357;
 --mono:'JetBrains Mono','SF Mono',Consolas,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:13px/1.45 -apple-system,'Segoe UI',Roboto,sans-serif}
a{color:var(--blue);text-decoration:none}
.top{display:flex;align-items:center;gap:14px;padding:10px 18px;background:var(--panel2);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:9}
.brand{font-weight:700;font-size:16px;letter-spacing:.4px}
.brand b{color:var(--blue);font-weight:700}
.dot{width:10px;height:10px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.warn{background:var(--red);box-shadow:0 0 6px var(--red)}
.chip{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:2px 9px;font-size:12px;color:var(--dim)}
.chip b{color:var(--txt);font-weight:600}
.top .sp{flex:1}
.wrap{padding:14px 18px 40px;max-width:1680px;margin:0 auto}
.grid{display:grid;gap:10px}
.kpis{grid-template-columns:repeat(auto-fit,minmax(158px,1fr))}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:12px 14px}
.panel h3{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);font-weight:600;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}
.stat .v{font-size:26px;font-weight:600;font-family:var(--mono)}
.stat .v small{font-size:13px;color:var(--dim);font-weight:400}
.stat.ok .v{color:var(--green)}.stat.bad .v{color:var(--red)}.stat.acc .v{color:var(--blue)}.stat.mut .v{color:var(--txt)}
.row2{grid-template-columns:minmax(320px,2fr) minmax(300px,1fr)}
@media(max-width:900px){.row2{grid-template-columns:1fr}}
.ctrl{display:flex;gap:6px;align-items:center}
.ctrl button,.ctrl select{background:var(--panel2);color:var(--dim);border:1px solid var(--border);border-radius:4px;padding:3px 9px;font-size:11px;cursor:pointer;font-family:inherit}
.ctrl button.on{color:var(--txt);border-color:var(--blue);background:#232a35}
svg.chart{width:100%;height:190px;display:block}
.legend{display:flex;gap:16px;font-size:11px;color:var(--dim);margin-top:6px}
.legend i{display:inline-block;width:10px;height:3px;border-radius:2px;margin-right:5px;vertical-align:middle}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{color:var(--dim);font-weight:600;text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.4px}
td{padding:6px 8px;border-bottom:1px solid #23262c;font-family:var(--mono)}
td.s{font-family:inherit}
tr:hover td{background:#1d2025}
.mono{font-family:var(--mono)}
.ok{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}.dim{color:var(--dim)}
.logs{max-height:340px;overflow-y:auto;font-family:var(--mono);font-size:12px}
.logs:hover{filter:none}
.le{display:flex;gap:8px;padding:3px 2px;border-bottom:1px solid #1d2025;align-items:baseline}
.le .t{color:var(--dim);flex:0 0 66px}
.le .k{flex:0 0 84px;text-align:center;border-radius:3px;font-size:10px;padding:1px 0;background:var(--panel2);color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.le .k.tunnel{color:var(--blue)}.le .k.proto{color:var(--purple)}.le .k.park{color:var(--orange)}.le .k.auth{color:var(--dim)}
.le .d{flex:0 0 90px;color:var(--dim);overflow:hidden;text-overflow:ellipsis}
.le .m{flex:1}
.le.w .m{color:var(--yellow)}
.facts{font-size:11.5px;color:var(--dim);line-height:1.7}
.foot{margin-top:14px;color:var(--dim);font-size:11px;display:flex;gap:14px;flex-wrap:wrap}
.pill{padding:1px 7px;border-radius:3px;background:var(--panel2);border:1px solid var(--border)}
button.act{font:inherit;font-size:11px;padding:3px 8px;border-radius:6px;border:1px solid #2a2f3a;background:#171a21;color:#d8dce6;cursor:pointer}
button.act:hover{border-color:#5794f2;color:#fff}
button.act.dw{color:#ff6b6b;border-color:#3a2226}
button.act.dw:hover{border-color:#ff6b6b}
</style>
</head>
<body>
<div class="top">
 <div class="brand">Reverse<b>Ray</b></div>
 <div class="dot" id="dot"></div>
 <div class="chip">версия <b id="ver">—</b></div>
 <div class="chip">uptime <b id="upt">—</b></div>
 <div class="chip">egress <b class="mono" id="eg">—</b></div>
 <div class="chip">сертификат до <b id="cert">—</b></div>
 <div class="sp"></div>
 <div class="chip" id="hprofile">—</div>
</div>
<div class="wrap">
 <div class="grid kpis" id="kpis"></div>
 <div class="grid" style="margin-top:10px">
  <div class="panel">
   <h3><span>Управление телефонами</span><span class="ctrl dim">hash-only</span></h3>
   <div style="overflow-x:auto"><table id="devs"><thead><tr>
    <th>Устройство</th><th>Сессий</th><th>Протоколы</th><th>↓ релей</th><th>↑ релей</th><th>API Mask</th><th>Действия</th>
   </tr></thead><tbody></tbody></table></div>
  </div>
 </div>
 <div class="grid row2" style="margin-top:10px">
  <div class="panel">
   <h3><span>Трафик через туннель</span>
    <span class="ctrl">
     <button data-p="150" class="on">5 мин</button><button data-p="450">15 мин</button><button data-p="1800">1 ч</button>
     <select id="unit"><option value="b">Б/с</option><option value="kb" selected>КБ/с</option><option value="mb">МБ/с</option><option value="mbit">Мбит/с</option></select>
    </span></h3>
   <svg class="chart" id="chart" preserveAspectRatio="none" viewBox="0 0 1000 190"></svg>
   <div class="legend"><span><i style="background:var(--green)"></i>входящий <b id="lin" class="mono">—</b></span><span><i style="background:var(--blue)"></i>исходящий <b id="lout" class="mono">—</b></span><span>пик <b id="lpeak" class="mono">—</b></span></div>
  </div>
  <div class="panel">
   <h3>Протоколы и защита</h3>
   <div class="facts" id="protos"></div>
   <h3 style="margin-top:12px">Канонические гарантии</h3>
   <div class="facts" id="facts"></div>
  </div>
 </div>
 <div class="grid" style="margin-top:10px">
  <div class="panel">
   <h3><span>Устройства и туннели</span><span class="ctrl dim" id="parkinfo"></span></h3>
   <div style="overflow-x:auto"><table id="sess"><thead><tr>
    <th>Устройство</th><th>Протокол</th><th>Транспорт</th><th>RTT</th><th>Потоки</th><th>Окно</th><th>↓ всего</th><th>↑ всего</th><th>↓/с</th><th>↑/с</th><th>Ошибки диала</th><th>Аптайм</th>
   </tr></thead><tbody></tbody></table></div>
  </div>
 </div>
 <div class="grid row2" style="margin-top:10px">
  <div class="panel">
   <h3><span>Журнал событий</span>
    <span class="ctrl"><button id="fall" class="on">все</button><button id="fwarn">предупреждения</button></span></h3>
   <div class="logs" id="logs"></div>
  </div>
  <div class="panel">
   <h3>Камуфляж и модули</h3>
   <div class="facts" id="mods"></div>
  </div>
 </div>
 <div class="foot">
  <span>GET /status — полная телеметрия</span><span>GET /metrics — Prometheus</span><span>GET /ui/logs — журнал (JSON)</span><span>GET /healthz · /readyz</span>
 </div>
</div>
<script>
var hist=[],lastRelay={},lastAt=0,lastStatus={},period=150,unit='kb',logCache=[],logFilter='all',lastLogKey='';
function fmtB(b){if(b==null)return'—';var u=['Б','КБ','МБ','ГБ','ТБ'],i=0,x=Number(b);while(x>=1024&&i<4){x/=1024;i++}return(i?x.toFixed(1):x)+' '+u[i]}
function fmtR(b){if(b==null||b<0)return'—';var u=['Б/с','КБ/с','МБ/с','ГБ/с'],i=0,x=b;while(x>=1024&&i<3){x/=1024;i++}return x.toFixed(i?1:0)+' '+u[i]}
function fmtUp(s){s=Math.max(0,s|0);var d=(s/86400)|0,h=((s%86400)/3600)|0,m=((s%3600)/60)|0;return(d?d+' д ':'')+(h?h+' ч ':'')+m+' мин'}
function inUnit(v){if(v==null)return null;if(unit==='b')return v;if(unit==='kb')return v/1024;if(unit==='mb')return v/1048576;return v*8/1e6}
function unitName(){return{b:'Б/с',kb:'КБ/с',mb:'МБ/с',mbit:'Мбит/с'}[unit]}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function protoLabel(id,s){var l=(s.protocol_labels||{})[id]||id,v=(s.protocol_vers||{})[id];return v?l+' · v'+v:l}
function stat(label,val,cls,sub){if(val===null||val===undefined||val==='')return'';return'<div class="panel stat '+(cls||'')+'"><h3>'+label+'</h3><div class="v">'+val+(sub?' <small>'+sub+'</small>':'')+'</div></div>'}
async function tick(){
 try{
  var r=await fetch('/status',{cache:'no-store'}),s=await r.json();lastStatus=s;
  document.getElementById('dot').className='dot'+(s.tunnels_up>0?'':' warn');
  document.getElementById('ver').textContent='v'+s.version;
  document.getElementById('upt').textContent=fmtUp(s.uptime_sec);
  document.getElementById('eg').textContent=s.egress_ip||'—';
  document.getElementById('cert').textContent=(s.cert_not_after||'—').slice(0,10);
  document.getElementById('hprofile').innerHTML='<b>'+esc(s.hardening_profile||'')+'</b>';
  var k=[
   stat('Туннели',s.tunnels_up,s.tunnels_up>0?'ok':'bad'),
   stat('Открытых потоков',s.streams_open||null,'mut'),
   stat('В буфере трафика',s.parked_streams||null,s.parked_streams?'acc':'mut','стримов'),
   stat('Устройств',s.devices||null,'mut'),
   stat('Пропущено всего',fmtB(s.bytes_relayed_total),'acc'),
   stat('Авторизаций устройств',s.auth_ok_total||null,'ok'),
   stat('Отклонено рукопожатий',s.auth_failures_total||null,'mut'),
   stat('UDP-дейтаграмм',s.udp_datagrams_total||null,'mut'),
   stat('Зондов отброшено (tarpit)',s.hardening_dropped_total||null,'mut'),
   stat('Отказов по лимиту',s.hardening_limited_total||null,'mut'),
   stat('API Mask: байтов',s.apimask_bytes_total!=null?fmtB(s.apimask_bytes_total):null,'mut'),
   stat('WS-туннелей',s.ws_tunnels||null,'mut'),
   stat('Сканирований отклонено',s.hardening_scans_total||null,'mut'),
   stat('RAM (Go heap)',s.mem_alloc_mb?fmtB(s.mem_alloc_mb*1048576):null,'mut'),
   stat('События',s.events_info!=null?('<span class="dim">'+s.events_info+'</span> / <span class="warn">'+(s.events_warn||0)+'</span>'):'','mut','info/warn')
  ].join('');
  document.getElementById('kpis').innerHTML=k;
  // скорости из дельт релея по сессиям
  var now=Date.now(),dIn=0,dOut=0,rows='';
  var sess=s.sessions||[];
  var prev=lastRelay,dt=0;
  if(lastAt){dt=Math.max(1,(now-lastAt)/1000);
   sess.forEach(function(x){var p=lastRelay[x.session];if(p){dIn+=Math.max(0,(x.relay_in||0)-p[0]);dOut+=Math.max(0,(x.relay_out||0)-p[1])}});
   hist.push({t:now,in:dIn/dt,out:dOut/dt});if(hist.length>1800)hist.shift();
  }
  lastAt=now;lastRelay={};
  sess.forEach(function(x){lastRelay[x.session]=[x.relay_in||0,x.relay_out||0]});
  draw();
  sess.forEach(function(x){
   var rtt=x.rtt_ms>0?x.rtt_ms+' мс':'—';
   var win=x.window_grant>0?(x.window_grant/1048576).toFixed(1)+' МБ':'—';
   var gr=x.window_grant>0?fmtB(x.relay_in):fmtB(x.relay_in);
   var pr=prev[x.session],ri='—',ro='—';
   if(pr&&dt){ri=fmtR(Math.max(0,(x.relay_in||0)-pr[0])/dt);ro=fmtR(Math.max(0,(x.relay_out||0)-pr[1])/dt)}
   rows+='<tr><td class="s"><b>'+esc(x.device)+'</b></td><td class="s">'+esc(protoLabel(x.proto,s))+'</td><td class="s dim">'+esc(x.proto===undefined?'':(x.transport||'tcp'))+'</td><td>'+rtt+'</td><td>'+x.streams+'</td><td>'+win+'</td><td>'+fmtB(x.relay_in)+'</td><td>'+fmtB(x.relay_out)+'</td><td class="s">'+ri+'</td><td class="s">'+ro+'</td><td>'+(x.open_errors?'<span class="warn">'+x.open_errors+'</span>':'<span class="ok">0</span>')+'</td><td class="dim">'+fmtUp(x.uptime_sec)+'</td></tr>';
  });
  document.querySelector('#sess tbody').innerHTML=rows||'<tr><td colspan="12" class="dim">нет активных туннелей</td></tr>';
  document.getElementById('parkinfo').textContent='в буфере: '+(s.parked_streams||0);
  var pl=(s.protocols||[]).map(function(p){return '<span class="pill">'+esc(protoLabel(p,s))+'</span>'}).join(' ');
  document.getElementById('protos').innerHTML='<div style="margin-bottom:6px">Реестр протоколов: '+pl+'</div><div>Протокол по умолчанию: <b>'+esc(protoLabel(s.default_proto,s))+'</b></div><div style="margin-top:4px">Сессии на не-дефолтном протоколе: '+s.proto_sessions_non_default+'</div>';
  document.getElementById('facts').innerHTML=(s.facts||[]).map(function(f){return '· '+esc(f)}).join('<br>');
  var m='';
  if(s.camouflage)m+='<div>API Mask: <b>'+esc(s.camouflage.name)+'</b> · v'+esc(s.camouflage.ver)+' · '+(s.camouflage.enabled?'<span class="ok">активен</span>':'<span class="warn">выключен</span>')+' · кадров '+s.apimask_frames_total+'</div>';
  if(s.modules_version)m+='<div>Модули: манифест <b>v'+esc(s.modules_version)+'</b>'+(s.modules_source?' · '+esc(s.modules_source):'')+'</div>';
  if(s.go_version)m+='<div>Среда: Go '+esc(s.go_version)+' · '+esc(s.goos)+'/'+esc(s.goarch)+' · state '+fmtB((s.state_dir_mb||0)*1048576)+'</div>';
  document.getElementById('mods').innerHTML=m||'<span class="dim">—</span>';
 }catch(e){var d=document.getElementById('dot');if(d)d.className='dot warn'}
 pollLogs();
}
function draw(){
 var svg=document.getElementById('chart');
 var win=hist.slice(-period);
 if(win.length<2){svg.innerHTML='<text x="12" y="100" fill="#8e9095" font-size="13">сбор данных…</text>';return}
 var W=1000,H=190,pad=26,max=0,sum=0;
 win.forEach(function(x){var a=inUnit(x.in)||0,b=inUnit(x.out)||0;if(a>max)max=a;if(b>max)max=b;sum+=a+b});
 if(max<=0)max=1;
 var pw=W-pad*2,ph=H-pad*1.4,x0=pad,y0=H-pad;
 function px(i){return x0+pw*i/(win.length-1)}
 function py(v){return y0-ph*(v/max)}
 function path(key){var d='';win.forEach(function(x,i){var v=inUnit(x[key])||0;d+=(i?'L':'M')+px(i).toFixed(1)+' '+py(v).toFixed(1)+' '});return d}
 var g='';for(var i=0;i<=4;i++){var yy=y0-ph*i/4;g+='<line x1="'+x0+'" y1="'+yy+'" x2="'+(x0+pw)+'" y2="'+yy+'" stroke="#23262c"/><text x="'+(x0-4)+'" y="'+(yy+3)+'" fill="#8e9095" font-size="9" text-anchor="end">'+fmtR(max*i/4*(unit==='mbit'?1:(unit==='b'?1:1)))+'</text>'}
 svg.innerHTML=g
  +'<path d="'+path('in')+'" fill="none" stroke="#73bf69" stroke-width="1.6"/>'
  +'<path d="'+path('out')+'" fill="none" stroke="#5794f2" stroke-width="1.6"/>';
 var lastIn=inUnit(win[win.length-1].in),lastOut=inUnit(win[win.length-1].out);
 document.getElementById('lin').textContent=lastIn==null?'—':lastIn.toFixed(1)+' '+unitName();
 document.getElementById('lout').textContent=lastOut==null?'—':lastOut.toFixed(1)+' '+unitName();
 document.getElementById('lpeak').textContent=max.toFixed(1)+' '+unitName();
}
async function pollLogs(){
 try{
  var r=await fetch('/ui/logs?limit=200',{cache:'no-store'}),list=await r.json();
  logCache=list||[];
  renderLogs();
 }catch(e){}
}
function renderLogs(){
 var el=document.getElementById('logs');
 var rows=logCache.filter(function(e){return logFilter==='all'||e.level!=='info'});
 el.innerHTML=rows.map(function(e){
  var t=new Date(e.at).toTimeString().slice(0,8);
  return '<div class="le'+(e.level==='warn'?' w':'')+'"><span class="t">'+t+'</span><span class="k '+esc(e.kind)+'">'+esc(e.kind)+'</span>'+(e.device?'<span class="d">'+esc(e.device)+'</span>':'<span class="d">—</span>')+'<span class="m">'+esc(e.msg)+'</span></div>';
 }).join('')||'<div class="dim" style="padding:8px">журнал пуст</div>';
}
document.querySelectorAll('[data-p]').forEach(function(b){b.onclick=function(){
 document.querySelectorAll('[data-p]').forEach(function(x){x.classList.remove('on');});b.classList.add('on');period=+b.dataset.p;draw();}});
document.getElementById('unit').onchange=function(e){unit=e.target.value;draw()};
document.getElementById('fall').onclick=function(){logFilter='all';document.getElementById('fall').classList.add('on');document.getElementById('fwarn').classList.remove('on');renderLogs()};
document.getElementById('fwarn').onclick=function(){logFilter='warn';document.getElementById('fwarn').classList.add('on');document.getElementById('fall').classList.remove('on');renderLogs()};
async function tickDevices(){
 try{
  var r=await fetch('/devices',{cache:'no-store'}),list=await r.json();
  var rows='';
  (list||[]).forEach(function(d){
   var camo=d.camouflage_off?'<span class="warn">выкл (клиент)</span>':'<span class="ok">вкл</span>';
   var online=d.online>0?'<span class="ok">'+d.online+'</span>':'<span class="dim">0</span>';
   var protos=(d.protocols||[]).join(', ')||'—';
   rows+='<tr><td class="s"><b>'+esc(d.device)+'</b></td><td>'+online+'</td><td class="s">'+esc(protos)+'</td><td>'+fmtB(d.relay_in)+'</td><td>'+fmtB(d.relay_out)+'</td><td>'+camo+'</td>'
    +'<td><button class="act" data-kick="'+esc(d.device)+'">Отключить</button> '
    +'<button class="act" data-copy="'+esc(d.device)+'">Копировать</button> '
    +'<button class="act dw" data-del="'+esc(d.device)+'">Удалить</button></td></tr>';
  });
  document.querySelector('#devs tbody').innerHTML=rows||'<tr><td colspan="7" class="dim">устройств нет</td></tr>';
  document.querySelectorAll('[data-kick]').forEach(function(b){b.onclick=function(){
   var d=b.dataset.kick;
   if(!confirm('Отключить телефон «'+d+'»?\n\nВНИМАНИЕ: без реконнекта со стороны телефона соединение может упасть НАВСЕГДА — телефон вернётся только сам.'))return;
   fetch('/devices/kick?device='+encodeURIComponent(d),{method:'POST'}).then(function(){pollLogs()});
  }});
  document.querySelectorAll('[data-del]').forEach(function(b){b.onclick=function(){
   var d=b.dataset.del;
   if(!confirm('УДАЛИТЬ телефон «'+d+'» из авторизации?\n\nТокен отзывается (hash-only), живые сессии глушатся. Возврат — только повторный enroll на сервере.'))return;
   fetch('/devices/delete?device='+encodeURIComponent(d),{method:'POST'}).then(function(r){if(!r.ok)r.text().then(function(t){alert('Не удалено: '+t)});tickDevices()});
  }});
  document.querySelectorAll('[data-copy]').forEach(function(b){b.onclick=function(){
   var s=lastStatus||{},d=b.dataset.copy;
   var port=((s.listen_tunnels||':4433').split(':').pop())||'4433';
   var link='rrp://<ТОКЕН>@'+location.hostname+':'+port+'/?pin='+encodeURIComponent(s.ca_pin||'')+'&name='+encodeURIComponent(d);
   (navigator.clipboard&&navigator.clipboard.writeText(link)||Promise.reject()).then(function(){b.textContent='Скопировано';setTimeout(function(){b.textContent='Копировать'},1200)},function(){window.prompt('Токен — из enroll:',link)});
  }});
 }catch(e){}
}
tick();setInterval(tick,2000);tickDevices();setInterval(tickDevices,5000);
</script>
</body>
</html>`

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
