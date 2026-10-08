package serverapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// ---- /status: сводка для веб-морды (/ui) и скриптов ----

type StatusReport struct {
	OK           bool             `json:"ok"`
	Version      string           `json:"version"`
	EgressIP     string           `json:"egress_ip,omitempty"`
	TunnelsUp    int64            `json:"tunnels_up"`
	StreamsOpen  int64            `json:"streams_open"`
	Devices      int              `json:"devices"`
	AuthOK       int64            `json:"auth_ok_total"`
	AuthFail     int64            `json:"auth_failures_total"`
	InboundConns int64            `json:"inbound_conns_total"`
	DefaultProto string           `json:"default_proto"`
	Protocols    []string         `json:"protocols"`
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

func (a *App) statusJSON() []byte {
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
<footer>авто-обновление 3 с · ReverseRay web UI · только чтение</footer>
<script>
function fmt(b){if(b==null||b===undefined)return"—";const u=["Б","КБ","МБ","ГБ"];let i=0,x=Number(b);while(x>=1024&&i<3){x/=1024;i++}return x.toFixed(i?1:0)+" "+u[i]}
async function tick(){
 try{
  const r=await fetch('/status',{cache:'no-store'});const s=await r.json();
  document.getElementById('sub').textContent='сервер v'+s.version+' · протокол по умолчанию: '+s.default_proto+' · egress IP: '+(s.egress_ip||'—');
  const c=[
   ['Туннели',s.tunnels_up,s.tunnels_up>0?'ok':'warn'],
   ['Открытых стримов',s.streams_open,''],
   ['Устройств',s.devices,''],
   ['Auth OK / fail',s.auth_ok_total+' / '+s.auth_failures_total,s.auth_failures_total>0?'warn':'ok'],
   ['Inbound-подключений',s.inbound_conns_total,''],
   ['Egress IP',s.egress_ip||'—',''],
  ];
  document.getElementById('cards').innerHTML=c.map(([k,v,cls])=>
   '<div class="card"><div class="k">'+k+'</div><div class="v '+cls+'">'+v+'</div></div>').join('');
  const rows=(s.sessions||[]).map(x=>
   '<tr><td>'+(x.device||'?')+'</td><td><code>'+String(x.session||'').slice(0,10)+'…</code></td>'+
   '<td>'+(x.proto||'—')+'</td><td>'+(x.rtt_ms!=null?x.rtt_ms+' мс':'—')+'</td>'+
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
