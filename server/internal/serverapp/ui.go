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
	// v0.9.5: выборы камуфляжа клиентов (кадр 0x2A): устройство → выключен.
	CamoOverrides map[string]bool `json:"camouflage_off,omitempty"`
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
	s.CamoOverrides = a.CamouflageOverrides() // v0.9.5: выборы клиентов
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
// Скейлится от узких телефонов до ультрашироких мониторов (CSS clamp/grid).

const uiHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>ReverseRay · панель</title>
<style>
:root{
 --bg:#070b16;--bg2:#0b1122;--card:#101830;--card2:#141d38;--line:#1e2b52;--line2:#27386b;
 --tx:#e6edff;--mut:#8fa3d9;--ok:#39d98a;--warn:#f9a825;--err:#ff6b6b;--acc:#4fc3f7;--acc2:#7c6bff;
 --in:#39d98a;--out:#4fc3f7;--r:14px;
}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{background:radial-gradient(1200px 600px at 80% -10%,#12204a 0%,var(--bg) 55%) fixed,var(--bg);
 color:var(--tx);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
 padding:clamp(10px,2.5vw,26px);max-width:1500px;margin:0 auto}
h1{font-size:clamp(19px,2.6vw,26px);letter-spacing:.01em;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sub{color:var(--mut);font-size:clamp(11px,1.5vw,13px);margin:4px 0 16px;display:flex;gap:8px 18px;flex-wrap:wrap}
.chip{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:2px 10px;font-size:11.5px;white-space:nowrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px rgba(57,217,138,.14);animation:p 2s infinite}
.dot.warn{background:var(--warn);box-shadow:0 0 0 4px rgba(249,168,37,.14)}
.dot.err{background:var(--err);box-shadow:0 0 0 4px rgba(255,107,107,.14)}
@keyframes p{50%{opacity:.55}}
@media (prefers-reduced-motion:reduce){.dot{animation:none}}
.grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));margin-bottom:12px}
.card{background:linear-gradient(180deg,var(--card),var(--bg2));border:1px solid var(--line);border-radius:var(--r);
 padding:13px 15px;min-width:0;transition:border-color .2s}
.card:hover{border-color:var(--line2)}
.k{color:var(--mut);font-size:10.5px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:3px}
.v{font-size:clamp(17px,2.2vw,22px);font-weight:700;font-variant-numeric:tabular-nums;word-break:break-word}
.v small{font-size:.55em;color:var(--mut);font-weight:600}
.ok{color:var(--ok)}.warn{color:var(--warn)}.err{color:var(--err)}.acc{color:var(--acc)}
.sec{margin:18px 0 8px;font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.12em;
 display:flex;align-items:center;gap:10px}
.sec::after{content:"";flex:1;height:1px;background:var(--line)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--mut);text-align:left;font-weight:600;padding:7px 9px;border-bottom:1px solid var(--line);white-space:nowrap;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
td{padding:7px 9px;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums;word-break:break-word;vertical-align:top}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:10.5px;font-weight:700;letter-spacing:.04em;border:1px solid}
.b-green{color:var(--ok);border-color:rgba(57,217,138,.4);background:rgba(57,217,138,.08)}
.b-blue{color:var(--acc);border-color:rgba(79,195,247,.4);background:rgba(79,195,247,.08)}
.b-purple{color:var(--acc2);border-color:rgba(124,107,255,.45);background:rgba(124,107,255,.1)}
.b-gray{color:var(--mut);border-color:var(--line2);background:rgba(143,163,217,.06)}
.num{font-variant-numeric:tabular-nums}
code{background:var(--card2);padding:1px 6px;border-radius:6px;font-size:11.5px;color:var(--mut)}
footer{color:var(--mut);font-size:11px;margin-top:16px;text-align:center}
.chartwrap{position:relative}
svg{width:100%;height:auto;display:block}
.legend{display:flex;gap:16px;font-size:12px;color:var(--mut);flex-wrap:wrap;margin-top:6px}
.legend b{color:var(--tx);font-variant-numeric:tabular-nums}
.sw{display:inline-block;width:14px;height:3px;border-radius:2px;vertical-align:middle;margin-right:6px}
.muted{color:var(--mut)}
.cols{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}
@media (max-width:560px){th:nth-child(9),td:nth-child(9){display:none}}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
</style>
</head>
<body>
<h1><span class="dot" id="dot"></span>ReverseRay — панель <span class="chip" id="ver">…</span></h1>
<div class="sub" id="sub">загрузка…</div>
<div class="grid" id="cards" aria-live="off"></div>

<div class="sec" id="traffic-sec">Трафик в реальном времени</div>
<div class="card chartwrap">
 <svg id="chart" viewBox="0 0 600 160" preserveAspectRatio="none" role="img" aria-label="График трафика в реальном времени">
  <defs>
   <linearGradient id="gIn" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#39d98a" stop-opacity=".35"/><stop offset="1" stop-color="#39d98a" stop-opacity="0"/>
   </linearGradient>
   <linearGradient id="gOut" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#4fc3f7" stop-opacity=".35"/><stop offset="1" stop-color="#4fc3f7" stop-opacity="0"/>
   </linearGradient>
  </defs>
  <g id="gridLines" stroke="#1e2b52" stroke-width="1"></g>
  <path id="areaIn" fill="url(#gIn)"/><path id="areaOut" fill="url(#gOut)"/>
  <path id="lineIn" fill="none" stroke="#39d98a" stroke-width="2" stroke-linejoin="round"/>
  <path id="lineOut" fill="none" stroke="#4fc3f7" stroke-width="2" stroke-linejoin="round"/>
  <text id="scaleHi" x="6" y="14" fill="#8fa3d9" font-size="11"></text>
 </svg>
 <div class="legend">
  <span><span class="sw" style="background:#39d98a"></span>Вход (телефон→сервер) <b id="rateIn">0 Б/с</b></span>
  <span><span class="sw" style="background:#4fc3f7"></span>Выход (сервер→телефон) <b id="rateOut">0 Б/с</b></span>
  <span class="muted">окно 90 с · шаг 2 с</span>
 </div>
</div>

<div class="sec">Клиенты</div>
<div id="clients" class="cols"></div>

<footer>авто-обновление 2 с · ReverseRay web UI</footer>
<script>
'use strict';
var histIn=[],histOut=[],lastRelay=null,lastAt=null,N=45;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function fmt(b){if(b==null||b===undefined)return'—';const u=['Б','КБ','МБ','ГБ','ТБ'];let i=0,x=Number(b);while(x>=1024&&i<4){x/=1024;i++}return (i?x.toFixed(1):x)+' '+u[i]}
function fmtR(b){if(!b)return'0 Б/с';const u=['Б/с','КБ/с','МБ/с','ГБ/с'];let i=0,x=b;while(x>=1024&&i<3){x/=1024;i++}return x.toFixed(i?1:0)+' '+u[i]}
function fmtUp(sec){sec=Math.max(0,sec|0);const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);return (d?d+' д ':'')+(h?h+' ч ':'')+m+' мин'}
function protoLabel(id,s){const l=(s.protocol_labels||{})[id]||id;const v=(s.protocol_vers||{})[id];return v?l+' · v'+v:l}
function protoBadge(id,s){if(id==='mtproto2')return'<span class="badge b-green">MTProto/2</span>';
 if(id==='wireguard')return'<span class="badge b-purple">WireGuard/1</span>';
 return'<span class="badge b-blue">'+esc(protoLabel(id,s))+'</span>'}
function drawChart(){
 const w=600,h=160,pad=6,n=N;
 let mx=1;for(let i=0;i<n;i++){mx=Math.max(mx,histIn[i]||0,histOut[i]||0)}
 const sx=w/ (n-1);
 function pts(arr){let p='';for(let i=0;i<n;i++){const v=arr[i]||0;const y=h-pad-(v/mx)*(h-2*pad);p+=(i?'L':'M')+(i*sx).toFixed(1)+' '+y.toFixed(1)}return p}
 function area(arr){return pts(arr)+' L'+w+' '+h+' L0 '+h+' Z'}
 document.getElementById('lineIn').setAttribute('d',pts(histIn));
 document.getElementById('lineOut').setAttribute('d',pts(histOut));
 document.getElementById('areaIn').setAttribute('d',area(histIn));
 document.getElementById('areaOut').setAttribute('d',area(histOut));
 let gl='';for(let k=1;k<4;k++){const y=(h/4*k).toFixed(0);gl+='<line x1="0" y1="'+y+'" x2="'+w+'" y2="'+y+'"/>'}
 document.getElementById('gridLines').innerHTML=gl;
 document.getElementById('scaleHi').textContent=fmt(mx)+'/с';
 document.getElementById('rateIn').textContent=fmtR(histIn[histIn.length-1]||0);
 document.getElementById('rateOut').textContent=fmtR(histOut[histOut.length-1]||0);
}
function clientCard(x,s){
 const mt=x.mt_active?'<span class="badge b-green" title="payload'+"'"+'ы DATA/UDP_DATA зашифрованы конвертом протокола">крипта вкл</span>':'<span class="badge b-gray">без конверта</span>';
 const camoOff=(s.camouflage_off||{})[x.device];
 const camo=camoOff?'<span class="badge b-gray">API Mask выкл (клиентом)</span>':
  ((s.camouflage&&s.camouflage.enabled)?'<span class="badge b-blue">API Mask</span>':'');
 return '<div class="card">'
 +'<div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline;flex-wrap:wrap">'
 +'<div class="v" style="font-size:clamp(15px,1.8vw,19px)">'+esc(x.device)+'</div>'+mt+'</div>'
 +'<div style="margin:6px 0 10px;display:flex;gap:6px;flex-wrap:wrap">'+protoBadge(x.proto,s)+camo+'</div>'
 +'<table>'
 +'<tr><td class="k">RTT</td><td class="num">'+(x.rtt_ms!=null?x.rtt_ms+' мс':'—')+'</td>'
 +'<td class="k">Uptime</td><td class="num">'+fmtUp(x.uptime_sec||0)+'</td></tr>'
 +'<tr><td class="k">Стримы</td><td class="num">'+(x.streams||0)+'</td>'
 +'<td class="k">В полёте</td><td class="num">'+fmt(x.outstanding)+'</td></tr>'
 +'<tr><td class="k">↓ relay</td><td class="num ok">'+fmt(x.relay_in)+'</td>'
 +'<td class="k">↑ relay</td><td class="num">'+fmt(x.relay_out)+'</td></tr>'
 +'<tr><td class="k">↓ телефон</td><td class="num ok">'+fmt(x.bytes_in)+'</td>'
 +'<td class="k">↑ телефон</td><td class="num">'+fmt(x.bytes_out)+'</td></tr>'
 +'<tr><td class="k">UDP</td><td class="num">'+(x.udp||0)+'</td>'
 +'<td class="k">DNS</td><td class="num">'+(x.dns||0)+'</td></tr>'
 +'</table>'
 +'<div class="muted" style="margin-top:8px;font-size:11.5px">сессия <code>'+esc(String(x.session||'').slice(0,13))+'…</code> · с '+esc(x.connected_at?new Date(x.connected_at*1000).toLocaleTimeString():'—')+'</div>'
 +'</div>';
}
async function tick(){
 try{
  const r=await fetch('/status',{cache:'no-store'});const s=await r.json();
  const dot=document.getElementById('dot');
  dot.className='dot'+(s.tunnels_up>0?'':' warn');
  document.getElementById('ver').textContent='v'+s.version;
  document.getElementById('sub').innerHTML=
   '<span>'+protoLabel(s.default_proto,s)+' по умолчанию</span>'
   +'<span>реестр: '+esc((s.protocols||[]).map(function(p){return protoLabel(p,s)}).join(' · '))+'</span>'
   +'<span>egress IP: <code>'+esc(s.egress_ip||'—')+'</code></span>'
   +(s.cert_not_after?'<span>серт TLS до '+esc(s.cert_not_after.slice(0,10))+'</span>':'');
  // KPI
  const c=[
   ['Туннели',s.tunnels_up,s.tunnels_up>0?'ok':'warn'],
   ['Открытых стримов',s.streams_open,''],
   ['Auth OK / fail',s.auth_ok_total+' / '+s.auth_failures_total,s.auth_failures_total>0?'warn':'ok'],
   ['Устройств',s.devices,''],
   ['Релея всего',fmt(s.bytes_relayed_total||0),'acc'],
   ['UDP-дейтаграмм',s.udp_datagrams_total||0,''],
   ['Uptime',fmtUp(s.uptime_sec||0),''],
   ['RAM (alloc)',fmt((s.mem_alloc_mb||0)*1048576),''],
  ];
  document.getElementById('cards').innerHTML=c.map(function(kv){
   return '<div class="card"><div class="k">'+kv[0]+'</div><div class="v '+kv[2]+'">'+kv[1]+'</div></div>'}).join('');
  // скорость из дельт BytesRelayed (общий relay)
  const now=Date.now();
  let rIn=0,rOut=0;
  const sess=s.sessions||[];
  if(lastRelay&&lastAt){
   const dt=Math.max(1,(now-lastAt)/1000);
   let dIn=0,dOut=0;
   sess.forEach(function(x){
    const p=lastRelay[x.session];
    if(p){dIn+=Math.max(0,(x.relay_in||0)-p[0]);dOut+=Math.max(0,(x.relay_out||0)-p[1])}
   });
   rIn=dIn/dt;rOut=dOut/dt;
  }
  lastAt=now;lastRelay={};
  sess.forEach(function(x){lastRelay[x.session]=[x.relay_in||0,x.relay_out||0]});
  histIn.push(rIn);histOut.push(rOut);
  if(histIn.length>N){histIn.shift();histOut.shift()}
  drawChart();
  // клиенты
  const cl=document.getElementById('clients');
  if(!sess.length){cl.innerHTML='<div class="card muted">нет активных сессий — подключите APK (rrp:// ссылка)</div>'}
  else{cl.innerHTML=sess.map(function(x){return clientCard(x,s)}).join('')}
 }catch(e){document.getElementById('sub').textContent='ошибка: '+e}
}
tick();setInterval(tick,2000);
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
