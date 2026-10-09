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
<meta name="color-scheme" content="dark light">
<title>ReverseRay · панель</title>
<style>
:root{
 --bg:#070b16;--bg2:#0b1122;--card:#101830;--card2:#141d38;--line:#1e2b52;--line2:#27386b;
 --tx:#e6edff;--mut:#8fa3d9;--ok:#39d98a;--warn:#f9a825;--err:#ff6b6b;--acc:#4fc3f7;--acc2:#7c6bff;
 --in:#39d98a;--out:#4fc3f7;--r:14px;--grid:#1e2b52;--axis:#8fa3d9;
}
@media (prefers-color-scheme:light){
 :root{
  --bg:#f3f5fb;--bg2:#ffffff;--card:#ffffff;--card2:#eef1fa;--line:#d7deee;--line2:#c3cde6;
  --tx:#1c2440;--mut:#5a6a94;--ok:#149a5c;--warn:#b07a00;--err:#d04545;--acc:#0f7dc2;--acc2:#5b4bd6;
  --in:#149a5c;--out:#0f7dc2;--grid:#dfe5f2;--axis:#7787b0;
 }
 body{background:radial-gradient(1200px 600px at 80% -10%,#e6ecff 0%,var(--bg) 55%) fixed,var(--bg)}
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
.sw.dash{background:repeating-linear-gradient(90deg,var(--mut) 0 4px,transparent 4px 8px)}
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
 <svg id="chart" viewBox="0 0 640 200" role="img" aria-label="График трафика в реальном времени">
  <defs>
   <linearGradient id="gIn" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#39d98a" stop-opacity=".35"/><stop offset="1" stop-color="#39d98a" stop-opacity="0"/>
   </linearGradient>
   <linearGradient id="gOut" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#4fc3f7" stop-opacity=".35"/><stop offset="1" stop-color="#4fc3f7" stop-opacity="0"/>
   </linearGradient>
  </defs>
  <g id="gridLines" stroke="var(--grid)" stroke-width="1"></g>
  <g id="gridLabels" fill="var(--axis)" font-size="10" font-family="system-ui,sans-serif"></g>
  <path id="areaIn" fill="url(#gIn)"/><path id="areaOut" fill="url(#gOut)"/>
  <path id="peakIn" fill="none" stroke="var(--axis)" stroke-width="1" stroke-dasharray="2 4"/>
  <path id="peakOut" fill="none" stroke="var(--axis)" stroke-width="1" stroke-dasharray="2 4"/>
  <path id="emaIn" fill="none" stroke="var(--axis)" stroke-width="1.5" stroke-dasharray="6 4"/>
  <path id="emaOut" fill="none" stroke="var(--axis)" stroke-width="1.5" stroke-dasharray="6 4"/>
  <path id="lineIn" fill="none" stroke="var(--in)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
  <path id="lineOut" fill="none" stroke="var(--out)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
 </svg>
 <div class="legend">
  <span><span class="sw" style="background:var(--in)"></span>Вход rx (телефон→сервер) <b id="rateIn">0 Б/с</b></span>
  <span><span class="sw" style="background:var(--out)"></span>Выход tx (сервер→телефон) <b id="rateOut">0 Б/с</b></span>
  <span><span class="sw dash"></span>среднее (EMA) · пик</span>
  <span class="muted">окно 90 с · шаг 2 с</span>
 </div>
</div>

<div class="sec">Клиенты</div>
<div id="clients" class="cols"></div>

<footer>авто-обновление 2 с · ReverseRay web UI</footer>
<script>
'use strict';
var histIn=[],histOut=[],emaIn=[],emaOut=[],lastRelay=null,lastAt=null,N=45;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function fmt(b){if(b==null||b===undefined)return'—';const u=['Б','КБ','МБ','ГБ','ТБ'];let i=0,x=Number(b);while(x>=1024&&i<4){x/=1024;i++}return (i?x.toFixed(1):x)+' '+u[i]}
function fmtR(b){if(!b)return'0 Б/с';const u=['Б/с','КБ/с','МБ/с','ГБ/с'];let i=0,x=b;while(x>=1024&&i<3){x/=1024;i++}return x.toFixed(i?1:0)+' '+u[i]}
function fmtUp(sec){sec=Math.max(0,sec|0);const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);return (d?d+' д ':'')+(h?h+' ч ':'')+m+' мин'}
function protoLabel(id,s){const l=(s.protocol_labels||{})[id]||id;const v=(s.protocol_vers||{})[id];return v?l+' · v'+v:l}
// KPI-карточка выводится только если поле несёт данные (канон v0.9.6)
function kpiCards(list){
 return list.filter(function(kv){return kv[1]!==null&&kv[1]!==undefined&&kv[1]!==0&&kv[1]!==''&&kv[1]!=='0'})
 .map(function(kv){return '<div class="card"><div class="k">'+kv[0]+'</div><div class="v '+kv[2]+'">'+kv[1]+'</div></div>'}).join('');
}
// сглаживание Катмулла-Рома: точки → кубические безье
function smoothPath(pts){
 if(pts.length<2)return '';
 if(pts.length===2)return 'M'+pts[0][0]+' '+pts[0][1]+' L'+pts[1][0]+' '+pts[1][1];
 let d='M'+pts[0][0].toFixed(1)+' '+pts[0][1].toFixed(1);
 for(let i=0;i<pts.length-1;i++){
  const p0=pts[Math.max(0,i-1)],p1=pts[i],p2=pts[i+1],p3=pts[Math.min(pts.length-1,i+2)];
  const c1x=p1[0]+(p2[0]-p0[0])/6,c1y=p1[1]+(p2[1]-p0[1])/6;
  const c2x=p2[0]-(p3[0]-p1[0])/6,c2y=p2[1]-(p3[1]-p1[1])/6;
  d+=' C'+c1x.toFixed(1)+' '+c1y.toFixed(1)+' '+c2x.toFixed(1)+' '+c2y.toFixed(1)+' '+p2[0].toFixed(1)+' '+p2[1].toFixed(1);
 }
 return d;
}
function toPts(arr,mx,x0,x1,y0,y1){
 const n=N,sx=(x1-x0)/(n-1),p=[];
 for(let i=0;i<n;i++){const v=arr[i]||0;p.push([x0+i*sx,y1-(v/mx)*(y1-y0)])}
 return p;
}
function drawChart(){
 const w=640,h=200,padL=56,padR=10,padT=12,padB=20;
 const x0=padL,x1=w-padR,y0=padT,y1=h-padB;
 let mx=1;for(let i=0;i<N;i++){mx=Math.max(mx,histIn[i]||0,histOut[i]||0)}
 // сетка: 5 горизонтальных линий с подписями скорости
 let gl='',lb='';
 for(let k=0;k<5;k++){
  const y=(y1-(y1-y0)*k/4).toFixed(1);
  gl+='<line x1="'+x0+'" y1="'+y+'" x2="'+x1+'" y2="'+y+'"/>';
  lb+='<text x="'+(x0-6)+'" y="'+(+y+3.5)+'" text-anchor="end">'+fmtR(mx*k/4)+'</text>';
 }
 // ось времени: -90с … 0
 for(let k=0;k<=4;k++){
  const x=(x0+(x1-x0)*k/4).toFixed(0);
  lb+='<text x="'+x+'" y="'+(h-5)+'" text-anchor="middle">-'+(90-90*k/4)+'с</text>';
 }
 document.getElementById('gridLines').innerHTML=gl;
 document.getElementById('gridLabels').innerHTML=lb;
 const pIn=toPts(histIn,mx,x0,x1,y0,y1),pOut=toPts(histOut,mx,x0,x1,y0,y1);
 document.getElementById('lineIn').setAttribute('d',smoothPath(pIn));
 document.getElementById('lineOut').setAttribute('d',smoothPath(pOut));
 document.getElementById('areaIn').setAttribute('d',smoothPath(pIn)+' L'+x1+' '+y1+' L'+x0+' '+y1+' Z');
 document.getElementById('areaOut').setAttribute('d',smoothPath(pOut)+' L'+x1+' '+y1+' L'+x0+' '+y1+' Z');
 // EMA (плавное среднее) и пик — пунктиром
 const eIn=[],eOut=[];let peak=0;
 for(let i=0;i<N;i++){
  const a=histIn[i]||0,b=histOut[i]||0;
  emaIn[i]=(i?emaIn[i-1]*0.7+a*0.3:a);emaOut[i]=(i?emaOut[i-1]*0.7+b*0.3:b);
  peak=Math.max(peak,a,b);
  eIn.push([x0+i*((x1-x0)/(N-1)),y1-(emaIn[i]/mx)*(y1-y0)]);
  eOut.push([x0+i*((x1-x0)/(N-1)),y1-(emaOut[i]/mx)*(y1-y0)]);
 }
 document.getElementById('emaIn').setAttribute('d',smoothPath(eIn));
 document.getElementById('emaOut').setAttribute('d',smoothPath(eOut));
 const yPk=(y1-peak/mx*(y1-y0)).toFixed(1);
 document.getElementById('peakIn').setAttribute('d','M'+x0+' '+yPk+' L'+x1+' '+yPk);
 document.getElementById('peakOut').setAttribute('d','M'+x0+' '+yPk+' L'+x1+' '+yPk);
 document.getElementById('rateIn').textContent=fmtR(histIn[histIn.length-1]||0);
 document.getElementById('rateOut').textContent=fmtR(histOut[histOut.length-1]||0);
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
   +(s.egress_ip?'<span>egress IP: <code>'+esc(s.egress_ip)+'</code></span>':'')
   +(s.cert_not_after?'<span>серт TLS до '+esc(s.cert_not_after.slice(0,10))+'</span>':'');
  // KPI: нули и пустоты не выводим (канон v0.9.6)
  const c=[
   ['Туннели',s.tunnels_up,s.tunnels_up>0?'ok':'warn'],
   ['Открытых стримов',s.streams_open||null,''],
   ['Auth OK / fail',s.auth_ok_total?s.auth_ok_total+' / '+s.auth_failures_total:null,s.auth_failures_total>0?'warn':'ok'],
   ['Устройств',s.devices||null,''],
   ['Релея всего',s.bytes_relayed_total?fmt(s.bytes_relayed_total):null,'acc'],
   ['UDP-дейтаграмм',s.udp_datagrams_total||null,''],
   ['Uptime',s.uptime_sec?fmtUp(s.uptime_sec):null,''],
   ['RAM (alloc)',s.mem_alloc_mb?fmt(s.mem_alloc_mb*1048576):null,''],
  ];
  document.getElementById('cards').innerHTML=kpiCards(c);
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
  // карточки клиентов — рендерит сервер (пустые поля не приходят вовсе)
  const cr=await fetch('/ui/cards',{cache:'no-store'});
  document.getElementById('clients').innerHTML=await cr.text();
 }catch(e){document.getElementById('sub').textContent='ошибка: '+e}
}
tick();setInterval(tick,2000);
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
}
