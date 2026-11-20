package serverapp

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
svg.chart{width:100%;height:240px;display:block}
.tip{position:absolute;pointer-events:none;background:#0d0e12;border:1px solid var(--border);border-radius:4px;padding:5px 8px;font-size:11px;font-family:var(--mono);color:var(--txt);display:none;z-index:8;white-space:nowrap}
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
 <div class="sp"></div>
</div>
<div class="wrap">
 <div class="grid kpis" id="kpis"></div>
 <div class="grid" style="margin-top:10px">
  <div class="panel">
   <h3><span>Устройства</span><span class="ctrl dim">hash-only</span></h3>
   <div style="overflow-x:auto"><table id="devs"><thead><tr>
    <th>Устройство</th><th>Сессий</th><th>Протоколы</th><th>↓ релей</th><th>↑ релей</th><th>Действия</th>
   </tr></thead><tbody></tbody></table></div>
   <h3 style="margin-top:14px"><span>Туннели</span><span class="ctrl dim" id="parkinfo"></span></h3>
   <div style="overflow-x:auto"><table id="sess"><thead><tr>
    <th>Устройство</th><th>Протокол</th><th>Транспорт</th><th>RTT</th><th>Потоки</th><th>Окно</th><th>↓ всего</th><th>↑ всего</th><th>↓/с</th><th>↑/с</th><th>Ошибки диала</th><th>Аптайм</th>
   </tr></thead><tbody></tbody></table></div>
  </div>
 </div>
 <div class="panel" style="margin-top:10px">
  <h3><span>Трафик через туннель</span>
    <span class="ctrl">
     <button data-p="150" class="on">5 мин</button><button data-p="450">15 мин</button><button data-p="1800">1 ч</button>
     <select id="unit"><option value="b">Б/с</option><option value="kb" selected>КБ/с</option><option value="mb">МБ/с</option><option value="mbit">Мбит/с</option></select>
    </span></h3>
   <svg class="chart" id="chart" preserveAspectRatio="none" viewBox="0 0 1000 190"></svg>
   <div class="legend"><span><i style="background:var(--green)"></i>входящий <b id="lin" class="mono">—</b></span><span><i style="background:var(--blue)"></i>исходящий <b id="lout" class="mono">—</b></span><span>пик <b id="lpeak" class="mono">—</b></span></div>
  </div>
 <div class="panel" style="margin-top:10px">
   <h3><span>Журнал событий</span>
    <span class="ctrl"><button id="fall" class="on">все</button><button id="fwarn">предупреждения</button></span></h3>
   <div class="logs" id="logs"></div>
 </div>
 <div class="foot">
  <span>версия <b id="ver">—</b></span><span>uptime <b id="upt">—</b></span><span>egress <b class="mono" id="eg">—</b></span><span>сертификат до <b id="cert">—</b></span><span id="env"></span><span>GET /status</span><span>GET /metrics — Prometheus</span><span>GET /ui/logs</span><span>GET /healthz · /readyz</span>
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
  var k=[
   stat('Туннели',s.tunnels_up,s.tunnels_up>0?'ok':'bad'),
   stat('Открытых потоков',s.streams_open||null,'mut'),
   stat('В буфере трафика',s.parked_streams||null,s.parked_streams?'acc':'mut','стримов'),
   stat('Устройств',s.devices||null,'mut'),
   stat('Пропущено всего',fmtB(s.bytes_relayed_total),'acc'),
   stat('Авторизаций устройств',s.auth_ok_total||null,'ok'),
   stat('UDP-дейтаграмм',s.udp_datagrams_total||null,'mut'),
   stat('WS-туннелей',s.ws_tunnels||null,'mut'),
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
  var env=document.getElementById('env');
  if(env)env.textContent='Go '+(s.go_version||'—')+' · '+(s.goos||'')+'/'+(s.goarch||'')+(s.modules_version?' · модули v'+s.modules_version:'');
 }catch(e){var d=document.getElementById('dot');if(d)d.className='dot warn'}
 pollLogs();
}
function niceCeil(v){if(v<=0)return 1;var e=Math.pow(10,Math.floor(Math.log(v)/Math.LN10)),m=v/e;return(m<=1?1:m<=2?2:m<=5?5:10)*e}
function draw(){
 var svg=document.getElementById('chart');
 var win=hist.slice(-period);
 if(win.length<2){svg.innerHTML='<text x="12" y="120" fill="#8e9095" font-size="13">сбор данных…</text>';return}
 var W=1000,H=240,pl=64,pr=12,pt=10,pb=22;
 var max=0;win.forEach(function(x){var a=inUnit(x.in)||0,b=inUnit(x.out)||0;if(a>max)max=a;if(b>max)max=b});
 max=niceCeil(max);
 var pw=W-pl-pr,ph=H-pt-pb,x0=pl,y0=H-pb;
 function px(i){return x0+pw*i/(win.length-1)}
 function py(v){return y0-ph*(v/max)}
 function path(key){var d='M'+px(0).toFixed(1)+' '+py(inUnit(win[0][key])||0).toFixed(1)+' ';for(var i=1;i<win.length;i++)d+='L'+px(i).toFixed(1)+' '+py(inUnit(win[i][key])||0).toFixed(1)+' ';return d}
 function area(key){return path(key)+'L'+px(win.length-1).toFixed(1)+' '+y0+' L'+px(0).toFixed(1)+' '+y0+' Z'}
 var ticks='',i,v;
 for(i=0;i<=4;i++){v=max*i/4;var yy=y0-ph*i/4;
  ticks+='<line x1="'+x0+'" y1="'+yy.toFixed(1)+'" x2="'+(x0+pw)+'" y2="'+yy.toFixed(1)+'" stroke="#23262c" stroke-dasharray="'+(i%4?'2 3':'0')+'"/>'
  +'<text x="'+(x0-6)+'" y="'+(yy+3).toFixed(1)+'" fill="#8e9095" font-size="9" text-anchor="end">'+fmtR(v)+'</text>'}
 // подписи времени по X: ~6 равномерных меток
 var tl='',n=win.length,step=Math.max(1,Math.floor(n/6));
 for(i=n-1;i>=0;i-=step){var d=new Date(win[i].t);tl+='<text x="'+px(i).toFixed(1)+'" y="'+(H-6)+'" fill="#8e9095" font-size="9" text-anchor="middle">'+d.toTimeString().slice(0,5)+'</text>'}
 var g=''
  +'<defs><linearGradient id="gin" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#73bf69" stop-opacity="0.35"/><stop offset="1" stop-color="#73bf69" stop-opacity="0"/></linearGradient>'
  +'<linearGradient id="gout" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5794f2" stop-opacity="0.30"/><stop offset="1" stop-color="#5794f2" stop-opacity="0"/></linearGradient></defs>'
  +ticks
  +'<path d="'+area('out')+'" fill="url(#gout)"/><path d="'+area('in')+'" fill="url(#gin)"/>'
  +'<path d="'+path('out')+'" fill="none" stroke="#5794f2" stroke-width="1.6" stroke-linejoin="round"/>'
  +'<path d="'+path('in')+'" fill="none" stroke="#73bf69" stroke-width="1.6" stroke-linejoin="round"/>';
 // hover: вертикаль + маркеры ближайшей точки
 var hover=window.__chartHover||(window.__chartHover={});
 if(hover&&hover.i!=null){var hi=Math.max(0,Math.min(n-1,hover.i));
  g+='<line x1="'+px(hi)+'" y1="'+pt+'" x2="'+px(hi)+'" y2="'+y0+'" stroke="#8e9095" stroke-opacity="0.5"/>'
  +'<circle cx="'+px(hi)+'" cy="'+py(inUnit(win[hi].in)||0)+'" r="2.5" fill="#73bf69"/>'
  +'<circle cx="'+px(hi)+'" cy="'+py(inUnit(win[hi].out)||0)+'" r="2.5" fill="#5794f2"/>'}
 svg.innerHTML=g;
 var lastIn=inUnit(win[n-1].in),lastOut=inUnit(win[n-1].out);
 document.getElementById('lin').textContent=lastIn==null?'—':lastIn.toFixed(1)+' '+unitName();
 document.getElementById('lout').textContent=lastOut==null?'—':lastOut.toFixed(1)+' '+unitName();
 document.getElementById('lpeak').textContent=max.toFixed(1)+' '+unitName();
}
// hover-обработчики: crosshair + тултип (Grafana-style)
(function(){
 var svg=document.getElementById('chart'),tip=null,ht={i:null};
 svg.addEventListener('mousemove',function(e){
  var win=hist.slice(-period);if(win.length<2)return;
  var r=svg.getBoundingClientRect(),W=1000,pl=64,pr=12,x0=pl,pw=W-pl-pr;
  var mx=(e.clientX-r.left)/r.width*W;
  var i=Math.round((mx-x0)/pw*(win.length-1));i=Math.max(0,Math.min(win.length-1,i));
  window.__chartHover={i:i};draw();
  if(!tip){tip=document.createElement('div');tip.className='tip';document.body.appendChild(tip)}
  var d=new Date(win[i].t);
  tip.innerHTML='<b>'+d.toTimeString().slice(0,8)+'</b><br><span style="color:#73bf69">↓ '+fmtR(inUnit(win[i].in))+'</span><br><span style="color:#5794f2">↑ '+fmtR(inUnit(win[i].out))+'</span>';
  tip.style.display='block';
  var lx=e.clientX+12,ly=e.clientY+12;
  if(lx+140>window.innerWidth)lx=e.clientX-150;
  tip.style.left=lx+'px';tip.style.top=ly+'px';
 });
 svg.addEventListener('mouseleave',function(){window.__chartHover={};draw();if(tip)tip.style.display='none'});
})();async function pollLogs(){
 try{
  var r=await fetch('/ui/logs?limit=200',{cache:'no-store'}),list=await r.json();
  logCache=list||[];
  renderLogs();
 }catch(e){}
}
function renderLogs(){
 var el=document.getElementById('logs');
 var rows=logCache.filter(function(e){return logFilter==='all'||e.level!=='INFO'});
 el.innerHTML=rows.map(function(e){
  var t=new Date(e.at).toTimeString().slice(0,8);
  return '<div class="le'+(e.level==='WARN'?' w':'')+'"><span class="t">'+t+'</span><span class="k '+esc(e.kind)+'">'+esc(e.kind)+'</span>'+(e.device?'<span class="d">'+esc(e.device)+'</span>':'<span class="d">—</span>')+'<span class="m">'+esc(e.msg)+'</span></div>';
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
