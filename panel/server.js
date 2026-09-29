#!/usr/bin/env node
/* Faxina · Visão Técnica das VPS — painel web (Node stdlib puro, sem dependências).
 * Aglutina o Caça-Loops (loops) + Mecânico Preventivo (faxina) numa só visão.
 * Acesso: nginx só aceita origem Tailscale (guardian.example.com -> IP Tailscale). Sem senha.
 * Mostra semáforo por área/categoria, botões de AÇÃO SEGURA, e código por item p/ aprofundar no Claude.
 */
'use strict';
const http = require('http');
const fs = require('fs');
const { execFileSync } = require('child_process');

const HUNTER = '/root/loop-hunter';
const CFG = JSON.parse(fs.readFileSync(HUNTER + '/config.json', 'utf8'));
const BIND_IP = process.env.LH_BIND || '127.0.0.1';
const PORT = parseInt(process.env.LH_PORT || '9777', 10);
const AUDIT = __dirname + '/actions.log';

const VPS = {
  main: { label: 'main', remote: null },
};
const SAFE_ACTIONS = new Set(['reset_counter', 'rotate_log']);

function audit(line){ try{ fs.appendFileSync(AUDIT, new Date().toISOString()+' '+line+'\n'); }catch(e){} }
function sh(args, timeout){ try { return execFileSync(args[0], args.slice(1), {encoding:'utf8', timeout: timeout||15000, maxBuffer: 8*1024*1024}); } catch(e){ return (e.stdout||''); } }
function shq(s){ return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

function readReport(vpsKey){
  const v = VPS[vpsKey]; let raw;
  if (!v.remote) { try { raw = fs.readFileSync(HUNTER+'/reports/latest.json','utf8'); } catch(e){ return {error:'sem relatório ainda'}; } }
  else { raw = sh(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8', v.remote, 'cat /root/loop-hunter/reports/latest.json'], 15000);
         if(!raw) return {error:'server-2 inalcançável ou sem relatório'}; }
  try { return JSON.parse(raw); } catch(e){ return {error:'relatório inválido'}; }
}
function readInventory(vpsKey){
  const v = VPS[vpsKey]; let raw;
  if (!v.remote) { try { raw = fs.readFileSync(HUNTER+'/reports/inventory.json','utf8'); } catch(e){ return {error:'sem inventário ainda (roda no scan profundo)'}; } }
  else { raw = sh(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8', v.remote, 'cat /root/loop-hunter/reports/inventory.json'], 15000);
         if(!raw) return {error:'server-2 inalcançável ou sem inventário'}; }
  try { return JSON.parse(raw); } catch(e){ return {error:'inventário inválido'}; }
}
function runScan(vpsKey, mode){
  const v = VPS[vpsKey]; const m = mode==='leve'?'--leve':'--profundo';
  if (!v.remote) sh(['bash', HUNTER+'/hunt.sh', m], 125000);
  else sh(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8', v.remote, 'bash /root/loop-hunter/hunt.sh '+m], 125000);
}
function runAction(vpsKey, finding){
  const a = finding.action;
  if (!a || !SAFE_ACTIONS.has(a.type)) throw new Error('ação não permitida no painel');
  const v = VPS[vpsKey];
  const argv = [a.type, a.file].concat(a.type==='reset_counter' ? [a.key] : []);
  let out;
  if (!v.remote) out = sh(['bash', HUNTER+'/act.sh'].concat(argv), 30000);
  else out = sh(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8', v.remote, 'bash /root/loop-hunter/act.sh ' + argv.map(shq).join(' ')], 30000);
  audit(`[ACT] vps=${vpsKey} type=${a.type} file=${a.file} key=${a.key||''} :: ${(out||'').trim()}`);
  return out;
}
function body(req){ return new Promise(r=>{let d='';req.on('data',c=>d+=c);req.on('end',()=>{try{r(JSON.parse(d||'{}'))}catch(e){r({})}});}); }
function json(res, code, obj){ res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'}); res.end(JSON.stringify(obj)); }

const server = http.createServer(async (req,res)=>{
  const u = new URL(req.url, 'http://x');
  try {
    if (req.method==='GET' && u.pathname==='/') { res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'}); return res.end(PAGE); }
    if (req.method==='GET' && u.pathname==='/mapa') { res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'}); return res.end(MAPA); }
    if (req.method==='GET' && u.pathname==='/api/mapa')
      return json(res,200,{ vps: Object.keys(VPS).map(k=>({ key:k, label:VPS[k].label, inv: readInventory(k) })) });
    // Sem senha: acesso é gateado pela malha Tailscale (nginx só aceita origem 100.64.0.0/10).
    if (req.method==='GET' && u.pathname==='/api/state')
      return json(res,200,{ generated: Date.now(), vps: Object.keys(VPS).map(k=>({ key:k, label:VPS[k].label, report: readReport(k) })) });
    if (req.method==='POST' && u.pathname==='/api/rescan') {
      const b = await body(req); if(!VPS[b.vps]) return json(res,400,{error:'vps inválida'});
      runScan(b.vps, b.mode); return json(res,200,{ ok:true, report: readReport(b.vps) });
    }
    if (req.method==='POST' && u.pathname==='/api/action') {
      const b = await body(req); if(!VPS[b.vps]) return json(res,400,{error:'vps inválida'});
      const rep = readReport(b.vps); const f = (rep.findings||[]).find(x=>x.fp===b.fp);
      if(!f) return json(res,404,{error:'achado não existe mais (talvez já resolvido)'});
      if(!f.action || !SAFE_ACTIONS.has(f.action.type)) return json(res,403,{error:'esse achado não tem ação segura por botão'});
      let result; try { result = runAction(b.vps, f); } catch(e){ return json(res,500,{error:String(e.message||e)}); }
      runScan(b.vps,'leve');
      return json(res,200,{ ok:true, result:(result||'').trim(), report: readReport(b.vps) });
    }
    json(res,404,{error:'rota não encontrada'});
  } catch(e){ json(res,500,{error:String(e.message||e)}); }
});
server.listen(PORT, BIND_IP, ()=>{ console.log(`Faxina painel em http://${BIND_IP}:${PORT}`); });

const PAGE = `<!doctype html><html lang="pt-br"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Faxina · Visão Técnica</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--mut:#8b949e;--cr:#f85149;--hi:#f0a04b;--md:#e3b341;--ok:#3fb950;--bl:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{padding:14px 16px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px;position:sticky;top:0;background:var(--bg);z-index:5}
header h1{font-size:16px;margin:0;font-weight:600}.sp{flex:1}
.btn{background:#21262d;border:1px solid var(--bd);color:var(--tx);border-radius:8px;padding:8px 12px;font-size:14px;cursor:pointer}
.btn:hover{border-color:#5a6473}.btn.go{background:#238636;border-color:#2ea043}.btn.go:hover{background:#2ea043}
.btn.safe{background:#1f6feb;border-color:#388bfd}.btn.safe:hover{background:#388bfd}
.wrap{max-width:900px;margin:0 auto;padding:14px}
.vps{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px;margin:14px 0}
.vps h2{margin:0;font-size:16px;display:flex;align-items:center;gap:8px}
.dot{width:11px;height:11px;border-radius:50%;display:inline-block;flex:none}
.summary{display:flex;gap:14px;flex-wrap:wrap;margin:8px 0 4px;font-size:13px;color:var(--mut)}
.summary b{color:var(--tx)}
.sec{margin-top:12px}.sec h3{font-size:14px;margin:0 0 4px;display:flex;align-items:center;gap:7px;border-top:1px solid var(--bd);padding-top:10px}
.f{border:1px solid var(--bd);border-left-width:4px;border-radius:9px;padding:10px 12px;margin:9px 0;background:#0f141b}
.f.critical{border-left-color:var(--cr)}.f.high{border-left-color:var(--hi)}.f.medium{border-left-color:var(--md)}.f.low{border-left-color:var(--mut)}
.f h4{margin:0 0 6px;font-size:14.5px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.chip{font-size:11px;padding:1px 7px;border-radius:20px}
.chip.critical{background:#3d1418;color:#ff7b72}.chip.high{background:#3a2410;color:var(--hi)}.chip.medium{background:#332a0d;color:var(--md)}.chip.low{background:#21262d;color:var(--mut)}
.chip.cat{background:#1c2430;color:var(--bl)}
.code{font-family:ui-monospace,monospace;background:#21262d;border:1px solid var(--bd);color:#7ee787;padding:1px 7px;border-radius:6px;cursor:pointer;font-size:12px}
.row{margin:3px 0;font-size:13px}.k{color:var(--mut)}.rec{color:#7ee787}
ul{margin:3px 0;padding-left:18px}li{font-size:13px}
.acts{margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.clean{color:var(--ok);padding:6px 2px;font-size:13.5px}.err{color:var(--cr)}
small.mono{font-family:ui-monospace,monospace;color:var(--mut)}
.hw{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:8px;margin:8px 0 6px}
.hwc{background:#0f141b;border:1px solid var(--bd);border-radius:8px;padding:7px 10px}
.hwc .lbl{font-size:11px;color:var(--mut);display:flex;justify-content:space-between;gap:6px}
.hwc .lbl b{color:var(--tx);font-weight:600}
.bar{height:7px;border-radius:4px;background:#21262d;margin-top:6px;overflow:hidden}
.bar>span{display:block;height:100%}
.toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#21262d;border:1px solid var(--bd);padding:10px 16px;border-radius:10px;max-width:90%;font-size:13px;z-index:9}
</style></head><body>
<header><span>🧹</span><h1>Faxina · Visão Técnica</h1><span class="sp"></span>
<a class="btn" href="/mapa" style="text-decoration:none;margin-right:8px">🗺️ Mapa</a>
<button class="btn go" id="rescanAll">🔄 Escanear tudo</button></header>
<div class="wrap" id="app"><p class="meta" style="text-align:center;margin-top:40px;color:#8b949e">carregando a VPS…</p></div>
<script>
const KIND={
 log_storm:{e:"Um log recebe muitas linhas de erro/retry em pouco tempo — algo repete uma operação que falha.",i:"Queima CPU/IO e, se for chamada externa, requests e rate-limit. Mascara o problema e enche disco.",s:["Corrigir a causa/backoff no processo dono","Se for cron redundante, desligar a linha","Rotacionar o log se for só volume"]},
 counter:{e:"Arquivo de estado com contador de falhas consecutivas alto — loop de falha persistente.",i:"Algo falha repetidamente há tempo; o valor alto infla alertas e esconde a saúde real.",s:["Achar o serviço dono e corrigir a causa","Resetar o contador depois de corrigir"]},
 cpu:{e:"Um processo consome CPU alta de forma sustentada.",i:"Esquenta a VPS, rouba CPU de outros serviços, pode ser loop infinito.",s:["Ver o que o processo faz","Se for runaway e seguro, encerrar (via Claude)","Corrigir o loop"]},
 pm2_loop:{e:"Um app do pm2 reinicia em loop.",i:"Serviço instável; cada restart reabre conexões e gera carga.",s:["pm2 logs <app>","Corrigir a causa do crash","Estabilizar antes de novo restart"]},
 pm2_status:{e:"Um app do pm2 está fora do ar.",i:"O serviço que ele provê está indisponível.",s:["pm2 logs <app>","Subir após corrigir"]},
 systemd_loop:{e:"Serviço do systemd reiniciando muito.",i:"Instabilidade e indisponibilidade intermitente.",s:["journalctl -u <serviço>","Corrigir a causa"]},
 cron_pileup:{e:"Um job de cron acumula cópias — demora mais que o intervalo.",i:"Processos empilham e competem pelo mesmo dado (foi assim no bug do token).",s:["Adicionar trava (flock)","Espaçar o cron","Acelerar o job"]},
 conn_storm:{e:"Um processo abriu muitas conexões a um destino externo.",i:"Possível storm de requests — rate-limit, custo, ou laço de reconexão.",s:["Ver o processo dono","Aplicar backoff/limite"]},
 disk:{e:"Uma partição está quase cheia.",i:"Se encher, serviços quebram (banco, logs, uploads).",s:["Rotacionar/limpar logs grandes","Achar runaway de escrita"]},
 inode:{e:"Os inodes (cadastro de arquivos) de uma partição estão acabando.",i:"Se acabarem, nada novo é criado mesmo com espaço livre.",s:["Achar a pasta com milhares de arquivos","Limpar/arquivar"]},
 failed_service:{e:"Um serviço do systemd está em estado 'failed'.",i:"A função dele está parada; pode derrubar algo que depende.",s:["journalctl -u <serviço>","Corrigir a causa","Reiniciar após entender"]},
 svc_down:{e:"Um serviço-chave de base não está ativo.",i:"Risco alto — nginx/docker/cron/tailscale fora derruba muita coisa.",s:["Subir o serviço","Investigar a queda"]},
 docker_dead:{e:"Um contêiner Docker está morto/reiniciando/parado.",i:"Se era pra rodar, a função está fora; se é lixo, ocupa espaço.",s:["Se obsoleto: docker rm","Se necessário: investigar o crash"]},
 big_log:{e:"Um arquivo de log passou de 100MB.",i:"Consome disco e pode esconder um processo escrevendo demais.",s:["Rotacionar (backup+trunca)","Achar quem escreve tanto"]},
 zombie:{e:"Processos zumbi (mortos, não recolhidos pelo pai).",i:"Em excesso, esgotam a tabela de processos.",s:["Identificar o processo-pai","Reiniciar o pai"]},
 orphan:{e:"Processos sem pai (ppid=1) rodando há muito tempo.",i:"Podem ser vazamentos consumindo memória à toa.",s:["Confirmar se são lixo","Encerrar os obsoletos"]},
 cert:{e:"Um certificado SSL está perto de expirar.",i:"Se vencer, o site fica com cadeado quebrado / sem HTTPS.",s:["Renovar (certbot)","Ver por que o auto-renew não pegou"]},
 apt:{e:"Há atualizações de segurança pendentes.",i:"Vulnerabilidades conhecidas ficam abertas.",s:["Revisar e aplicar em janela segura"]},
 silence:{e:"Um cron/pipeline parou de escrever no log — provavelmente morreu e não roda mais.",i:"O resultado esperado deixa de ser produzido EM SILÊNCIO; você só nota quando falta.",s:["Rodar o job na mão e ver o erro","Corrigir a causa","Confirmar que voltou a rodar"]},
 backup:{e:"Um backup não rodou recentemente (log parado).",i:"Backup que falha calado = você só descobre no dia que precisa restaurar.",s:["Conferir o cron/script do backup","Rodar na mão","Validar que gera arquivo recente"]},
 mem_low:{e:"A memória disponível da VPS está criticamente baixa.",i:"Pode travar e o sistema começa a matar processos (OOM).",s:["Achar o que consome RAM","Reiniciar o serviço culpado","Avaliar aumentar memória"]},
 swap_high:{e:"A VPS usa muito swap com pouca RAM livre.",i:"Swap pesado deixa tudo lento — degradação geral.",s:["Investigar consumo de memória","Reiniciar serviço que vaza"]},
 oom:{e:"O 'OOM killer' do Linux matou processo(s) por falta de memória.",i:"Um serviço pode ter morrido do nada por falta de RAM.",s:["Ver qual processo morreu","Ajustar/limitar o serviço","Avaliar mais memória"]},
 romount:{e:"Uma partição foi montada como SÓ-LEITURA.",i:"Gravíssimo: o sistema não escreve mais ali (banco, logs, uploads param).",s:["Ver dmesg por erro de disco","Possível fsck + reboot","Acionar suporte se for hardware"]},
 ioerror:{e:"O kernel registrou erros de disco (I/O).",i:"Disco com problema — risco de perda de dados.",s:["Olhar dmesg/journal","Checar SMART","Avaliar troca/restore com urgência"]},
 reboot:{e:"Há um update (kernel) esperando reboot.",i:"Até reiniciar, a correção (às vezes de segurança) não fica ativa.",s:["Agendar reboot em janela tranquila"]},
 disk_predict:{e:"No ritmo de crescimento atual, o disco vai encher em poucos dias.",i:"Disco cheio quebra tudo que escreve (banco, logs, uploads) — e pega de surpresa.",s:["Achar o que está crescendo","Rotacionar/limpar","Avaliar aumentar o disco"]},
 exposure:{e:"Uma porta está aberta pra internet (escuta em 0.0.0.0 e o firewall libera).",i:"Qualquer um na internet pode tentar acessar — banco/cache exposto = risco de vazamento; app sem nginx = sem TLS/proteção.",s:["Fechar a porta no ufw","Ou amarrar o serviço a 127.0.0.1/Tailscale","Ou pôr atrás do nginx"]},
 firewall:{e:"O firewall local (ufw) está desligado.",i:"Tudo que escuta em 0.0.0.0 fica aberto pra internet — exposição total.",s:["Reativar o ufw com as regras certas (urgente)"]},
 fail2ban_off:{e:"O fail2ban (bloqueia força-bruta de senha) não está ativo.",i:"Ataques de senha não são mais bloqueados automaticamente.",s:["systemctl enable --now fail2ban"]},
 ssh_posture:{e:"O SSH permite login de root com senha.",i:"Alvo fácil de força-bruta — uma senha fraca e entram como root.",s:["PermitRootLogin prohibit-password","PasswordAuthentication no (key-only)"]},
 ssh_attack:{e:"Muitas tentativas falhas de SSH nas últimas 24h.",i:"Alguém está tentando entrar à força (a porta 22 está alcançável da internet).",s:["Confirmar que o fail2ban bloqueia","Considerar fechar a 22 pra só-Tailscale"]},
 other:{e:"Achado.",i:"",s:[]}
};
const SEVN={critical:"crítico",high:"alto",medium:"médio",low:"baixo"},SEVR={critical:3,high:2,medium:1,low:0};
const esc=s=>String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function toast(m){let t=document.createElement('div');t.className='toast';t.textContent=m;document.body.appendChild(t);setTimeout(()=>t.remove(),4000);}
async function api(p,opt){const r=await fetch(p,Object.assign({headers:{'Content-Type':'application/json'}},opt));return r.json();}
function light(list){if(!list.length)return 'var(--ok)';const m=Math.max.apply(0,list.map(f=>SEVR[f.severity]||0));return m>=2?'var(--cr)':'var(--md)';}
function dotColor(rep){if(rep.error)return 'var(--mut)';return light(rep.findings||[]);}
function barColor(p){return p>=90?'var(--cr)':p>=70?'var(--md)':'var(--ok)';}
function hwCell(label,val,pct){return \`<div class="hwc"><div class="lbl"><span>\${esc(label)}</span><b>\${esc(val)}</b></div><div class="bar"><span style="width:\${Math.min(100,Math.max(2,pct))}%;background:\${barColor(pct)}"></span></div></div>\`;}
function hwHTML(rep){const h=rep.hardware;if(!h)return '';
 const lp=h.cores?Math.round(h.load[0]/h.cores*100):0;
 let c=hwCell('CPU · load '+(h.load?h.load[0]:'?'), lp+'%', lp);
 if(h.mem)c+=hwCell('RAM', (h.mem.used_mb/1024).toFixed(1)+'/'+(h.mem.total_mb/1024).toFixed(1)+'GB', h.mem.pct);
 (h.disks||[]).forEach(d=>{c+=hwCell('Disco '+d.mount, d.used_gb+'/'+d.total_gb+'GB', d.pct);});
 const sw=(h.swap&&h.swap.total_mb)?(' · swap '+h.swap.used_mb+'/'+h.swap.total_mb+'MB'):'';
 return \`<div class="hw">\${c}</div><div class="meta" style="margin-top:0">⏱ ligada há \${Math.round(h.uptime_h||0)}h · \${h.cores} cores\${sw}</div>\`;}

function findingHTML(vps,f){const k=KIND[f.kind]||KIND.other;const hasAct=f.action&&(f.action.type==='reset_counter'||f.action.type==='rotate_log');
 const al=f.action&&f.action.type==='reset_counter'?'✓ Resetar contador':'✓ Rotacionar log (backup)';
 return \`<div class="f \${f.severity}"><h4><span class="chip \${f.severity}">\${SEVN[f.severity]||''}</span><span class="chip cat">\${esc(f.categoria)}</span>\${esc(f.title)}
   <span class="code" title="clique p/ copiar — cole no Claude Code p/ aprofundar" onclick="copy('\${esc(f.code)}')">\${esc(f.code)}</span></h4>
  <div class="row"><span class="k">Medição:</span> \${esc(f.measure)}</div>
  <div class="row"><span class="k">O que é:</span> \${esc(k.e)}</div>
  <div class="row"><span class="k">Implicações:</span> \${esc(k.i)}</div>
  <div class="row"><span class="k">Sugestões:</span><ul>\${k.s.map(x=>'<li>'+esc(x)+'</li>').join('')}</ul></div>
  \${f.fix?\`<div class="row rec"><span class="k">Recomendação:</span> \${esc(f.fix)}</div>\`:''}
  \${f.risk&&f.risk!=='n/a'?\`<div class="row"><span class="k">Risco de matar:</span> \${esc(f.risk)}</div>\`:''}
  <div class="acts">\${hasAct?\`<button class="btn safe" onclick="act('\${vps}','\${esc(f.fp)}',this)">\${al}</button>\`:''}
   <small class="mono">aprofundar → digite <b>\${esc(f.code)}</b> no Claude Code</small></div></div>\`;}

function sectionHTML(vps,findings,tipo,icon,nome){const list=findings.filter(f=>(f.tipo||'loop')===tipo);
 const inner=list.length?list.map(f=>findingHTML(vps,f)).join(''):\`<div class="clean">✅ sem \${nome} pendente</div>\`;
 return \`<div class="sec"><h3><span class="dot" style="background:\${light(list)}"></span>\${icon} \${nome} <span class="k">(\${list.length})</span></h3>\${inner}</div>\`;}

function vpsHTML(v){const rep=v.report||{};const f=(rep.findings||[]);
 if(rep.error)return \`<div class="vps"><h2><span class="dot" style="background:var(--mut)"></span>\${esc(v.label)}</h2><div class="err">⚠️ \${esc(rep.error)}</div></div>\`;
 const loops=f.filter(x=>(x.tipo||'loop')==='loop'),fax=f.filter(x=>x.tipo==='faxina');
 return \`<div class="vps"><h2><span class="dot" style="background:\${dotColor(rep)}"></span>\${esc(v.label)}</h2>
  <div class="summary">
    <span><span class="dot" style="background:\${light(loops)}"></span> 🔁 Loops <b>\${loops.length}</b></span>
    <span><span class="dot" style="background:\${light(fax)}"></span> 🧹 Faxina <b>\${fax.length}</b></span>
    <span class="k">\${rep.ts_human?('scan '+esc(rep.mode||'')+' · '+esc(rep.ts_human)):''} · <a href="#" onclick="rescan('\${v.key}');return false" style="color:#58a6ff">re-escanear</a></span>
  </div>
  \${hwHTML(rep)}
  \${sectionHTML(v.key,f,'loop','🔁','loops')}
  \${sectionHTML(v.key,f,'faxina','🧹','faxina')}</div>\`;}

async function load(){try{const s=await api('/api/state');document.getElementById('app').innerHTML=s.vps.map(vpsHTML).join('');}catch(e){document.getElementById('app').innerHTML='<p class="err">falha ao carregar</p>';}}
function copy(c){try{navigator.clipboard.writeText(c);}catch(e){}toast('código '+c+' — cole no Claude Code pra aprofundar este item');}
async function rescan(k){toast('Escaneando '+k+'… (completo, pode levar alguns segundos)');try{await api('/api/rescan',{method:'POST',body:JSON.stringify({vps:k,mode:'profundo'})});await load();toast(k+' atualizado.');}catch(e){toast('falha no scan.');}}
document.getElementById('rescanAll').onclick=async()=>{toast('Escaneando a VPS…');for(const k of['main']){try{await api('/api/rescan',{method:'POST',body:JSON.stringify({vps:k,mode:'profundo'})});}catch(e){}}await load();toast('Tudo atualizado.');};
async function act(vps,fp,btn){if(!confirm('Confirmar esta ação segura em '+vps+'?'))return;btn.disabled=true;btn.textContent='executando…';
 try{const r=await api('/api/action',{method:'POST',body:JSON.stringify({vps,fp})});toast(r.ok?('✅ '+(r.result||'feito')):('⚠️ '+(r.error||'falhou')));await load();}catch(e){toast('falha.');btn.disabled=false;}}
setInterval(load,30000);load();
</script></body></html>`;

// ---------------- PÁGINA /mapa (inventário vivo) ----------------
const MAPA = `<!doctype html><html lang="pt-br"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Faxina · Mapa da casa</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--mut:#8b949e;--cr:#f85149;--ok:#3fb950;--md:#e3b341;--bl:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{padding:14px 16px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px;position:sticky;top:0;background:var(--bg);z-index:5}
header h1{font-size:16px;margin:0}.sp{flex:1}
.btn{background:#21262d;border:1px solid var(--bd);color:var(--tx);border-radius:8px;padding:7px 12px;font-size:14px;text-decoration:none}
.wrap{max-width:980px;margin:0 auto;padding:14px}
.vps{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px;margin:14px 0}
.vps h2{margin:0 0 6px;font-size:16px}
.sec{border-top:1px solid var(--bd);padding-top:10px;margin-top:10px}
.sec h3{font-size:13px;margin:0 0 6px;color:var(--bl);text-transform:uppercase;letter-spacing:.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:6px}
.it{background:#0f141b;border:1px solid var(--bd);border-radius:7px;padding:6px 9px;font-size:13px;display:flex;align-items:center;gap:6px}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
.mut{color:var(--mut);font-size:12px}.dead{color:var(--cr)}.mono{font-family:ui-monospace,monospace}
.chip{font-size:11px;padding:0 6px;border-radius:10px;background:#1c2430;color:var(--bl)}
details{margin-top:4px}summary{cursor:pointer;color:var(--mut);font-size:13px}
a{color:var(--bl)}
</style></head><body>
<header><span>🗺️</span><h1>Mapa da casa</h1><span class="sp"></span><a class="btn" href="/">← Faxina</a></header>
<div class="wrap" id="app"><p class="mut" style="text-align:center;margin-top:40px">carregando inventário…</p></div>
<script>
const esc=s=>String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function dot(c){return '<span class="dot" style="background:'+c+'"></span>';}
function sec(t,html){return '<div class="sec"><h3>'+t+'</h3>'+html+'</div>';}
function grid(items){return '<div class="grid">'+items.join('')+'</div>';}

function pm2HTML(list){if(!list||!list.length)return '<span class="mut">—</span>';
 return grid(list.map(p=>{const c=p.status==='online'?'var(--ok)':'var(--cr)';
  return '<div class="it">'+dot(c)+'<b>'+esc(p.name)+'</b><span class="mut">'+(p.status==='online'?(p.uptime_h+'h · '+p.restarts+'r'):esc(p.status))+'</span></div>';}));}

function dockerHTML(d){if(!d)return '';let h='';
 if(d.services&&d.services.length)h+='<div class="mut" style="margin:2px 0">Swarm services:</div>'+grid(d.services.map(s=>'<div class="it">'+dot('var(--bl)')+esc(s.name)+'<span class="mut">'+esc(s.replicas)+'</span></div>'));
 if(d.containers&&d.containers.length)h+='<div class="mut" style="margin:6px 0 2px">Containers:</div>'+grid(d.containers.map(c=>{const bad=/exited|dead|restarting|unhealthy/i.test(c.status);return '<div class="it">'+dot(bad?'var(--cr)':'var(--ok)')+esc(c.name).slice(0,28)+'<span class="mut '+(bad?'dead':'')+'">'+esc(c.status).slice(0,18)+'</span></div>';}));
 return h||'<span class="mut">—</span>';}

function subsHTML(list){if(!list||!list.length)return '<span class="mut">—</span>';
 const dead=list.filter(s=>/morto/.test(s.status)), ok=list.filter(s=>!/morto/.test(s.status));
 let h='';
 if(dead.length)h+=grid(dead.map(s=>'<div class="it">'+dot('var(--cr)')+'<span class="dead">'+esc(s.name)+'</span><span class="mut">→'+esc(s.backend)+' morto</span></div>'));
 h+='<details><summary>'+ok.length+' subdomínio(s) ok'+(dead.length?(' · ⚠️ '+dead.length+' com backend morto'):'')+'</summary>'+grid(ok.map(s=>'<div class="it mono" style="font-size:12px">'+esc(s.name)+' <span class="mut">'+(s.backend?(':'+s.backend):'estático')+'</span></div>'))+'</details>';
 return h;}

function portsHTML(list){if(!list||!list.length)return '';
 const pub=list.filter(p=>p.cls==='público'),ts=list.filter(p=>p.cls==='tailscale'),lo=list.filter(p=>p.cls==='loopback');
 const cell=p=>'<div class="it mono" style="font-size:12px">'+esc(p.port)+' <span class="mut">'+esc(p.proc)+'</span></div>';
 let h='';
 if(pub.length)h+='<div class="mut">🌐 público ('+pub.length+'):</div>'+grid(pub.map(cell));
 h+='<details><summary>'+ts.length+' Tailscale · '+lo.length+' loopback (interno)</summary>'+grid(ts.concat(lo).map(cell))+'</details>';
 return h;}

function vpsHTML(v){const i=v.inv;
 if(i.error)return '<div class="vps"><h2>'+esc(v.label)+'</h2><div class="dead">⚠️ '+esc(i.error)+'</div></div>';
 const d=i.inventory;
 return '<div class="vps"><h2>🏠 '+esc(v.label)+' <span class="mut" style="font-size:12px">· inventário '+esc(i.ts_human||'')+'</span></h2>'
  +sec('Apps pm2 ('+d.pm2.length+')', pm2HTML(d.pm2))
  +sec('Docker', dockerHTML(d.docker))
  +sec('Serviços systemd ('+d.systemd.length+')', d.systemd.length?grid(d.systemd.map(s=>'<div class="it">'+dot('var(--ok)')+esc(s.replace('.service',''))+'</div>')):'<span class="mut">—</span>')
  +sec('Subdomínios ('+d.subdomains.length+')', subsHTML(d.subdomains))
  +sec('Portas em escuta ('+d.ports.length+')', portsHTML(d.ports))
  +sec('Crons ('+d.crons.length+')', '<details><summary>ver os '+d.crons.length+' agendamentos</summary>'+grid(d.crons.map(c=>'<div class="it mono" style="font-size:11px">'+esc(c.sched)+' <span class="mut">'+esc(c.cmd)+'</span></div>'))+'</details>')
  +'</div>';}

async function load(){try{const r=await fetch('/api/mapa');const s=await r.json();
 document.getElementById('app').innerHTML=s.vps.map(vpsHTML).join('');}catch(e){document.getElementById('app').innerHTML='<p class="dead">falha ao carregar</p>';}}
load();
</script></body></html>`;
