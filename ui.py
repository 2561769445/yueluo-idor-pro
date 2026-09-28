#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ui.py — 越权测试工具控制台(内嵌单页HTML, 深色中文)
数据包左右对照: 左请求包 | 右响应包; 原始vs重放两组上下排列"""

HTML = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>月落 · 越权测试工具</title>
<link rel="icon" href="/favicon.ico?v=3">
<link rel="shortcut icon" href="/favicon.ico?v=3">
<style>
:root{--bg:#0D1526;--panel:#141d2e;--card:#1a2536;--line:#283548;--txt:#d7e0ea;--dim:#8194a7;
--acc:#9B7BF7;--red:#ff5c5c;--yel:#ffc24b;--grn:#4cd97b;--gray:#7a8ba0}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:14px/1.6 "Microsoft YaHei",sans-serif;padding:18px}
h1{font-size:20px;display:flex;align-items:center;gap:10px}
h1 .dot{width:10px;height:10px;border-radius:50%;background:var(--gray);box-shadow:0 0 6px var(--gray)}
h1 .dot.on{background:var(--grn);box-shadow:0 0 8px var(--grn);animation:pulse 1.2s infinite}
@keyframes pulse{50%{opacity:.4}}
.bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:8px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
.panel h3{font-size:15px;color:var(--acc);margin-bottom:10px;font-weight:600}
.accts{display:flex;gap:10px;flex-wrap:wrap}
.acct{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;width:240px;position:relative}
.acct .nm{font-weight:600;font-size:15px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center}
.acct input{width:100%;background:#131c2b;border:1px solid var(--line);border-radius:5px;color:var(--txt);padding:6px 8px;margin-bottom:6px;font-size:13px}
.acct .meta{font-size:12px;color:var(--dim)}
.acct .meta b{color:var(--grn)}
.acct .del{color:var(--red);cursor:pointer;font-size:13px;border:none;background:none}
.acct .err{color:var(--red);font-size:12px}
.addbtn{width:120px;min-height:90px;border:1px dashed var(--line);border-radius:8px;background:none;color:var(--dim);cursor:pointer;font-size:14px}
.addbtn:hover{border-color:var(--acc);color:var(--acc)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
button.act{background:linear-gradient(135deg,#9B7BF7,#6D4DE0);color:#fff;border:none;border-radius:6px;padding:9px 18px;font-size:14px;cursor:pointer}
button.act.green{background:#2f9e5f}button.act.danger{background:#c0392b}button.act.ghost{background:transparent;border:1px solid var(--line);color:var(--dim)}
button.act.small{padding:5px 12px;font-size:13px}
button.act:disabled{opacity:.45;cursor:not-allowed}
.sett{display:flex;gap:16px;flex-wrap:wrap;color:var(--dim);font-size:13px;align-items:center;margin-top:10px}
.sett label{display:flex;gap:5px;align-items:center;cursor:pointer}
.sett input[type=checkbox]{accent-color:var(--acc)}
.sett input[type=number]{width:56px;background:#131c2b;border:1px solid var(--line);color:var(--txt);border-radius:4px;padding:3px 6px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.chip{padding:4px 12px;border-radius:14px;border:1px solid var(--line);color:var(--dim);cursor:pointer;font-size:13px;user-select:none}
.chip.on{border-color:var(--acc);color:var(--acc);background:#241f3d}
.chip.red{color:var(--red)}.chip.yel{color:var(--yel)}.chip.grn{color:var(--grn)}
.search{background:#131c2b;border:1px solid var(--line);border-radius:6px;color:var(--txt);padding:6px 10px;width:220px;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--dim);text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);font-weight:500;white-space:nowrap}
td{padding:7px 8px;border-bottom:1px solid #1d2942;vertical-align:top}
tr:hover td{background:#182338}
.lv{white-space:nowrap;font-weight:600}
.lv-high{color:var(--red)}.lv-mid{color:var(--yel)}.lv-ok{color:var(--grn)}.lv-public{color:var(--gray)}
.lv-waf{color:#e07bff}.lv-skip{color:var(--gray)}.lv-base_reject{color:var(--yel)}.lv-error{color:var(--gray)}
.mth{font-weight:700;color:var(--acc);white-space:nowrap}
td.url{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr}
td.ev{max-width:400px;color:var(--dim);font-size:12px;white-space:pre-line}
.op{white-space:nowrap}
.op a{color:var(--acc);cursor:pointer;margin-right:8px;font-size:13px}
.op a.del{color:var(--red)}
.mark-sel{background:#131c2b;color:var(--txt);border:1px solid var(--line);border-radius:5px;padding:5px}
.mark-badge{font-size:11px;padding:1px 6px;border-radius:3px;margin-left:4px}
.mk-confirmed{background:#3a2b52;color:#c39bff}.mk-fp{background:#333d33;color:#8fd8a0}
#log{font-family:Consolas,monospace;font-size:12px;color:var(--dim);max-height:120px;overflow:auto;background:#0e1523;border-radius:6px;padding:8px;margin-top:10px}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.65);display:none;justify-content:center;align-items:flex-start;padding:40px 20px;z-index:99;overflow:auto}
.overlay.show{display:flex}
.dlg{background:var(--panel);border:1px solid var(--line);border-radius:10px;max-width:1280px;width:100%;padding:18px}
.dlg h4{color:var(--acc);margin-bottom:8px;font-size:15px}
/* 数据包左右对照 */
.pair{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:6px 0 14px}
.pkt{background:#0e1523;border:1px solid var(--line);border-radius:6px;padding:10px;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow:auto;direction:ltr;text-align:left}
.pkt b{color:var(--acc)}
.pair-label{font-size:13px;color:var(--txt);font-weight:600;margin:10px 0 2px}
.pair-label small{color:var(--dim);font-weight:400}
.vuln-desc{background:#241a1a;border:1px solid #4a2d2d;border-radius:8px;padding:12px;margin-bottom:12px;font-size:13px;white-space:pre-line;color:#f0d5d5;line-height:1.7}
.vuln-desc b{color:var(--red)}
.toast{position:fixed;bottom:24px;right:24px;background:#2f9e5f;color:#fff;padding:10px 18px;border-radius:8px;display:none;z-index:100;font-size:14px}
.toast.err{background:#c0392b}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;font-size:13px;color:var(--dim)}
.stats b{font-size:16px}
.progress{height:6px;background:#131c2b;border-radius:3px;overflow:hidden;margin-bottom:10px;display:none}
.progress i{display:block;height:100%;background:var(--acc);width:0;transition:width .4s}
.empty{color:var(--dim);text-align:center;padding:30px}
</style>
</head>
<body>
<div id="crawlBanner" style="display:none;background:#3a342b;border:1px solid #e0c24b;color:#e0c24b;
padding:10px 16px;border-radius:8px;margin-bottom:12px;font-size:14px;font-weight:600;
animation:pulse 1.6s infinite">🕸 自动遍历进行中</div>
<div class="bar">
  <h1><svg width="36" height="36" viewBox="0 0 64 64" style="vertical-align:-9px;filter:drop-shadow(0 2px 8px #6D4DE055)">
  <defs>
    <linearGradient id="ylg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#9B7BF7"/><stop offset="1" stop-color="#6D4DE0"/>
    </linearGradient>
    <mask id="ylm">
      <rect width="64" height="64" fill="black"/>
      <circle cx="29.5" cy="32" r="16.6" fill="white"/>
      <circle cx="37" cy="38.5" r="19.2" fill="black"/>
    </mask>
  </defs>
  <rect x="1" y="1" width="62" height="62" rx="14.5" fill="url(#ylg)"/>
  <rect x="1" y="1" width="62" height="62" rx="14.5" fill="#fff" mask="url(#ylm)"/>
</svg>
<span style="color:#fff;font-weight:700">月落</span>
<span style="color:#A78BFA;font-weight:500;margin:0 3px;font-size:17px">越权测试工具</span> <span class="dot" id="dot"></span>
<span style="font-size:12px;color:var(--dim)">多账号流量录制 → 交叉重放 → 自动判定</span></h1>
  <div class="row">
    <span style="color:var(--dim);font-size:13px">测试会话:</span>
    <select id="sess" class="mark-sel" onchange="switchSess()"></select>
    <button class="act danger small" onclick="delSess()">删除当前会话</button>
    <button class="act ghost small" onclick="clearSess()">🗑 清空全部历史</button>
    <span id="stateTxt" style="color:var(--dim);font-size:13px"></span>
  </div>
</div>

<div class="panel">
  <h3>① 账号管理 <span style="font-weight:400;color:var(--dim);font-size:12px">(添加2个及以上账号可测交叉越权; 建议一个管理员账号+多个普通账号, 可同时覆盖水平/垂直越权)</span></h3>
  <div class="accts" id="accts"></div>
  <div style="margin-top:10px" class="row">
    <button class="addbtn" onclick="addAcct()">＋ 添加账号</button>
  </div>
  <div class="sett">
    <label><input type="checkbox" id="stSkipDel" checked> 跳过删除类操作(推荐)</label>
    <label><input type="checkbox" id="stNoauth" checked> 包含去凭证测试(未授权检测)</label>
    <label><input type="checkbox" id="stDeep" checked> 深度绕过(XFF伪造/方法翻转)</label>
    <label><input type="checkbox" id="stGetOnly"> 仅测试GET(更保守)</label>
    <label>并发 <input type="number" id="stConc" value="4" min="1" max="16"></label>
  </div>
  <div class="row" style="margin-top:8px">
    <span style="color:var(--dim);font-size:13px">上游代理(Burp):</span>
    <input style="background:#131c2b;border:1px solid var(--line);border-radius:5px;color:var(--txt);padding:6px 8px;width:220px;font-size:13px" id="proxyUrl" placeholder="http://127.0.0.1:8080 (留空=直连)">
    <button class="act ghost small" onclick="saveProxy()">保存并检测</button>
    <span id="proxyStat" style="color:var(--dim);font-size:12px">全部重放流量将经代理留档(Burp请关闭Intercept)</span>
  </div>
</div>

<div class="panel">
  <h3>🤖 AI误报筛查 <span style="font-weight:400;color:var(--dim);font-size:12px">(测试完成后一键让AI判定全部疑似项: 真漏洞/误报/需人工)</span></h3>
  <div class="row">
    <input style="background:#131c2b;border:1px solid var(--line);border-radius:5px;color:var(--txt);padding:6px 8px;width:260px;font-size:13px" id="aiUrl" placeholder="API地址 (如 https://open.bigmodel.cn/api/paas/v4)">
    <input type="password" style="background:#131c2b;border:1px solid var(--line);border-radius:5px;color:var(--txt);padding:6px 8px;width:200px;font-size:13px" id="aiKey" placeholder="API Key">
    <button class="act ghost" onclick="fetchModels()">📥 获取模型列表</button>
    <input style="background:#131c2b;border:1px solid var(--line);border-radius:5px;color:var(--txt);padding:6px 8px;width:190px;font-size:13px" id="aiModel" list="modelList" placeholder="选择或输入模型">
    <datalist id="modelList">
      <option value="glm-4-flash">智谱·免费快速</option>
      <option value="glm-4-air">智谱·性价比</option>
      <option value="glm-4-plus">智谱·标准</option>
      <option value="glm-4.5">智谱·4.5</option>
      <option value="glm-4.5-flash">智谱·4.5快速</option>
      <option value="deepseek-chat">DeepSeek</option>
      <option value="gpt-4o-mini">OpenAI·便宜</option>
      <option value="gpt-4o">OpenAI</option>
    </datalist>
    <button class="act ghost" onclick="saveAI()">保存配置</button>
    <button class="act" onclick="api('ai_judge')">🤖 AI筛查全部疑似项</button>
    <span id="aiStat" style="color:var(--dim);font-size:13px"></span>
  </div>
</div>

<div class="panel">
  <h3>② 测试控制</h3>
  <div class="row">
    <button class="act green" onclick="api('start')">🚀 开启测试 (新建会话+弹浏览器)</button>
    <button class="act ghost" onclick="api('crawl')">🕸 自动遍历全部账号</button>
    <button class="act" onclick="startTest()" id="btnTest">▶ 开始越权测试</button>
    <button class="act danger" onclick="api('stop_test')">停止测试</button>
    <button class="act ghost" onclick="api('stop_all')">关闭全部浏览器</button>
  </div>
  <div class="sett" style="margin-top:8px;color:var(--dim);font-size:12px">
    流程: 添加账号 → 「开启测试」弹出N个独立浏览器 → 各窗口手动登录 → <b style="color:var(--acc)">点「自动遍历」工具自动扫全站接口</b>(也可手动点功能点) → 「开始越权测试」
  </div>
  <div class="sett" style="margin-top:8px;color:var(--dim);font-size:12px">
    流程: 添加账号 → 点「开启测试」弹出N个独立浏览器(带账号编号) → 各窗口手动登录并遍历功能点 → 回来点「开始越权测试」
  </div>
  <div class="progress" id="prog"><i id="progBar"></i></div>
  <div id="log"></div>
</div>

<div class="panel">
  <h3>③ 测试结果</h3>
  <div class="stats" id="stats"></div>
  <div class="chips" id="chips"></div>
  <div class="row" style="margin-bottom:10px">
    <input class="search" id="q" placeholder="搜索URL/证据/账号..." oninput="setSearch(this.value)">
    <select class="mark-sel" id="mkAct">
      <option value="confirmed">标记选中 → ✅确认漏洞</option>
      <option value="false_positive">标记选中 → ❌误报</option>
      <option value="pending">标记选中 → 待定</option>
    </select>
    <button class="act ghost" onclick="markSel()">应用标记</button>
    <button class="act danger" onclick="delSel()">删除选中</button>
    <span style="flex:1"></span>
    <button class="act ghost" onclick="exportFile('report')">📄 导出HTML报告</button>
    <button class="act ghost" onclick="exportFile('ai')">🤖 导出AI筛查包</button>
  </div>
  <div class="row" style="margin-bottom:8px;color:var(--dim);font-size:12px" id="aiLegend">
    AI徽章说明: <span class="mark-badge mk-confirmed">AI确认</span>=AI判定真实漏洞 ·
    <span class="mark-badge mk-fp">AI误报</span>=AI判定误报(可放心删) · <span class="mark-badge" style="background:#3a342b;color:#e0c24b">AI待人工</span>=数据不足
  </div>
  <div style="overflow-x:auto">
  <table>
    <thead><tr>
      <th><input type="checkbox" onchange="toggleAll(this)" id="ckAll"></th>
      <th>判定</th><th>方法</th><th>URL</th><th>账号</th><th>证据</th><th>操作</th>
    </tr></thead>
    <tbody id="tbody"></tbody>
  </table>
  </div>
  <div class="empty" id="empty" style="display:none">暂无结果</div>
</div>

<div class="overlay" id="ovl" onclick="if(event.target===this)closeDlg()">
  <div class="dlg" id="dlgBody"></div>
</div>
<div class="toast" id="toast"></div>

<script>
let S={accounts:[],results:[],sessions:[],current:"",testing:false,done:0,total:0};
let filter="all", qstr="";
const LV={high:"🔴高危",mid:"🟡中危",ok:"🟢正常",public:"⚪公共",waf:"🚫WAF",skip:"⏭️跳过",base_reject:"⚠️基线被拒",error:"❌失败"};
const CATS=[["all","全部"],["high","🔴高危"],["mid","🟡中危"],["ok","🟢正常"],["public","⚪公共"],["waf","🚫WAF"],["skip","⏭️跳过"],["base_reject","⚠️基线被拒"]];

function toast(msg,err){const t=document.getElementById('toast');t.textContent=msg;t.className='toast show'+(err?' err':'');setTimeout(()=>t.className='toast',2600)}
async function api(path,body){
  try{
    const r=await fetch('/api/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
    const j=await r.json();
    if(!j.ok){toast(j.msg||'操作失败',1);return null}
    if(j.msg)toast(j.msg);
    refresh();return j;
  }catch(e){toast('请求失败: '+e.message,1);return null}
}
async function refresh(){
  try{
    const r=await fetch('/api/state');const j=await r.json();
    Object.assign(S,j);
    document.getElementById('dot').className='dot'+((j.accounts||[]).some(a=>a.recording)?' on':'');
    document.getElementById('stateTxt').textContent=j.testing?`测试中 ${j.done}/${j.total}`:(j.accounts||[]).some(a=>a.recording)?'录制中':(j.current?'就绪':'未开始');
    const pr=document.getElementById('prog');
    if(j.testing){pr.style.display='block';document.getElementById('progBar').style.width=(j.total?100*j.done/j.total:0)+'%';document.getElementById('btnTest').disabled=true}
    else{pr.style.display='none';document.getElementById('btnTest').disabled=false}
    renderAccts();renderSess();renderResults();renderLog(j.log||[]);
    // 遍历横幅: 持续醒目提醒勿操作浏览器
    const cb=document.getElementById('crawlBanner');
    const cs=(j.accounts||[]).filter(a=>a.crawling);
    if(cs.length){
      cb.style.display='block';
      cb.textContent='🕸 自动遍历进行中 ['+cs.map(a=>`${a.name}: ${a.crawl?a.crawl.phase:''} ${a.crawl?a.crawl.done:0}/${a.crawl?a.crawl.total:0}`).join(' | ')+'] — 请勿操作浏览器窗口, 遍历完成后自动消失';
    } else cb.style.display='none';
    // AI状态
    const as=document.getElementById('aiStat');
    as.textContent=j.ai_running?`AI筛查中 ${j.ai_done}/${j.ai_total}`:(j.ai_cfg&&j.ai_cfg.has_key?'AI就绪':'AI未配置');
    if(j.ai_cfg&&j.ai_cfg.base_url&&!aiUrl.value)aiUrl.value=j.ai_cfg.base_url;
    if(j.ai_cfg&&j.ai_cfg.model&&!aiModel.value)aiModel.value=j.ai_cfg.model;
    if(j.ai_cfg&&j.ai_cfg.has_key&&!aiKey.value)aiKey.value='●已保存●';
    if(j.proxy&&!proxyUrl.value)proxyUrl.value=j.proxy;
  }catch(e){}
}
function renderAccts(){
  const box=document.getElementById('accts');
  if(!S.accounts.length){box.innerHTML='<div class="empty">先添加账号 (如: 账号a / 账号b / 账号c)</div>';return}
  box.innerHTML=S.accounts.map((a,i)=>`
  <div class="acct">
    <div class="nm">账号 ${i+1} <button class="del" onclick="delAcct('${esc(a.name)}')">✕移除</button></div>
    <input placeholder="账号名称" value="${esc(a.name)}" onchange="updAcct(${i},'name',this.value)">
    <input placeholder="起始URL (如 http://x.com/login)" value="${esc(a.start_url)}" onchange="updAcct(${i},'start_url',this.value)">
    <input placeholder="角色标注(可选: 管理员/普通用户, 供AI判定参考)" value="${esc(a.role||'')}" onchange="updAcct(${i},'role',this.value)">
    <div class="meta">${a.running?'浏览器: <b>在线</b> (:'+a.port+')':'浏览器: 未启动'} · 录制: <b>${a.captured||0}</b>条${a.recording?' · 录制中':''}${a.crawling?` · <span style="color:#e0c24b">🕸遍历中 ${a.crawl?a.crawl.phase:''} ${a.crawl?a.crawl.done:0}/${a.crawl?a.crawl.total:0}</span>`:''}</div>
    ${a.error?`<div class="err">${esc(a.error)}</div>`:''}
  </div>`).join('');
}
async function startTest(){
  await api('test',{
    skip_delete:stSkipDel.checked, include_noauth:stNoauth.checked,
    deep_bypass:stDeep.checked, get_only:stGetOnly.checked,
    concurrency:parseInt(stConc.value)||4,
    proxy:proxyUrl.value.trim()});
}
async function saveProxy(){
  const r=await api('proxy_config',{proxy:proxyUrl.value.trim()});
  if(r&&r.ok)proxyStat.textContent=proxyUrl.value.trim()?'✓ 代理可达, 重放将经代理留档':'已清除代理(直连)';
}
async function saveAI(){
  await api('ai_config',{base_url:aiUrl.value,api_key:aiKey.value,model:aiModel.value});
}
async function fetchModels(){
  const r=await api('ai_models',{base_url:aiUrl.value,api_key:aiKey.value});
  if(r&&r.ok){
    const dl=document.getElementById('modelList');
    dl.innerHTML=(r.models||[]).map(m=>`<option value="${esc(m)}">`).join('');
    aiModel.focus();aiModel.click();
  }
}
async function addAcct(){await api('account',{op:'add'})}
async function delAcct(n){await api('account',{op:'del',name:n})}
async function updAcct(i,k,v){await api('account',{op:'upd',idx:i,key:k,value:v})}
function renderSess(){
  const sel=document.getElementById('sess');
  sel.innerHTML=(S.sessions||[]).map(s=>`<option value="${s.ts}" ${s.ts===S.current?'selected':''}>${s.label} (${s.count}条)</option>`).join('')||'<option>暂无会话</option>';
}
async function switchSess(){const v=document.getElementById('sess').value;if(v){await api('session_switch',{ts:v});await refresh()}}
async function delSess(){
  const v=document.getElementById('sess').value;
  if(!v||v==='暂无会话')return toast('无可删除的会话',1);
  if(!confirm('确定删除该测试会话及其全部结果? (不可恢复)'))return;
  await api('session_delete',{ts:v});
}
async function clearSess(){
  const n=(S.sessions||[]).length;
  if(n<=1)return toast('没有可清空的历史会话',1);
  if(!confirm(`确定清空全部 ${n-1} 个历史会话? (保留当前会话, 不可恢复)`))return;
  await api('session_clear',{});
}
function renderLog(lines){document.getElementById('log').innerHTML=lines.map(l=>`<div>${esc(l)}</div>`).join('')}
function setFilter(k){filter=k;renderResults()}
function aiBadge(r){
  if(!r.ai_verdict)return '';
  if(r.ai_verdict==='confirmed')return '<span class="mark-badge mk-confirmed" title="'+esc(r.ai_reason||'')+'">AI确认</span>';
  if(r.ai_verdict==='false_positive')return '<span class="mark-badge mk-fp" title="'+esc(r.ai_reason||'')+'">AI误报</span>';
  return '<span class="mark-badge" style="background:#3a342b;color:#e0c24b" title="'+esc(r.ai_reason||'')+'">AI待人工</span>';
}
function setSearch(v){qstr=v;renderResults()}
function renderResults(){
  const cnt={};(S.results||[]).forEach(r=>cnt[r.level]=(cnt[r.level]||0)+1);
  document.getElementById('stats').innerHTML=
    `<span>共 <b>${S.results.length}</b> 条</span>`+
    ['high','mid','ok','public','waf','skip','base_reject','error'].map(k=>cnt[k]?`<span class="lv lv-${k}">${LV[k]} <b>${cnt[k]}</b></span>`:'').join('');
  document.getElementById('chips').innerHTML=CATS.map(([k,n])=>{
    const c=k==='all'?S.results.length:(cnt[k]||0);
    return `<span class="chip ${filter===k?'on':''} ${k==='high'?'red':k==='mid'?'yel':(k==='ok'?'grn':'')}" onclick="setFilter('${k}')">${n} ${c}</span>`}).join('');
  let list=S.results.filter(r=>filter==='all'||r.level===filter);
  if(qstr)list=list.filter(r=>(r.url+r.evidence+r.owner+(r.cross_account||'')).toLowerCase().includes(qstr.toLowerCase()));
  list=[...list].reverse();
  // 保留勾选状态(自动刷新不丢勾选)
  const checked=new Set([...document.querySelectorAll('.ck:checked')].map(c=>c.value));
  const tb=document.getElementById('tbody');
  if(!list.length){document.getElementById('empty').style.display='block';tb.innerHTML='';return}
  document.getElementById('empty').style.display='none';
  tb.innerHTML=list.map(r=>`
  <tr>
    <td><input type="checkbox" class="ck" value="${r.id}" ${checked.has(r.id)?'checked':''}></td>
    <td class="lv lv-${r.level}">${LV[r.level]||r.level}${r.mark==='confirmed'?'<span class="mark-badge mk-confirmed">已确认</span>':r.mark==='false_positive'?'<span class="mark-badge mk-fp">误报</span>':''}${aiBadge(r)}</td>
    <td class="mth">${r.method}</td>
    <td class="url" title="${esc(r.url)}">${esc(r.url)}</td>
    <td>${esc(r.owner)}${r.cross_account?` <span style="color:var(--dim)">→</span> ${esc(r.cross_account)}`:(r.mode==='noauth'?' <span style="color:var(--dim)">→ 裸</span>':'')}</td>
    <td class="ev">${esc(r.evidence||r.category)}</td>
    <td class="op"><a onclick="detail('${r.id}')">详情</a><a class="del" onclick="delOne('${r.id}')">删除</a></td>
  </tr>`).join('');
}
function toggleAll(el){document.querySelectorAll('.ck').forEach(c=>c.checked=el.checked)}
function selIds(){return [...document.querySelectorAll('.ck:checked')].map(c=>c.value)}
async function delOne(id){await api('result_delete',{ids:[id]})}
async function delSel(){const ids=selIds();if(!ids.length)return toast('先勾选要删除的行',1);await api('result_delete',{ids})}
async function markSel(){const ids=selIds();if(!ids.length)return toast('先勾选要标记的行',1);
  await api('result_mark',{ids:ids,mark:document.getElementById('mkAct').value})}
async function detail(id){
  const r=await (await fetch('/api/detail?id='+id)).json();
  if(!r.ok)return toast(r.msg,1);
  const d=r.data;
  document.getElementById('dlgBody').innerHTML=`
  <h4>${LV[d.level]||''} ${esc(d.category)} <span style="font-weight:400;color:var(--dim);font-size:12px">${d.id} · ${d.ts}</span></h4>
  <div style="color:var(--dim);font-size:12px;margin-bottom:8px">${d.method} ${esc(d.url)} · 录制账号:${esc(d.owner)}${d.cross_account?' · 重放凭证:'+esc(d.cross_account):''}</div>
  ${(d.level==='high'||d.level==='mid')&&d.evidence?`<div class="vuln-desc">${esc(d.evidence)}</div>`:''}
  <div class="pair-label">▣ 对照组一: <b style="color:var(--acc)">原始请求</b> <small>(录制账号 ${esc(d.owner)} 正常操作时抓取)</small></div>
  <div class="pair">
    <div class="pkt"><b>【左·请求包】</b>
${esc(reqTxt(d.orig))}</div>
    <div class="pkt"><b>【右·响应包】</b> HTTP ${d.orig&&d.orig.status||'?'}
${esc((d.orig&&d.orig.body)||'(响应体未捕获)')}</div>
  </div>
  ${d.baseline?`<div class="pair-label">▣ 基线重放 <small>(原凭证原样重放 → 用于排除防重放干扰)</small></div>
  <div class="pkt"><b>HTTP ${d.baseline.status}</b>
${esc((d.baseline.body||'').slice(0,1200))}</div>`:''}
  ${d.replay?`<div class="pair-label">▣ 对照组二: <b style="color:var(--red)">重放请求</b> <small>(${d.mode==='noauth'?'去掉全部凭证':'凭证替换为 '+esc(d.cross_account)} — 越权测试请求)</small></div>
  <div class="pair">
    <div class="pkt"><b>【左·请求包】</b>
${esc(reqTxt(d.replay))}</div>
    <div class="pkt"><b>【右·响应包】</b> HTTP ${d.replay.status} ${esc(d.replay.location?('302→'+d.replay.location):'')} ${d.replay.err?('ERR '+d.replay.err):''}
${esc((d.replay.body||'').slice(0,4000))}</div>
  </div>`:''}
  <div class="row"><button class="act ghost" onclick="closeDlg()">关闭</button></div>`;
  document.getElementById('ovl').classList.add('show');
}
function reqTxt(p){if(!p)return'(无)';
  let s=`${p.method} ${p.url}\n`;
  for(const[k,v]of Object.entries(p.headers||{}))s+=`${k}: ${v}\n`;
  if(p.post_data)s+=`\n${p.post_data}`;
  return s}
function closeDlg(){document.getElementById('ovl').classList.remove('show')}
function exportFile(kind){window.open('/api/export_'+kind+'?ts='+S.current,'_blank')}
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
refresh();setInterval(refresh,1500);
</script>
</body>
</html>
"""
