#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""crawler.py — 自动遍历引擎 (升级一: 人只登录, 工具扫全站)
三层遍历:
  ① SPA路由导航: 收集页面路由(a[href]/Vue Router) → Page.navigate逐个 → 页面加载时自动发的API全被CDP录制
  ② API变体枚举: 从已录制URL提取API模块前缀 × 常见子端点(list/page/detail/export...) → 页面内fetch(带登录态)
  ③ DOM链接收集: 同域链接直接fetch
安全: 只发GET; 跳过删除语义/认证类/外域; 限速; 总量上限"""
import json
import re
import threading
import time
from urllib.parse import urljoin, urlsplit

DELETE_RE = re.compile(r"(delete|remove|destroy|\bdel\b|\bdrop\b|\bclear\b)", re.I)
AUTH_RE = re.compile(
    r"(login|logout|signin|signup|register|captcha|verif|sms|sendcode|sso|oauth|password|forget|kaptcha)", re.I)
STATIC_RE = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|mp3)([?#]|$)", re.I)
# 常见API子端点名 (对已见模块前缀做变体枚举)
COMMON_SUBS = ["list", "page", "all", "detail", "info", "export", "tree", "search", "query",
               "count", "stat", "get", "view", "index", "data", "menu", "config"]

# 页面内执行的链接/路由收集JS
COLLECT_JS = """(function(){
  var out = [];
  try{ document.querySelectorAll('a[href]').forEach(function(a){
    var h = a.getAttribute('href') || '';
    if(h && h !== '#' && !h.startsWith('javascript:') && !/^https?:\\/\\//i.test(h) && !h.startsWith('//'))
      out.push(h);
  }); }catch(e){}
  try{ // Vue2 router
    var app = document.querySelector('#app');
    if(app && app.__vue__ && app.__vue__.$router){
      app.__vue__.$router.options.routes.forEach(function(r){
        if(r.path) out.push(r.path);
        (r.children||[]).forEach(function(c){ if(c.path) out.push((r.path+'/'+c.path).replace(/\\/\\+/g,'/')); });
      });
    }
  }catch(e){}
  try{ // Vue3 router
    var app3 = document.querySelector('#app');
    if(app3 && app3.__vue_app__){
      var gr = app3.__vue_app__.config.globalProperties.$router;
      (gr && gr.getRoutes ? gr.getRoutes() : []).forEach(function(r){ if(r.path) out.push(r.path); });
    }
  }catch(e){}
  return JSON.stringify([...new Set(out)].slice(0, 200));
})()"""

FETCH_JS = """(async function(){
  try{ const r = await fetch(%s, {credentials:'same-origin', redirect:'follow'});
    const t = await r.text().catch(()=>'');
    return JSON.stringify({s: r.status, u: r.url, b: t.slice(0, 400)});
  }catch(e){ return JSON.stringify({s:0, u:'', b:''}); }
})()"""


class Crawler(threading.Thread):
    """单账号自动遍历器。用法: Crawler(rec, account, base_url, log, on_progress).start()"""

    def __init__(self, rec, account, base_url, log=print, on_progress=None,
                 max_routes=30, max_api=200, dwell=2.0):
        super().__init__(daemon=True)
        self.rec = rec
        self.account = account
        self.base = base_url            # 起始URL(登录后所在域)
        self.log = log
        self.on_progress = on_progress or (lambda **k: None)
        self.max_routes, self.max_api, self.dwell = max_routes, max_api, dwell
        self.stop_flag = threading.Event()
        self.stats = {"routes": 0, "apis": 0, "found": 0}
        self.error = None

    def stop(self):
        self.stop_flag.set()

    # ---------- 收集 ----------
    def _origin(self):
        sp = urlsplit(self.base)
        return f"{sp.scheme}://{sp.netloc}"

    def _collect_routes(self):
        raw = self.rec.eval_on_page(COLLECT_JS, timeout=15)
        routes = []
        try:
            for h in json.loads(raw or "[]"):
                h = str(h).strip()
                if not h or h.startswith(("mailto:", "tel:")):
                    continue
                full = urljoin(self.base, h)
                sp = urlsplit(full)
                if f"{sp.scheme}://{sp.netloc}" != self._origin():
                    continue                      # 只在本站内遍历
                if STATIC_RE.search(sp.path):
                    continue
                routes.append(full.split("#")[0] or full)
        except Exception:
            pass
        return routes

    def _api_prefixes(self):
        """从已录制URL提取API模块前缀: /api/order/detail?id=1 → /api/order/"""
        prefixes = set()
        for e in self.rec.snapshot():
            sp = urlsplit(e["url"])
            segs = [s for s in sp.path.split("/") if s]
            if len(segs) >= 2:
                # 末段若是明细型子端点, 取父前缀; 数字段视为ID截断
                cut = []
                for s in segs:
                    if re.fullmatch(r"\d+", s):
                        break
                    cut.append(s)
                if len(cut) >= 2:
                    prefixes.add("/" + "/".join(cut[:len(cut) - 1 if len(cut) > 2 else len(cut)]) + "/")
        return sorted(p for p in prefixes if not DELETE_RE.search(p) and not AUTH_RE.search(p))[:20]

    # ---------- 执行 ----------
    def run(self):
        try:
            self.log(f"[crawl:{self.account}] 自动遍历启动 (起点 {self.base})")
            # ① SPA路由导航
            routes = self._collect_routes()
            # 当前URL也入列(先回首页确保登录态上下文)
            seen = set()
            todo = [r for r in routes if r not in seen][:self.max_routes]
            self.on_progress(phase="路由导航", total=len(todo), done=0)
            for i, url in enumerate(todo):
                if self.stop_flag.is_set():
                    break
                if DELETE_RE.search(url) or AUTH_RE.search(url):
                    continue
                self.rec.navigate_to(url)
                self.stats["routes"] += 1
                time.sleep(self.dwell)          # 等页面mounted发API
                seen.add(url)
                self.on_progress(phase="路由导航", total=len(todo), done=i + 1)
            n0 = self.rec.count()
            # ② API变体枚举 (页面内fetch, 天然带登录态且被CDP录制)
            prefixes = self._api_prefixes()
            cands = []
            for p in prefixes:
                for sub in COMMON_SUBS:
                    cands.append(self._origin() + p + sub)
            cands = [c for c in dict.fromkeys(cands)
                     if not DELETE_RE.search(c) and not AUTH_RE.search(c)][:self.max_api]
            self.on_progress(phase="API枚举", total=len(cands), done=0)
            for i, url in enumerate(cands):
                if self.stop_flag.is_set():
                    break
                js = FETCH_JS % json.dumps(url)
                self.rec.eval_on_page(js, timeout=10)
                self.stats["apis"] += 1
                time.sleep(0.12)
                if i % 20 == 19:
                    self.on_progress(phase="API枚举", total=len(cands), done=i + 1)
            self.stats["found"] = self.rec.count() - n0 + self.stats["routes"]
            self.log(f"[crawl:{self.account}] 遍历完成: 导航{self.stats['routes']}个路由, "
                     f"枚举{self.stats['apis']}个API, 录制池新增至 {self.rec.count()} 条")
            self.on_progress(phase="完成", total=0, done=0, stats=self.stats)
        except Exception as e:
            self.error = str(e)
            self.log(f"[crawl:{self.account}] 遍历异常: {e}")
            self.on_progress(phase="异常", total=0, done=0)
