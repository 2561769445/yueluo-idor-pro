#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""idor_pro.py — 越权测试工具主程序
用法: python idor_pro.py   →  http://127.0.0.1:8777 (自动弹出控制台)
流程: 添加账号 → 开启测试(弹N个浏览器+CDP录制) → 手动遍历功能点 → 开始越权测试(交叉重放+判定) → 筛查/导出"""
import json
import os
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
sys.path.insert(0, BASE)
WORKDIR = os.path.join(BASE, "idor_workdir")
os.makedirs(WORKDIR, exist_ok=True)
os.makedirs(os.path.join(WORKDIR, "sessions"), exist_ok=True)
os.makedirs(os.path.join(WORKDIR, "logs"), exist_ok=True)

from browser import find_browser, find_free_port, launch as browser_launch, kill_pid, cdp_alive  # noqa: E402
from recorder import Recorder  # noqa: E402
from replayer import Replayer, LEVEL_NAME  # noqa: E402
from crawler import Crawler  # noqa: E402
from ai_judge import AIJudge  # noqa: E402
from ui import HTML  # noqa: E402

AI_CFG_PATH = os.path.join(WORKDIR, "ai_config.json")
SET_CFG_PATH = os.path.join(WORKDIR, "settings.json")


def load_ai_cfg():
    try:
        return json.load(open(AI_CFG_PATH, encoding="utf-8"))
    except Exception:
        return {"base_url": "", "api_key": "", "model": "glm-4-flash"}


def load_set_cfg():
    try:
        return json.load(open(SET_CFG_PATH, encoding="utf-8"))
    except Exception:
        return {"proxy": ""}


def proxy_reachable(proxy):
    """预检代理连通性: 解析host:port并TCP探测"""
    try:
        import re as _re
        m = _re.search(r"://([^/:]+):(\d+)", proxy or "")
        if not m:
            return False, "代理地址格式应为 http://127.0.0.1:8080"
        import socket
        with socket.create_connection((m.group(1), int(m.group(2))), timeout=3):
            return True, ""
    except Exception as e:
        return False, f"代理不可达({proxy}): {type(e).__name__} — Burp开了吗? Intercept是否关闭?"


# ================= 状态 =================
class App:
    def __init__(self):
        self.lock = threading.RLock()
        self.accounts = []          # {name, start_url, port, pid, recorder, error}
        self.current = ""           # 当前会话ts
        self.results = []           # 当前会话结果
        self.testing = False
        self.stop_flag = None
        self.done = 0
        self.total = 0
        self.logs = []              # 最近日志
        self.http_port = 8777
        self.crawlers = {}          # name -> Crawler
        self.crawl_prog = {}        # name -> {phase,total,done}
        self.ai = None              # AIJudge实例

    def log(self, msg):
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        with self.lock:
            self.logs.append(line)
            self.logs = self.logs[-300:]
        try:
            print(line, flush=True)
            with open(os.path.join(WORKDIR, "logs", "idor_pro.log"), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    # ---------- 会话 ----------
    def sess_dir(self, ts=None):
        ts = ts or self.current
        return os.path.join(WORKDIR, "sessions", ts) if ts else ""

    def list_sessions(self):
        out = []
        root = os.path.join(WORKDIR, "sessions")
        for ts in sorted(os.listdir(root), reverse=True):
            d = os.path.join(root, ts)
            meta_p = os.path.join(d, "meta.json")
            res_p = os.path.join(d, "results.json")
            if not os.path.isfile(meta_p):
                continue
            try:
                meta = json.load(open(meta_p, encoding="utf-8"))
                n = len(json.load(open(res_p, encoding="utf-8"))) if os.path.isfile(res_p) else 0
            except Exception:
                meta, n = {}, 0
            accts = ",".join(meta.get("accounts", []))
            out.append({"ts": ts, "label": f"{ts} [{accts}]", "count": n})
        return out

    def load_session(self, ts):
        with self.lock:
            self.current = ts
            p = os.path.join(self.sess_dir(), "results.json")
            try:
                self.results = json.load(open(p, encoding="utf-8"))
            except Exception:
                self.results = []

    def save_results(self):
        with self.lock:
            if not self.current:
                return
            try:
                p = os.path.join(self.sess_dir(), "results.json")
                tmp = p + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self.results, f, ensure_ascii=False)
                os.replace(tmp, p)
            except Exception as e:
                self.log(f"[!] 结果落盘失败({self.current}): {e}")

    # ---------- 操作 ----------
    def start(self):
        """开启测试: 新会话 + 确保所有账号浏览器在线 + 重启录制"""
        with self.lock:
            if self.testing:
                return False, "测试进行中, 请先停止"
            accts = [a for a in self.accounts if a.get("name")]
            if not accts:
                return False, "请先添加账号"
            if len(accts) == 1:
                self.log("⚠ 仅1个账号: 只能做基线+去凭证测试, 交叉越权需≥2账号")
            bw = find_browser()
            if not bw:
                return False, "未找到 Chrome/Edge 浏览器, 请先安装"
            used_ports = set()
            # 1) 停旧录制
            for a in self.accounts:
                if a.get("recorder"):
                    a["recorder"].stop()
                    a["recorder"] = None
            time.sleep(0.3)
            # 2) 新会话目录
            ts = time.strftime("%Y%m%d_%H%M%S")
            os.makedirs(os.path.join(WORKDIR, "sessions", ts), exist_ok=True)
            self.current = ts
            self.results = []
            self.done = self.total = 0
            # 3) 逐账号启动/复用浏览器 + 开录制
            meta_accts = []
            win_idx = 0
            for a in self.accounts:
                if not a.get("name"):
                    continue
                try:
                    alive = a.get("pid") and cdp_alive(a.get("port", 0))
                    if not alive:
                        used = used_ports | {x.get("port") for x in self.accounts if x.get("port")}
                        port = find_free_port(9222, used)
                        # 起始页=欢迎页(窗口标题带账号编号, 8秒后跳转目标系统)
                        welcome = f"http://127.0.0.1:{self.http_port}/welcome?acct={urllib.parse.quote(a['name'])}&url={urllib.parse.quote(a.get('start_url') or 'about:blank')}"
                        info = browser_launch(a["name"].replace("/", "_"), welcome, WORKDIR, port, idx=win_idx)
                        a["port"], a["pid"] = info["port"], info["pid"]
                        used_ports.add(port)
                        self.log(f"浏览器已启动: 【{a['name']}】 → 127.0.0.1:{port} (PID {info['pid']}, 窗口#{win_idx + 1})")
                    else:
                        self.log(f"复用已有浏览器: {a['name']} → :{a['port']}")
                    rec = Recorder(a["port"], a["name"], log_fn=self.log)
                    rec.start()
                    a["recorder"] = rec
                    a["error"] = None
                    meta_accts.append(a["name"])
                    win_idx += 1
                except Exception as e:
                    a["error"] = str(e)
                    self.log(f"账号 {a['name']} 启动失败: {e}")
            with open(os.path.join(self.sess_dir(), "meta.json"), "w", encoding="utf-8") as f:
                json.dump({"ts": ts, "accounts": meta_accts}, f, ensure_ascii=False)
            ok = any(a.get("recorder") and a["recorder"].alive() for a in self.accounts)
            if not ok:
                return False, "所有账号浏览器/录制均启动失败, 请查看日志"
            self.log(f"✅ 会话 {ts} 已开启, 请在弹出的浏览器中登录并遍历功能点")
            return True, f"会话{ts}已开启, 请登录并遍历功能点后点「开始越权测试」"

    def stop_all(self):
        """停录制+关闭所有浏览器(精确PID)"""
        with self.lock:
            for a in self.accounts:
                if a.get("recorder"):
                    a["recorder"].stop()
                    a["recorder"] = None
                if a.get("pid"):
                    kill_pid(a["pid"])
                    self.log(f"浏览器已关闭: {a['name']} (PID {a['pid']})")
                    a["pid"] = a["port"] = None

    def run_test(self, settings):
        """后台线程: 快照录制 → 重放判定"""
        caps = {}
        with self.lock:
            if self.testing:
                return
            for a in self.accounts:
                if a.get("recorder") and a.get("name"):
                    rec = a["recorder"]
                    snap = rec.snapshot()
                    if not snap:
                        continue
                    # 补Cookie: extraInfo时序不可靠, 直接拉浏览器当前Cookie补齐缺失条目
                    try:
                        ck = rec.get_cookies() if rec.alive() else ""
                    except Exception:
                        ck = ""
                    if ck:
                        n = 0
                        for e in snap:
                            if e.get("cookie_missing"):
                                e["headers"]["Cookie"] = ck
                                e.pop("cookie_missing", None)
                                n += 1
                        if n:
                            self.log(f"账号 {a['name']}: {n}条录制补齐Cookie(主动拉取)")
                    caps[a["name"]] = snap
            if not caps:
                return self.log("❌ 无录制数据, 请先开启测试并遍历功能点")
            self.testing = True
            self.stop_flag = threading.Event()
            self.done = 0
            n = len(caps)
            est = sum(len(v) for v in caps.values())
            self.total = est * max(1, (n - 1 + (1 if settings.get("include_noauth", True) else 0)))
            ts_now = self.current
            # 保存录制快照
            for name, lst in caps.items():
                with open(os.path.join(self.sess_dir(ts_now), f"capture_{name}.json"), "w", encoding="utf-8") as f:
                    json.dump(lst, f, ensure_ascii=False)

        def on_result(rec):
            with self.lock:
                self.results.append(rec)
                self.done += 1
            self.save_results()

        def worker():
            try:
                rp = Replayer(caps, settings, on_result, self.stop_flag, log=self.log)
                rp.run()
            except Exception as e:
                self.log(f"❌ 测试线程异常: {e}")
            finally:
                with self.lock:
                    self.testing = False
                self.log("测试结束, 结果已保存")

        threading.Thread(target=worker, daemon=True).start()

    def state(self):
        with self.lock:
            accts = []
            for a in self.accounts:
                rec = a.get("recorder")
                accts.append({
                    "name": a.get("name", ""), "start_url": a.get("start_url", ""),
                    "role": a.get("role", ""),
                    "port": a.get("port"), "running": bool(a.get("pid") and cdp_alive(a.get("port") or 0)),
                    "recording": bool(rec and rec.alive()),
                    "captured": rec.count() if rec else 0,
                    "crawling": bool(self.crawlers.get(a.get("name", "")) and
                                     self.crawlers[a.get("name", "")].is_alive()),
                    "crawl": self.crawl_prog.get(a.get("name", "")),
                    "error": rec.error if rec else a.get("error"),
                })
            return {
                "accounts": accts, "current": self.current, "testing": self.testing,
                "done": self.done, "total": self.total,
                "results": self.results[-2000:], "sessions": self.list_sessions(),
                "log": self.logs[-40:],
                "ai_running": bool(self.ai and self.ai.running),
                "ai_done": self.ai.done if self.ai else 0,
                "ai_total": self.ai.total if self.ai else 0,
                "ai_cfg": {"base_url": load_ai_cfg().get("base_url", ""),
                           "model": load_ai_cfg().get("model", ""),
                           "has_key": bool(load_ai_cfg().get("api_key"))},
                "proxy": load_set_cfg().get("proxy", ""),
            }

    def start_crawl(self):
        """对所有在线录制账号启动自动遍历"""
        with self.lock:
            if self.testing:
                return False, "越权测试进行中, 请先停止"
            started = 0
            for a in self.accounts:
                rec = a.get("recorder")
                if not (rec and rec.alive()) or not a.get("name"):
                    continue
                base = a.get("start_url") or rec.page_url() or "about:blank"
                if "about:" in base:
                    return False, f"账号 {a['name']} 无起始URL且当前页为空"
                name = a["name"]
                if name in self.crawlers and self.crawlers[name].is_alive():
                    continue
                cw = Crawler(rec, name, base, log=self.log,
                             on_progress=(lambda n: (lambda phase="", total=0, done=0, stats=None:
                                                     self._crawl_cb(n, phase=phase, total=total,
                                                                    done=done, stats=stats)))(name))
                self.crawlers[name] = cw
                self.crawl_prog[name] = {"phase": "启动", "total": 0, "done": 0}
                cw.start()
                started += 1
            if not started:
                return False, "没有在线的录制账号 (先「开启测试」并登录)"
            self.log(f"🕸 自动遍历已启动: {started} 个账号 (遍历中请勿操作浏览器)")
            return True, f"自动遍历启动({started}个账号), 遍历中请勿操作浏览器窗口"

    def _crawl_cb(self, name, phase="", total=0, done=0, stats=None):
        with self.lock:
            self.crawl_prog[name] = {"phase": phase, "total": total, "done": done,
                                     "stats": stats}


APP = App()


# ================= 导出 =================
def export_report(ts):
    d = os.path.join(WORKDIR, "sessions", ts)
    try:
        results = json.load(open(os.path.join(d, "results.json"), encoding="utf-8"))
        meta = json.load(open(os.path.join(d, "meta.json"), encoding="utf-8"))
    except Exception:
        results, meta = [], {}
    cnt = {}
    for r in results:
        cnt[r["level"]] = cnt.get(r["level"], 0) + 1

    def esc(s):
        return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def req_txt(p):
        if not p:
            return "(无)"
        s = f"{p.get('method')} {p.get('url')}\n"
        for k, v in (p.get("headers") or {}).items():
            s += f"{k}: {v}\n"
        if p.get("post_data"):
            s += "\n" + str(p["post_data"])
        return s

    def block(r):
        rows = f"<h3>{LEVEL_NAME.get(r['level'], r['level'])} {esc(r['category'])}</h3>"
        if r.get("evidence"):
            rows += f"<div class='vuln'>{esc(r['evidence'])}</div>"
        rows += f"<p class='meta'>{r['method']} {esc(r['url'])} · 录制:{esc(r['owner'])}"
        if r.get("cross_account"):
            rows += f" → 重放凭证:{esc(r['cross_account'])}"
        rows += f" · {r['ts']} · {r['id']}</p>"
        # 对照组一: 原始(左请求|右响应)
        rows += "<div class='pl'>▣ 对照组一: 原始请求 (录制账号正常操作时抓取)</div><div class='pair'>"
        rows += f"<div class='pkt'><b>【左·请求包】</b>\n{esc(req_txt(r.get('orig')))}</div>"
        rows += f"<div class='pkt'><b>【右·响应包】</b> HTTP {r.get('orig', {}).get('status', '?')}\n{esc((r.get('orig', {}).get('body') or '(未捕获)')[:4000])}</div></div>"
        if r.get("baseline"):
            rows += f"<div class='pl'>▣ 基线重放 (原凭证原样重放, 排除防重放干扰) → HTTP {r['baseline'].get('status')}</div>"
        # 对照组二: 重放(左请求|右响应)
        if r.get("replay"):
            tag = "去掉全部凭证" if r["mode"] == "noauth" else f"凭证替换为 {esc(r.get('cross_account', ''))}"
            rows += f"<div class='pl'>▣ 对照组二: 重放请求 ({tag} — 越权测试)</div><div class='pair'>"
            rows += f"<div class='pkt'><b>【左·请求包】</b>\n{esc(req_txt(r['replay']))}</div>"
            loc = f" 302→{esc(r['replay'].get('location') or '')}" if r['replay'].get('location') else ""
            err = f" ERR:{esc(r['replay'].get('err') or '')}" if r['replay'].get("err") else ""
            rows += (f"<div class='pkt'><b>【右·响应包】</b> HTTP {r['replay'].get('status')}{loc}{err}\n"
                     f"{esc((r['replay'].get('body') or '')[:4000])}</div></div>")
        return rows

    highs = [r for r in results if r["level"] == "high" and r.get("mark") != "false_positive"]
    mids = [r for r in results if r["level"] == "mid" and r.get("mark") != "false_positive"]
    stat = "".join(f"<span>{LEVEL_NAME.get(k, k)}: <b>{v}</b></span>" for k, v in cnt.items())
    html = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>越权测试报告 {ts}</title>
<style>body{{font-family:"Microsoft YaHei";margin:0;background:#f5f6fa;color:#222}}
.hd{{background:#1a2933;color:#fff;padding:24px}}.hd h1{{font-size:22px;margin-bottom:6px}}
.metas{{color:#9ab;font-size:13px}}.wrap{{max-width:1280px;margin:20px auto;padding:0 16px}}
.stats{{display:flex;gap:18px;flex-wrap:wrap;background:#fff;padding:14px;border-radius:8px;margin-bottom:16px}}
.stats b{{font-size:18px}}.sec{{background:#fff;border-radius:8px;padding:18px;margin-bottom:16px}}
h2{{font-size:17px;border-left:4px solid #3d9eff;padding-left:10px;margin-bottom:12px}}
h3{{font-size:15px;margin:14px 0 4px}}.meta{{color:#888;font-size:12px;word-break:break-all}}
.vuln{{background:#fdf3f3;border:1px solid #ecd5d5;border-radius:6px;padding:10px;font-size:13px;white-space:pre-line;color:#7a2e2e;margin:6px 0}}
.pair{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:4px 0 12px}}
.pl{{font-size:13px;font-weight:600;margin:10px 0 2px;color:#333}}
.pkt{{background:#f2f4f7;border:1px solid #dde;padding:10px;font-family:Consolas;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:340px;overflow:auto}}
.pkt b{{color:#1a6fc9}}</style></head><body>
<div class="hd"><h1>越权测试报告</h1><div class="metas">会话 {ts} · 账号: {esc(','.join(meta.get('accounts', [])))} · 生成于 {time.strftime('%Y-%m-%d %H:%M:%S')}</div></div>
<div class="wrap"><div class="stats">{stat}</div>
<div class="sec"><h2>🔴 高危发现 ({len(highs)})</h2>{''.join(block(r) for r in highs) or '<p>无</p>'}</div>
<div class="sec"><h2>🟡 中危/需人工确认 ({len(mids)})</h2>{''.join(block(r) for r in mids) or '<p>无</p>'}</div>
<div class="sec"><h2>数据包说明</h2><p style="font-size:13px;color:#555">每个发现含两组左右对照: <b>左为请求包、右为响应包</b>。
对照组一为账号正常操作时的原始流量; 对照组二为越权测试请求(换凭证/去凭证/换ID)及其响应。
复现时直接发送对照组二左侧的请求包即可(头部逐行转为 curl 的 <code>-H</code> 参数)。</p></div>
</div></body></html>"""
    return html


def export_ai(ts):
    d = os.path.join(WORKDIR, "sessions", ts)
    try:
        results = json.load(open(os.path.join(d, "results.json"), encoding="utf-8"))
    except Exception:
        results = []
    lines = [f"# AI误报筛查包 — 会话 {ts}",
             "",
             f"- 待筛查: {len([r for r in results if r['level'] in ('high', 'mid')])} 条 (高危+中危)",
             "- 请逐条判定: 真漏洞 / 误报(说明理由) / 需补充验证(说明缺什么)",
             ""]
    for r in results:
        if r["level"] not in ("high", "mid"):
            continue
        lines += [f"## [{r['id']}] {LEVEL_NAME.get(r['level'])} {r['category']}",
                  f"- URL: `{r['method']} {r['url']}`",
                  f"- 录制账号: {r['owner']}" + (f" / 重放凭证: {r['cross_account']}" if r.get("cross_account") else " / (去凭证)"),
                  f"- 证据: {r['evidence']}",
                  f"- 原始响应: HTTP {r.get('orig', {}).get('status')} `{(r.get('orig', {}).get('body') or '')[:600]}`",
                  f"- 重放响应: HTTP {r.get('replay', {}).get('status')} `{(r.get('replay', {}).get('body') or '')[:600]}`",
                  f"- 重放请求头: `{json.dumps(r.get('replay', {}).get('headers') or {}, ensure_ascii=False)[:500]}`",
                  ""]
    return "\n".join(lines)


# ================= HTTP =================
WELCOME_PAGE = """<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>【%(acct)s】越权测试</title>
<style>body{font-family:"Microsoft YaHei";background:linear-gradient(135deg,#1a2a3a,#0f1419);color:#fff;
display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;margin:0}
.badge{font-size:56px;font-weight:900;color:#3d9eff;text-shadow:0 0 30px #3d9eff88;margin-bottom:16px}
.tip{color:#9ab;font-size:16px;margin-bottom:8px}
a.go{display:inline-block;margin-top:20px;padding:14px 44px;background:#2f9e5f;color:#fff;border-radius:8px;
text-decoration:none;font-size:20px;font-weight:700}
a.go:hover{background:#37b96e}</style></head><body>
<div class="badge">▶ 此浏览器 = %(acct)s</div>
<div class="tip">请在本窗口登录 <b>%(acct)s</b> 的账号, 然后遍历所有功能点</div>
<div class="tip">目标系统: <b>%(target)s</b></div>
<a class="go" href="%(url)s">→ 点击进入目标系统 ←</a>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text, name="report.html"):
        import urllib.parse as up
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # HTTP头不能含非ASCII: 用RFC5987编码中文文件名
        self.send_header("Content-Disposition",
                         f"attachment; filename*=UTF-8''{up.quote(name)}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if u.path == "/favicon.ico":
            ico = os.path.join(getattr(sys, "_MEIPASS", BASE), "assets", "yueluo.ico")
            try:
                body = open(ico, "rb").read()
            except Exception:
                body = b""
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if u.path == "/welcome":
            q = parse_qs(u.query)
            acct = (q.get("acct") or ["账号"])[0][:30]
            target = (q.get("url") or ["about:blank"])[0]
            page = WELCOME_PAGE % {"acct": acct, "url": target, "target": target[:80]}
            body = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if u.path == "/api/state":
            return self._json(APP.state())
        if u.path == "/api/detail":
            rid = (parse_qs(u.query).get("id") or [""])[0]
            with APP.lock:
                r = next((x for x in APP.results if x["id"] == rid), None)
            return self._json({"ok": bool(r), "data": r, "msg": "" if r else "未找到"})
        if u.path == "/api/export_report":
            ts = (parse_qs(u.query).get("ts") or [APP.current])[0]
            return self._html(export_report(ts), f"越权测试报告_{ts}.html")
        if u.path == "/api/export_ai":
            ts = (parse_qs(u.query).get("ts") or [APP.current])[0]
            md = export_ai(ts)
            body = md.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition",
                             f"attachment; filename*=UTF-8''{urllib.parse.quote(f'AI筛查包_{ts}.md')}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        return self._json({"ok": False, "msg": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            body = {}
        if u.path == "/api/account":
            op = body.get("op")
            with APP.lock:
                if op == "add":
                    APP.accounts.append({"name": f"账号{chr(97 + len(APP.accounts))}", "start_url": "", "port": None, "pid": None, "recorder": None, "error": None})
                elif op == "del":
                    a = next((x for x in APP.accounts if x["name"] == body.get("name")), None)
                    if a:
                        if a.get("recorder"):
                            a["recorder"].stop()
                        if a.get("pid"):
                            kill_pid(a["pid"])
                        APP.accounts.remove(a)
                elif op == "upd":
                    i, k, v = body.get("idx"), body.get("key"), body.get("value")
                    if i is not None and 0 <= i < len(APP.accounts) and k in ("name", "start_url", "role"):
                        APP.accounts[i][k] = v.strip()[:200]
            return self._json({"ok": True})
        if u.path == "/api/start":
            ok, msg = APP.start()
            return self._json({"ok": ok, "msg": msg})
        if u.path == "/api/stop_all":
            APP.stop_all()
            return self._json({"ok": True, "msg": "已停止录制并关闭浏览器"})
        if u.path == "/api/test":
            # 遍历保护: 自动遍历进行中拒绝开跑(录制池还在变, 测了也白测)
            with APP.lock:
                crawling = [n for n, cw in APP.crawlers.items() if cw.is_alive()]
            if crawling:
                return self._json({"ok": False,
                                   "msg": f"自动遍历进行中({','.join(crawling)}), 请等遍历完成后再开始测试 (或先停止遍历)"})
            settings = {
                "skip_delete": body.get("skip_delete", True),
                "get_only": body.get("get_only", False),
                "include_noauth": body.get("include_noauth", True),
                "deep_bypass": body.get("deep_bypass", True),
                "concurrency": int(body.get("concurrency", 4)),
                "proxy": str(body.get("proxy", "")).strip(),
            }
            # 代理预检: 开了代理但连不上就直接拒绝开跑(避免整轮error)
            if settings["proxy"]:
                ok, msg = proxy_reachable(settings["proxy"])
                if not ok:
                    return self._json({"ok": False, "msg": msg})
            with APP.lock:
                if APP.testing:
                    return self._json({"ok": False, "msg": "测试进行中"})
                if not APP.current:
                    return self._json({"ok": False, "msg": "请先点「开启测试」"})
            APP.run_test(settings)
            return self._json({"ok": True, "msg": "测试已启动" + (f"(经代理 {settings['proxy']})" if settings["proxy"] else "")})
        if u.path == "/api/proxy_config":
            cfg = {"proxy": str(body.get("proxy", "")).strip()}
            with open(SET_CFG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False)
            if cfg["proxy"]:
                ok, msg = proxy_reachable(cfg["proxy"])
                APP.log(f"[proxy] 代理配置: {cfg['proxy']} → {'可达' if ok else '不可达: ' + msg}")
                return self._json({"ok": ok, "msg": "代理可达, 配置已保存" if ok else msg})
            return self._json({"ok": True, "msg": "已清除代理(直连)"})
        if u.path == "/api/stop_test":
            if APP.stop_flag:
                APP.stop_flag.set()
            return self._json({"ok": True, "msg": "正在停止…"})
        if u.path == "/api/result_delete":
            ids = set(body.get("ids", []))
            with APP.lock:
                APP.results = [r for r in APP.results if r["id"] not in ids]
            APP.save_results()
            return self._json({"ok": True, "msg": f"已删除{len(ids)}条"})
        if u.path == "/api/result_mark":
            ids, mk = set(body.get("ids", [])), body.get("mark", "pending")
            with APP.lock:
                for r in APP.results:
                    if r["id"] in ids:
                        r["mark"] = mk
            APP.save_results()
            return self._json({"ok": True, "msg": "已标记"})
        if u.path == "/api/_drive":
            # 内部测试钩子: 在指定账号的页面上执行JS/导航(e2e验收用, 走录制同一连接)
            name = body.get("name", "")
            rec = next((a.get("recorder") for a in APP.accounts if a.get("name") == name), None)
            if not rec or not rec.alive():
                return self._json({"ok": False, "msg": f"录制器不在线 err={getattr(rec,'error',None)}"})
            if body.get("wait"):
                rec.ready.wait(int(body["wait"]))
                return self._json({"ok": rec.ready.is_set(), "msg": "" if rec.ready.is_set() else "等待page超时"})
            if body.get("nav"):
                ok = rec.navigate_to(body["nav"])
                return self._json({"ok": ok, "msg": "" if ok else "导航失败"})
            val = rec.eval_on_page(body.get("js", ""), timeout=45)
            return self._json({"ok": val is not None, "data": val})
        if u.path == "/api/crawl":
            ok, msg = APP.start_crawl()
            return self._json({"ok": ok, "msg": msg})
        if u.path == "/api/crawl_stop":
            with APP.lock:
                for cw in APP.crawlers.values():
                    cw.stop()
            return self._json({"ok": True, "msg": "正在停止遍历…"})
        if u.path == "/api/ai_config":
            cfg = {"base_url": str(body.get("base_url", "")).strip(),
                   "api_key": str(body.get("api_key", "")).strip(),
                   "model": str(body.get("model", "glm-4-flash")).strip() or "glm-4-flash"}
            with open(AI_CFG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False)
            APP.log(f"[ai] AI配置已保存: {cfg['base_url']} model={cfg['model']} "
                    f"key={'已填' if cfg['api_key'] else '空'}")
            return self._json({"ok": True, "msg": "AI配置已保存"})
        if u.path == "/api/ai_models":
            # 拉取OpenAI兼容 /models 列表 (智谱/OpenAI/自建网关通用)
            import requests as _rq
            base = str(body.get("base_url", "")).strip().rstrip("/")
            key = str(body.get("api_key", "")).strip()
            if not base or not key:
                return self._json({"ok": False, "msg": "请先填写API地址和Key"})
            try:
                rr = _rq.get(f"{base}/models",
                             headers={"Authorization": f"Bearer {key}"},
                             timeout=15, verify=False,
                             proxies={"http": None, "https": None})
                rr.raise_for_status()
                data = rr.json().get("data") or []
                ids = sorted(str(m.get("id")) for m in data if m.get("id"))
                APP.log(f"[ai] 拉取到 {len(ids)} 个模型: {', '.join(ids[:8])}{'…' if len(ids) > 8 else ''}")
                return self._json({"ok": True, "models": ids[:100],
                                   "msg": f"获取到{len(ids)}个模型, 已填入下拉列表"})
            except Exception as e:
                return self._json({"ok": False,
                                   "msg": f"拉取模型列表失败: {str(e)[:100]} — 可手动输入模型名"})
        if u.path == "/api/ai_judge":
            cfg = load_ai_cfg()
            with APP.lock:
                if not APP.results:
                    return self._json({"ok": False, "msg": "当前会话无结果"})
                if APP.ai and APP.ai.running:
                    return self._json({"ok": False, "msg": "AI筛查进行中"})
                APP.ai = AIJudge(cfg, log=APP.log)
                roles = "; ".join(f"{a.get('name')}={a.get('role', '未标注')}"
                                  for a in APP.accounts if a.get("name"))
                results_ref = APP.results

            def safe_save(_r=None):
                try:
                    APP.save_results()
                except Exception as e:
                    APP.log(f"[ai] 判定结果落盘失败: {e}")
            ok = APP.ai.start(results_ref, on_update=safe_save, roles=roles)
            if not ok:
                return self._json({"ok": False, "msg": "AI未配置: 请先填写API地址和Key"})
            return self._json({"ok": True, "msg": f"AI筛查已启动({APP.ai.total}条疑似项)"})
        if u.path == "/api/session_switch":
            APP.load_session(body.get("ts", ""))
            return self._json({"ok": True})
        if u.path == "/api/session_delete":
            import shutil
            ts = body.get("ts", "")
            d = os.path.join(WORKDIR, "sessions", ts)
            if ts and os.path.isdir(d) and ".." not in ts:
                shutil.rmtree(d, ignore_errors=True)
                with APP.lock:
                    if APP.current == ts:
                        APP.current, APP.results = "", []
                APP.log(f"会话 {ts} 已删除")
            return self._json({"ok": True, "msg": "会话已删除"})
        if u.path == "/api/session_clear":
            # 批量清空: 删除全部历史会话(保留当前)
            import shutil
            n = 0
            root = os.path.join(WORKDIR, "sessions")
            for ts in list(os.listdir(root)):
                d = os.path.join(root, ts)
                if not os.path.isdir(d) or ts == APP.current:
                    continue
                shutil.rmtree(d, ignore_errors=True)
                n += 1
            APP.log(f"已批量清空 {n} 个历史会话")
            return self._json({"ok": True, "msg": f"已清空 {n} 个历史会话(当前会话保留)"})
        return self._json({"ok": False, "msg": "not found"}, 404)


def main():
    port = APP.http_port
    while True:
        import socket
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                break
        port += 1
    APP.http_port = port
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    APP.log(f"越权测试工具已启动: {url}")
    APP.log(f"数据目录: {WORKDIR}")
    try:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        APP.stop_all()


if __name__ == "__main__":
    main()
