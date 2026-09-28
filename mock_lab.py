#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mock_lab.py — 越权测试工具本地验收靶场 (纯stdlib, 零依赖)
3账号: alice/bob(普通) + admin(管理员), 密码统一 123456

端点清单 (期望判定):
  ① GET  /api/order/detail?orderId=A1   防护正常(校验归属)          → 🟢
  ② GET  /api/profile/detail?userId=1   水平越权(只校验登录)         → 🔴
  ③ GET  /api/config/list               未授权(不校验登录)           → 🔴 noauth
  ④ GET  /api/dict/city                 公共接口(本来无需登录)        → ⚪
  ⑤ GET  /api/notice/list               防护正常+时间戳响应(考验降噪) → 🟢
  ⑥ POST /api/order/delete              删除语义(应被跳过)           → ⏭️
  ⑦ POST /api/user/info {userId}        POST水平越权                 → 🔴
  ⑧ GET  /api/admin/stats               垂直越权(只校验登录不校验角色) → 🔴 (admin录制+alice凭证cross)
  ⑨ GET  /api/admin/audit               垂直防护正常(校验admin角色)   → 🟢
用法: python mock_lab.py [端口, 默认9900]
"""
import json
import re
import sys
import time
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9900

# ---------- 数据 ----------
USERS = {
    "alice": {"id": 1, "name": "爱丽丝", "phone": "13800001111", "idcard": "330102199001011234", "role": "user", "pwd": "123456"},
    "bob":   {"id": 2, "name": "鲍勃",   "phone": "13900002222", "idcard": "330102199202022345", "role": "user", "pwd": "123456"},
    "admin": {"id": 99, "name": "管理员", "phone": "13700003333", "idcard": "330102198505053456", "role": "admin", "pwd": "123456"},
}
ORDERS = {  # orderId → 归属userId
    "A1": {"owner": 1, "title": "alice的订单-按摩椅", "amount": 899.00},
    "A2": {"owner": 1, "title": "alice的订单-台灯", "amount": 129.00},
    "B1": {"owner": 2, "title": "bob的订单-机械键盘", "amount": 459.00},
    "B2": {"owner": 2, "title": "bob的订单-显示器", "amount": 1899.00},
}
SESSIONS = {}  # token → username


def now_user(handler):
    """从Cookie取当前登录用户, 未登录返回None"""
    m = re.search(r"session=([a-f0-9]+)", handler.headers.get("Cookie", "") or "")
    if not m:
        return None
    return SESSIONS.get(m.group(1))


def require_user(handler):
    u = now_user(handler)
    if not u:
        return None, (401, {"code": 401, "msg": "未登录"})
    return u, None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # 静默访问日志

    # ---- 基础工具 ----
    def _send(self, status, obj, setcookie=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if setcookie:
            self.send_header("Set-Cookie", setcookie)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            try:
                from urllib.parse import parse_qs
                q = parse_qs(raw.decode("utf-8"))
                return {k: v[0] for k, v in q.items()}
            except Exception:
                return {}

    # ---- 页面 ----
    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/v4/models":
            # 假LLM模型列表(OpenAI兼容) — 回归测试拉取模型用
            return self._send(200, {"data": [{"id": "glm-4-flash"}, {"id": "glm-4-plus"},
                                             {"id": "mock-model"}]})
        if p.path in ("/", "/login"):
            return self._html(LOGIN_PAGE)
        if p.path == "/home":
            u = now_user(self)
            if not u:
                return self._send(401, {"code": 401, "msg": "未登录"})
            return self._html(HOME_PAGE % USERS[u]["name"])
        if p.path == "/api/order/detail":
            u, err = require_user(self)
            if err:
                return self._send(*err)
            oid = (parse_qs(p.query).get("orderId") or [""])[0]
            o = ORDERS.get(oid)
            if not o:
                return self._send(200, {"code": 1, "msg": "订单不存在", "data": None})
            if o["owner"] != USERS[u]["id"]:  # ① 校验归属 → 防护正常
                return self._send(200, {"code": 403, "msg": "无权查看他人订单", "data": None})
            return self._send(200, {"code": 0, "msg": "ok", "data": {"orderId": oid, **o, "ownerName": USERS[u]["name"]}})
        if p.path == "/api/profile/detail":  # ② 水平越权: 只校验登录, 不校验userId归属
            u, err = require_user(self)
            if err:
                return self._send(*err)
            uid = int((parse_qs(p.query).get("userId") or ["0"])[0])
            target = next((v for v in USERS.values() if v["id"] == uid), None)
            if not target:
                return self._send(200, {"code": 1, "msg": "用户不存在", "data": None})
            return self._send(200, {"code": 0, "msg": "ok", "data": {
                "userId": target["id"], "name": target["name"], "phone": target["phone"], "idcard": target["idcard"]}})
        if p.path == "/api/config/list":  # ③ 未授权: 不校验登录
            return self._send(200, {"code": 0, "msg": "ok", "data": {
                "db_host": "192.168.1.100", "db_user": "root", "backup_dir": "/data/backup", "env": "prod"}})
        if p.path == "/api/dict/city":  # ④ 公共接口
            return self._send(200, {"code": 0, "msg": "ok", "data": [{"id": 1, "name": "杭州"}, {"id": 2, "name": "宁波"}]})
        if p.path == "/api/notice/list":  # ⑤ 防护正常 + 时间戳噪声
            u, err = require_user(self)
            if err:
                return self._send(*err)
            return self._send(200, {"code": 0, "msg": "ok", "data": [
                {"id": 1, "title": "系统维护通知", "ts": int(time.time() * 1000)},
                {"id": 2, "title": "版本更新公告", "ts": int(time.time() * 1000)}]})
        if p.path == "/api/admin/stats":  # ⑧ 垂直越权: 只校验登录不校验角色
            u, err = require_user(self)
            if err:
                return self._send(*err)
            return self._send(200, {"code": 0, "msg": "ok", "data": {
                "total_users": 3, "total_orders": 4, "revenue": 3386.0, "admin_only_secret": "KPI-2026-Q3"}})
        if p.path == "/api/admin/audit":  # ⑨ 垂直防护: 校验admin角色
            u, err = require_user(self)
            if err:
                return self._send(*err)
            if USERS[u]["role"] != "admin":
                return self._send(200, {"code": 403, "msg": "需要管理员权限", "data": None})
            return self._send(200, {"code": 0, "msg": "ok", "data": {"logs": 1024, "risk_events": 3}})
        return self._send(404, {"code": 404, "msg": "not found"})

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/v4/chat/completions":
            # 假LLM(OpenAI兼容): 回归测试AI筛查链路用 — noauth类判误报, 其余判confirmed
            n = int(self.headers.get("Content-Length") or 0)
            try:
                prompt = json.dumps(json.loads(self.rfile.read(n) or b"{}"), ensure_ascii=False)
            except Exception:
                prompt = ""
            if "不带任何登录凭证" in prompt or "去凭证" in prompt:
                v = {"verdict": "false_positive", "reason": "mock: 公开数据非漏洞", "severity": "low"}
            elif "param_swap" in prompt or "ID交叉" in prompt:
                v = {"verdict": "confirmed", "reason": "mock: A凭证+Bid=B数据实锤", "severity": "high"}
            else:
                v = {"verdict": "confirmed", "reason": "mock: 返回他人敏感数据", "severity": "high"}
            out = {"choices": [{"message": {"content": json.dumps(v, ensure_ascii=False)}}]}
            return self._send(200, out)
        if p.path == "/api/login":
            b = self._body()
            name, pwd = str(b.get("username", "")), str(b.get("password", ""))
            u = USERS.get(name)
            if not u or u["pwd"] != pwd:
                return self._send(200, {"code": 1, "msg": "用户名或密码错误"})
            tok = secrets.token_hex(16)
            SESSIONS[tok] = name
            return self._send(200, {"code": 0, "msg": "ok", "data": {"username": name, "role": u["role"]}},
                              setcookie=f"session={tok}; Path=/")
        if p.path == "/api/order/delete":  # ⑥ 删除语义 → 工具应跳过
            u, err = require_user(self)
            if err:
                return self._send(*err)
            return self._send(200, {"code": 0, "msg": "ok", "data": {"deleted": True}})
        if p.path == "/api/user/info":  # ⑦ POST水平越权
            u, err = require_user(self)
            if err:
                return self._send(*err)
            b = self._body()
            uid = int(str(b.get("userId", 0)))
            target = next((v for v in USERS.values() if v["id"] == uid), None)
            if not target:
                return self._send(200, {"code": 1, "msg": "用户不存在", "data": None})
            return self._send(200, {"code": 0, "msg": "ok", "data": {
                "userId": target["id"], "name": target["name"], "phone": target["phone"]}})
        return self._send(404, {"code": 404, "msg": "not found"})


LOGIN_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>登录</title>
<style>body{font-family:sans-serif;background:#f5f6fa;display:flex;justify-content:center;padding-top:80px}
.box{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:300px}
input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box}button{width:100%;padding:10px;background:#409eff;color:#fff;border:0;border-radius:4px;cursor:pointer}
p.tip{color:#888;font-size:12px}</style></head><body><div class="box"><h3>业务系统登录</h3>
<form onsubmit="login(event)"><input id="u" placeholder="用户名"><input id="p" type="password" placeholder="密码"><button>登录</button></form>
<p class="tip">alice / bob / admin,密码均为 123456</p><p id="msg" style="color:red"></p></div>
<script>async function login(e){e.preventDefault();
const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({username:u.value,password:p.value})});
const j=await r.json();if(j.code===0){location='/home'}else{msg.textContent=j.msg}}</script></body></html>"""

HOME_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>工作台</title>
<style>body{font-family:sans-serif;background:#f5f6fa;margin:0;padding:20px}
h3{color:#333}a{display:inline-block;margin:6px;padding:10px 16px;background:#409eff;color:#fff;border-radius:4px;text-decoration:none;font-size:14px}
</style></head><body><h3>欢迎, %s (把下面每个功能点都点一遍)</h3>
<a href="/api/order/detail?orderId=A1">我的订单A1</a>
<a href="/api/order/detail?orderId=B1">订单B1(他人)</a>
<a href="/api/profile/detail?userId=1">用户详情1</a>
<a href="/api/profile/detail?userId=2">用户详情2</a>
<a href="/api/user/info" onclick="ui(event)">POST用户信息1</a>
<a href="/api/config/list">系统配置</a>
<a href="/api/dict/city">城市字典</a>
<a href="/api/notice/list">公告列表</a>
<a href="/api/order/delete" onclick="del(event)">删除订单</a>
<a href="/api/admin/stats">管理统计</a>
<a href="/api/admin/audit">审计日志</a>
<div id="out" style="margin-top:16px;background:#fff;padding:12px;border-radius:6px;min-height:60px;white-space:pre-wrap;font-size:13px"></div>
<script>async function ui(e){e.preventDefault();
const r=await fetch('/api/user/info',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userId:1})});
out.textContent='POST /api/user/info → '+JSON.stringify(await r.json())}
async function del(e){e.preventDefault();
const r=await fetch('/api/order/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderId:'A1'})});
out.textContent='POST /api/order/delete → '+JSON.stringify(await r.json())}</script></body></html>"""


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[mock_lab] 验收靶场已启动: http://127.0.0.1:{PORT}/  (alice/bob/admin, 密码123456)")
    print("[mock_lab] 登录后访问 /home 逐个点击功能点即可录制流量")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
