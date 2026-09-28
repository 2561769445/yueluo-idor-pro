#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recorder.py — CDP流量录制引擎
每个账号一条线程: browser-level WebSocket + Target.setAutoAttach(flatten) 自动附加所有tab,
每tab Network.enable, 捕获 requestWillBeSent / ExtraInfo(完整Cookie) / responseReceived / getResponseBody。
只保留 Document/XHR/Fetch 类型, 过滤静态资源与浏览器自身请求。"""
import base64
import hashlib
import json
import re
import threading
import time
import urllib.request

import websocket  # websocket-client

# 静态资源后缀黑名单 (双重过滤: ResourceType + 后缀)
STATIC_EXT = re.compile(
    r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|map|mp4|webm|webp|avif|mp3|wav|flv|swf|jar|apk)"
    r"([?#]|$)", re.I)
# 浏览器/系统自身请求域名黑名单
BROWSER_NOISE = re.compile(
    r"(chrome-extension://|chrome-error://|gstatic\.com|googleapis\.com|google\.com|edgedl\.me\.gvt1\.com"
    r"|msedge\.net|bing\.com|microsoftonline\.com|windows\.com|gov\.cn/captcha|schema\.org|w3\.org)", re.I)
# 保留的ResourceType
KEEP_TYPES = {"Document", "XHR", "Fetch"}
MAX_BODY = 256 * 1024          # 响应体最大捕获
MAX_RECORDS = 5000             # 每账号录制上限
DROP_AFTER_S = 60              # 未完成请求保留时长


def _ws_url(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=3) as r:
        return json.loads(r.read()).get("webSocketDebuggerUrl")


class Recorder(threading.Thread):
    """单账号CDP录制器。用法:
       rec = Recorder(port=9222, account="账号a"); rec.start(); ... ; rec.stop()"""

    def __init__(self, port, account, log_fn=None):
        super().__init__(daemon=True)
        self.port = port
        self.account = account
        self.log = log_fn or (lambda m: None)
        self._stop = threading.Event()
        self._lock = threading.RLock()   # 可重入: commit路径会在持锁状态下再进锁
        self._ws = None
        self._msgid = 0
        self._pending = {}          # msgid -> reqkey (getResponseBody回调)
        self._raw = {}              # (sessionId, requestId) -> entry
        self._captures = {}         # dedup_key -> entry (最终录制的请求)
        self._sessions = {}         # sessionId -> targetInfo (autoAttach的所有target)
        self._eval_waiters = {}     # msgid -> {"event":Event, "result":dict} (eval_on_page回调)
        self._targets = {}          # targetId -> targetInfo (setDiscoverTargets维护)
        self._attach_targets = {}   # msgid -> targetId (显式attachToTarget映射)
        self._rid_map = {}          # (sid,rid) -> dedup_key (孤儿extra回补用)
        self.ready = threading.Event()   # 第一个page session登记后置位
        self.error = None           # 启动/运行错误(中文, 供UI显示)

    # ---------- 对外 ----------
    def stop(self):
        self._stop.set()

    def count(self):
        with self._lock:
            return len(self._captures)

    def snapshot(self):
        """返回录制请求列表 (拷贝)"""
        with self._lock:
            return [dict(v) for v in self._captures.values()]

    def alive(self):
        return not self._stop.is_set() and self.error is None

    def eval_on_page(self, js, timeout=10):
        """在第一个真实页面上执行JS, 返回值(returnByValue)。失败返回None"""
        sid = None
        try:
            with self._lock:
                for s, ti in self._sessions.items():
                    if ti.get("type") == "page" and not (ti.get("url") or "").startswith(("devtools", "chrome")):
                        sid = s
                        break
                if sid is None:
                    self.log(f"[recorder:{self.account}] eval失败: 无page session "
                             f"(sessions={[(t.get('type'), (t.get('url') or '')[:40]) for t in self._sessions.values()]})")
                    return None
            ev = threading.Event()
            box = {"event": ev, "result": None}
            with self._lock:
                self._msgid += 1
                mid = self._msgid
                self._eval_waiters[mid] = box
                payload = {"id": mid, "method": "Runtime.evaluate", "sessionId": sid,
                           "params": {"expression": js, "awaitPromise": True,
                                      "returnByValue": True}}
                self._ws.send(json.dumps(payload))
            if not ev.wait(timeout):
                self._eval_waiters.pop(mid, None)
                self.log(f"[recorder:{self.account}] eval超时({timeout}s)")
                return None
            r = (box["result"] or {})
            if r.get("exceptionDetails"):
                self.log(f"[recorder:{self.account}] eval页面异常: "
                         f"{str(r['exceptionDetails'].get('exception', {}).get('description', ''))[:120]}")
                return None
            rv = (r.get("result") or {})
            if "value" in rv:
                return rv["value"]
            self.log(f"[recorder:{self.account}] eval无value: {str(rv)[:120]}")
            return None
        except Exception as e:
            self.log(f"[recorder:{self.account}] eval异常: {e}")
            return None

    def get_cookies(self, timeout=8):
        """主动拉取浏览器当前全部Cookie → "k=v; k2=v2" (同步RPC, 不依赖extraInfo时序)"""
        sid = None
        with self._lock:
            for s, ti in self._sessions.items():
                if ti.get("type") == "page":
                    sid = s
                    break
        if not sid:
            return ""
        ev = threading.Event()
        box = {"event": ev, "result": None}
        with self._lock:
            self._msgid += 1
            mid = self._msgid
            self._eval_waiters[mid] = box
            try:
                self._ws.send(json.dumps({"id": mid, "method": "Network.getCookies",
                                          "sessionId": sid, "params": {}}))
            except Exception:
                self._eval_waiters.pop(mid, None)
                return ""
        if not ev.wait(timeout):
            self._eval_waiters.pop(mid, None)
            return ""
        cookies = (box["result"] or {}).get("cookies") or []
        return "; ".join(f"{c.get('name')}={c.get('value')}" for c in cookies if c.get("name"))

    def page_url(self):
        with self._lock:
            for s, ti in self._sessions.items():
                if ti.get("type") == "page":
                    return ti.get("url", "")
        return ""

    def navigate_to(self, url, timeout=10):
        """Page.navigate导航第一个page — fire-and-forget(不依赖响应循环, 发送成功即True)"""
        sid = None
        with self._lock:
            for s, ti in self._sessions.items():
                if ti.get("type") == "page" and not ti.get("url", "").startswith(("devtools", "chrome")):
                    sid = s
                    break
        if not sid:
            with self._lock:
                snap = [(t.get("type"), (t.get("url") or "")[:50]) for t in self._sessions.values()]
            self.log(f"[recorder:{self.account}] nav失败: 无page session, 当前sessions={snap}")
            return False
        try:
            with self._lock:
                self._msgid += 1
                mid = self._msgid
                self._ws.send(json.dumps({"id": mid, "method": "Page.navigate",
                                          "sessionId": sid, "params": {"url": url}}))
            return True
        except Exception as e:
            self.log(f"[recorder:{self.account}] nav发送失败: {e}")
            return False

    # ---------- 内部工具 ----------
    def _send(self, method, params=None, session_id=None, tag=None):
        with self._lock:
            self._msgid += 1
            mid = self._msgid
            if tag:
                self._pending[mid] = tag
            msg = {"id": mid, "method": method, "params": params or {}}
            if session_id:
                msg["sessionId"] = session_id
            try:
                self._ws.send(json.dumps(msg))
            except Exception:
                pass
        return mid

    @staticmethod
    def _dedup_key(method, url, post):
        h = hashlib.md5((post or "").encode("utf-8", "replace")).hexdigest()[:10]
        return f"{method} {url} :: {h}"

    # ---------- 主循环 ----------
    def run(self):
        try:
            ws_url = _ws_url(self.port)
        except Exception as e:
            self.error = f"无法连接CDP端口{self.port}: {e}"
            return
        try:
            # suppress_origin: 新版Chrome拒绝带Origin头的ws握手
            self._ws = websocket.create_connection(ws_url, timeout=3, suppress_origin=True)
        except Exception as e:
            self.error = f"CDP WebSocket连接失败: {e}"
            return
        # 三重保险附加机制:
        # 1) autoAttach 捕获后续新tab
        self._send("Target.setAutoAttach", {
            "autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True})
        # 2) target发现事件: 维护targetId→url (供选择page/更新session url)
        self._send("Target.setDiscoverTargets", {"discover": True})
        # 3) 显式attach当前已存在的page targets (headless早期时序下autoAttach可能漏掉)
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/json/list", timeout=3) as r:
                for t in json.loads(r.read()):
                    if t.get("type") == "page":
                        self._targets[t["id"]] = {"targetId": t["id"], "type": "page", "url": t.get("url", "")}
                        mid = self._send("Target.attachToTarget", {"targetId": t["id"], "flatten": True})
                        with self._lock:
                            self._attach_targets[mid] = t["id"]
        except Exception as e:
            self.log(f"[recorder:{self.account}] 显式attach失败: {e}")
        last_clean = time.time()
        while not self._stop.is_set():
            try:
                self._ws.settimeout(1.0)
                raw = self._ws.recv()
            except websocket.WebSocketTimeoutException:
                if time.time() - last_clean > 10:
                    self._gc()
                    last_clean = time.time()
                continue
            except Exception:
                if not self._stop.is_set():
                    self.error = "CDP连接断开 (浏览器被关闭?)"
                break
            try:
                self._handle(json.loads(raw))
            except Exception:
                continue
        try:
            self._ws.close()
        except Exception:
            pass

    def _handle(self, msg):
        sid = msg.get("sessionId", "")
        # 命令响应 (getResponseBody / Runtime.evaluate / attachToTarget)
        if "id" in msg and "method" not in msg:
            mid = msg.get("id")
            key = self._pending.pop(mid, None)
            if key:
                res = msg.get("result") or {}
                body, b64 = res.get("body"), res.get("base64Encoded", False)
                if body is not None:
                    if b64:
                        try:
                            body = base64.b64decode(body).decode("utf-8", "replace")
                        except Exception:
                            body = None
                    self._set_body(key, body)
                return
            box = self._eval_waiters.pop(mid, None)
            if box:
                box["result"] = msg.get("result") or {}
                box["event"].set()
                return
            # attachToTarget响应: result里带sessionId (事件可能不来, 响应必须登记)
            res = msg.get("result") or {}
            if "sessionId" in res:
                new_sid = res["sessionId"]
                with self._lock:
                    tid = self._attach_targets.pop(mid, "")
                    ti = dict(self._targets.get(tid, {"type": "page", "url": ""}))
                    ti.setdefault("type", "page")
                    self._sessions[new_sid] = ti
                self.log(f"[recorder:{self.account}] 已附加target: {ti.get('url','')[:60]}")
                if ti.get("type") == "page":
                    self.ready.set()
                    self._send("Network.enable", session_id=new_sid)
                    self._send("Network.setCacheDisabled", {"cacheDisabled": True}, session_id=new_sid)
            return
        m, p = msg.get("method", ""), msg.get("params") or {}
        if m in ("Target.targetCreated", "Target.targetInfoChanged"):
            ti = p.get("targetInfo") or {}
            with self._lock:
                self._targets[ti.get("targetId", "")] = ti
                for s, info in self._sessions.items():
                    if info.get("targetId") == ti.get("targetId"):
                        self._sessions[s] = ti
            return
        if m == "Target.attachedToTarget":
            # 事件的新session在params.sessionId (顶层sessionId是路由字段, 此处为空)
            sid = p.get("sessionId", sid)
            ti = p.get("targetInfo") or {}
            with self._lock:
                self._sessions[sid] = ti
            if ti.get("type") == "page":
                self.ready.set()
                self._send("Network.enable", session_id=sid)
                self._send("Network.setCacheDisabled", {"cacheDisabled": True}, session_id=sid)
            return
        if m == "Target.detachedFromTarget":
            with self._lock:
                self._sessions.pop(p.get("sessionId", ""), None)
            return
        if not m.startswith("Network."):
            return
        rid = p.get("requestId")
        if rid is None:
            return
        rkey = (sid, rid)

        if m == "Network.requestWillBeSent":
            self._on_sent(rkey, p)
        elif m == "Network.requestWillBeSentExtraInfo":
            self._on_extra(rkey, p)
        elif m == "Network.responseReceived":
            self._on_resp(rkey, p)
        elif m in ("Network.loadingFinished", "Network.loadingFailed"):
            self._on_loaded(rkey, m, p)

    # ---------- 事件 ----------
    def _on_sent(self, rkey, p):
        req = p.get("request") or {}
        url, method = req.get("url", ""), req.get("method", "GET")
        rtype = p.get("type", "")
        if not url.startswith(("http://", "https://")):
            return
        if rtype and rtype not in KEEP_TYPES:
            return
        if STATIC_EXT.search(url) or BROWSER_NOISE.search(url):
            return
        if url.startswith("ws://") or url.startswith("wss://"):
            return
        initiator = p.get("initiator") or {}
        entry = {
            "account": self.account,
            "method": method,
            "url": url,
            "headers": dict(req.get("headers") or {}),
            "extra_headers": {},          # ExtraInfo headers (含完整Cookie) 延迟合并
            "post_data": req.get("postData"),
            "resource_type": rtype or "XHR",
            "document_url": p.get("documentURL", ""),
            "initiator": str(initiator.get("type", "")),
            "ts": p.get("timestamp", time.time()),
            "resp_status": None, "resp_headers": {}, "resp_body": None,
            "loaded": False, "body_failed": False,
        }
        entry["_rkey"] = rkey            # commit时建rid索引(孤儿extra回补)
        with self._lock:
            # ExtraInfo可能先于Sent到达(占位_extra_only) — 保留先到的headers(含Cookie)
            old = self._raw.get(rkey)
            if old is not None and old.get("extra_headers"):
                entry["extra_headers"] = dict(old["extra_headers"])
            self._raw[rkey] = entry
            self._try_commit(rkey)

    def _on_extra(self, rkey, p):
        hdrs = p.get("headers") or {}
        import sys as _s
        has_ck = "cookie" in json.dumps(hdrs).lower()
        with self._lock:
            e = self._raw.get(rkey)
            if e is None and has_ck:
                dk = self._rid_map.get(rkey)
                print(f"[dbg-orphan] {self.account} rid={rkey[1][:10]} ck=True "
                      f"in_raw=False ridmap={'HIT:'+str(dk)[:40] if dk else 'MISS'} "
                      f"in_caps={dk in self._captures if dk else '-'}", file=_s.stderr, flush=True)
            if e is not None:
                # ExtraInfo可能先于sent到达 — 先暂存, commit时合并
                e["extra_headers"].update(hdrs)
                self._try_commit(rkey)
                return
            # 孤儿extra: 请求已完成pop(响应极快时extraInfo晚到) — 回补进已入池条目
            # (键只用rid: 双session下同一请求rid相同但sid不同, (sid,rid)会查不到)
            dk = self._rid_map.get(rkey[1])
            if dk and dk in self._captures:
                ent = self._captures[dk]
                for k, v in hdrs.items():
                    if not k.startswith(":"):
                        ent["headers"][k] = v
                return
            # sent未到: 建占位, 只存extra
            self._raw[rkey] = {
                "account": self.account, "method": "", "url": "",
                "headers": {}, "extra_headers": dict(hdrs),
                "post_data": None, "resource_type": "", "document_url": "",
                "initiator": "", "ts": time.time(),
                "resp_status": None, "resp_headers": {}, "resp_body": None,
                "loaded": False, "body_failed": False, "_extra_only": True,
            }

    def _on_resp(self, rkey, p):
        with self._lock:
            e = self._raw.get(rkey)
            if e is None:
                return
            resp = p.get("response") or {}
            e["resp_status"] = resp.get("status")
            e["resp_headers"] = dict(resp.get("headers") or {})

    def _on_loaded(self, rkey, mname, p):
        with self._lock:
            e = self._raw.get(rkey)
            if e is None:
                return
            e["loaded"] = True
            if mname == "Network.loadingFailed":
                e["body_failed"] = True
                self._commit(e)
                self._raw.pop(rkey, None)
                return
            # loadingFinished → 异步拉响应体 (只有小body才拉)
            cl = e["resp_headers"].get("Content-Length") or e["resp_headers"].get("content-length")
            try:
                if cl is not None and int(cl) > MAX_BODY:
                    e["body_failed"] = True
                else:
                    self._send("Network.getResponseBody", {"requestId": rkey[1]},
                               session_id=rkey[0], tag=rkey)
                    return  # body回来后再commit
            except Exception:
                pass
            self._commit(e)
            self._raw.pop(rkey, None)

    def _set_body(self, rkey, body):
        with self._lock:
            e = self._raw.get(rkey)
            if e is None:
                return
            e["resp_body"] = body[:MAX_BODY] if body else body
            self._commit(e)
            self._raw.pop(rkey, None)

    # ---------- 合并/入库 ----------
    def _try_commit(self, rkey):
        """sent与extra都到了(或extra缺席) → 合并headers入录制池"""
        e = self._raw.get(rkey)
        if e is None or e.get("_extra_only"):
            return
        if e["url"] == "":
            return
        self._commit(e)

    def _commit(self, e):
        """合并headers写入去重池"""
        if not e.get("url"):            # 纯extra占位(sent被过滤/丢失)不入池
            return
        # ExtraInfo的headers更完整(含Cookie/UA真实值), 覆盖sent的; sent独有头补充
        merged = dict(e["headers"])
        for k, v in (e.get("extra_headers") or {}).items():
            if not k.startswith(":"):        # 去掉伪头
                merged[k] = v
        # 小写归一化查cookie
        low = {k.lower(): v for k, v in merged.items()}
        if "cookie" not in low:
            # ExtraInfo还没到就结束了 — 用sent自带(可能缺Cookie), 标记
            e["cookie_missing"] = True
        e["headers"] = merged
        e.pop("extra_headers", None)
        e.pop("_extra_only", None)
        key = self._dedup_key(e["method"], e["url"], e.get("post_data"))
        with self._lock:
            # rid索引: 孤儿extra回补用 (键=rid, 双session同请求rid相同)
            rk = e.pop("_rkey", None)
            if rk:
                if len(self._rid_map) > MAX_RECORDS:
                    self._rid_map.clear()
                self._rid_map[rk[1]] = key
            old = self._captures.get(key)
            if old is None and len(self._captures) >= MAX_RECORDS:
                return
            self._captures[key] = e

    def _gc(self):
        """清理长期未完成的请求条目"""
        cut = time.time() - DROP_AFTER_S
        with self._lock:
            for rkey in [k for k, v in self._raw.items() if v.get("ts", 0) < cut]:
                e = self._raw.pop(rkey)
                if e.get("url"):
                    self._commit(e)
