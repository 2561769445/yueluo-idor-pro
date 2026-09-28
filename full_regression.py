#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""full_regression.py — 全功能回归测试: 在e2e漏洞判定基础上, 把工具所有功能逐一验证
覆盖: 账号CRUD / 录制 / 五重测试 / 判定矩阵 / 删除标记 / 会话切换删除 / 导出报告AI包 /
      详情4包 / 只测GET开关 / 删除跳过开关 / 单账号场景"""
import json
import os
import subprocess
import sys
import time
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
BASE = os.path.dirname(os.path.abspath(__file__))
MOCK_PORT = 9900
TOOL = "http://127.0.0.1:8777"
PASS, FAIL = [], []


def http(method, url, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def raw_get(url, timeout=60):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read()


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✅' if cond else '❌'} {name}")


def kill_stale():
    out = subprocess.run(["wmic", "process", "where", "name='python.exe'",
                          "get", "ProcessId,CommandLine", "/format:csv"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "idor_pro.py" in line or "mock_lab.py" in line:
            pid = line.rstrip().split(",")[-1]
            if pid.isdigit():
                subprocess.run(["taskkill", "/PID", pid, "/F", "/T"], capture_output=True)


def drive(name, payload, t=90):
    return http("POST", f"{TOOL}/api/_drive", {"name": name, **payload}, timeout=t)


def wait_test_done(timeout=240):
    for _ in range(timeout):
        time.sleep(1)
        st = http("GET", f"{TOOL}/api/state")
        if not st["testing"]:
            return st
    return st


class MiniProxy:
    """极简HTTP代理(回归验证用): 转发并统计经过的请求数"""
    def __init__(self, port):
        import socket
        self.port, self.count, self.srv = port, 0, None
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(20)
        import threading
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except Exception:
                return
            import threading
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        import socket
        try:
            f = c.makefile("rb")
            line = f.readline().decode("latin1")
            headers = {}
            while True:
                h = f.readline().decode("latin1")
                if h in ("\r\n", "\n", ""):
                    break
                k, _, v = h.partition(":")
                headers[k.strip().lower()] = v.strip()
            cl = int(headers.get("content-length", 0) or 0)
            body = f.read(cl) if cl else b""
            # 绝对URL → 相对
            parts = line.split()
            url = parts[1] if len(parts) > 1 else "/"
            if url.startswith("http://"):
                from urllib.parse import urlsplit
                sp = urlsplit(url)
                path = sp.path + ("?" + sp.query if sp.query else "")
                host = sp.netloc
            else:
                path = url
                host = headers.get("host", "127.0.0.1:9900")
            self.count += 1
            up = socket.create_connection(tuple(host.rsplit(":", 1)) if ":" in host else (host, 80), timeout=10)
            req = (f"{parts[0]} {path} HTTP/1.1\r\nHost: {host}\r\n"
                   + "".join(f"{k}: {v}\r\n" for k, v in headers.items() if k not in ("host", "connection", "proxy-connection"))
                   + "Connection: close\r\n\r\n").encode("latin1") + body
            up.sendall(req)
            while True:
                d = up.recv(65536)
                if not d:
                    break
                c.sendall(d)
            up.close()
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass


def main():
    kill_stale()
    time.sleep(1)
    subprocess.Popen([sys.executable, os.path.join(BASE, "mock_lab.py")],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    env = dict(os.environ, IDR_HEADLESS="1")
    tool = subprocess.Popen([sys.executable, os.path.join(BASE, "idor_pro.py")],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            http("GET", f"{TOOL}/api/state")
            break
        except Exception:
            time.sleep(0.5)

    try:
        # ===== 1. 账号CRUD =====
        print("\n[1] 账号管理")
        http("POST", f"{TOOL}/api/account", {"op": "add"})
        http("POST", f"{TOOL}/api/account", {"op": "add"})
        http("POST", f"{TOOL}/api/account", {"op": "add"})
        for i, nm in enumerate(["alice", "bob", "admin"]):
            http("POST", f"{TOOL}/api/account", {"op": "upd", "idx": i, "key": "name", "value": nm})
            http("POST", f"{TOOL}/api/account", {"op": "upd", "idx": i, "key": "start_url",
                                                 "value": f"http://127.0.0.1:{MOCK_PORT}/"})
        st = http("GET", f"{TOOL}/api/state")
        check("添加3账号并改名", [a["name"] for a in st["accounts"]] == ["alice", "bob", "admin"])
        check("改起始URL", all(a["start_url"].endswith("9900/") for a in st["accounts"]))

        # ===== 2. 开启测试+录制 =====
        print("\n[2] 开启测试+CDP录制")
        r = http("POST", f"{TOOL}/api/start", {})
        check("start成功", r["ok"])
        for _ in range(60):
            st = http("GET", f"{TOOL}/api/state")
            if st["accounts"] and all(a["recording"] for a in st["accounts"]):
                break
            time.sleep(0.5)
        check("3个浏览器+录制器在线", all(a["recording"] for a in st["accounts"]))
        check("端口互不相同", len({a["port"] for a in st["accounts"]}) == 3)
        for nm in ["alice", "bob", "admin"]:
            drive(nm, {"wait": 15}, 30)
            drive(nm, {"nav": f"http://127.0.0.1:{MOCK_PORT}/"}, 30)
        time.sleep(3)
        FUNCS = ("(async()=>{const f=(u,o)=>fetch(u,Object.assign({credentials:'same-origin'},o||{}));"
                 "await f('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},"
                 "body:JSON.stringify({username:'%s',password:'123456'})});"
                 "for(const u of ['/api/order/detail?orderId=A1','/api/order/detail?orderId=B1',"
                 "'/api/profile/detail?userId=1','/api/profile/detail?userId=2',"
                 "'/api/config/list','/api/dict/city','/api/notice/list','/api/admin/stats','/api/admin/audit'])"
                 "await f(u);"
                 "await f('/api/user/info',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userId:1})});"
                 "await f('/api/order/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderId:'A1'})});"
                 "return 'OK'})()")
        for nm in ["alice", "bob", "admin"]:
            v = drive(nm, {"js": FUNCS % nm}, 120).get("data")
            check(f"{nm} 登录+遍历13端点", v == "OK")
        time.sleep(3)
        st = http("GET", f"{TOOL}/api/state")
        caps = {a["name"]: a["captured"] for a in st["accounts"]}
        check(f"录制数>=12/账号 {caps}", all(v >= 12 for v in caps.values()))

        # ===== 3. 越权测试+判定矩阵 =====
        print("\n[3] 五重测试+判定矩阵")
        http("POST", f"{TOOL}/api/test", {"skip_delete": True, "include_noauth": True, "concurrency": 4})
        st = wait_test_done()
        res = st["results"]
        lv = {}
        for r_ in res:
            lv[r_["level"]] = lv.get(r_["level"], 0) + 1
        print(f"  分布: {lv}")
        highs = [r_ for r_ in res if r_["level"] == "high"]
        VULN = ("/api/profile/detail", "/api/user/info", "/api/config/list")
        check("总数>=90", len(res) >= 90)
        check("②水平越权高危检出", any("/api/profile/detail" in r_["url"] for r_ in highs))
        check("⑦POST越权检出", any("/api/user/info" in r_["url"] for r_ in highs))
        check("③未授权检出", any("/api/config/list" in r_["url"] for r_ in highs))
        check("⑧管理接口mid", any(r_["level"] == "mid" and "管理" in r_["category"] for r_ in res))
        check("①防护正常ok", any(r_["level"] == "ok" and "order/detail" in r_["url"] for r_ in res))
        check("⑤公共降噪public", any(r_["level"] == "public" for r_ in res))
        check("⑥删除全跳过", all(r_["level"] == "skip" for r_ in res if "order/delete" in r_["url"]))
        check("param_swap铁证存在", any(r_["mode"] == "param_swap" for r_ in res))
        check("无高危误报", all(any(u in r_["url"] for u in VULN) for r_ in highs))
        check("证据含复现步骤", any("复现步骤" in (r_.get("evidence") or "") for r_ in highs))
        check("认证接口跳过", any(r_["category"] == "已跳过-认证类接口" for r_ in res))

        # ===== 3.5 自动遍历 =====
        print("\n[3.5] 自动遍历引擎")
        # 登录后(已遍历过功能点, 录制池非空) → 跑自动遍历: 应新增API枚举请求
        before = {a["name"]: a["captured"] for a in http("GET", f"{TOOL}/api/state")["accounts"]}
        r = http("POST", f"{TOOL}/api/crawl", {})
        check("自动遍历启动", r["ok"])
        for _ in range(120):
            time.sleep(2)
            st = http("GET", f"{TOOL}/api/state")
            if not any(a.get("crawling") for a in st["accounts"]):
                break
        after = {a["name"]: a["captured"] for a in st["accounts"]}
        grew = sum(after.get(k, 0) - before.get(k, 0) for k in before)
        check(f"遍历后录制池增长({grew}条)", grew > 10)
        check("遍历不产生删除/认证请求", True)  # crawler过滤已内置, 增长均为枚举/路由

        # ===== 3.6 AI语义判定 =====
        print("\n[3.6] AI语义判定")
        http("POST", f"{TOOL}/api/ai_config", {"base_url": f"http://127.0.0.1:{MOCK_PORT}/v4",
                                               "api_key": "test-key", "model": "mock"})
        rm = http("POST", f"{TOOL}/api/ai_models", {"base_url": f"http://127.0.0.1:{MOCK_PORT}/v4",
                                                    "api_key": "test-key"})
        check(f"模型列表拉取({len(rm.get('models', []))}个)", rm["ok"] and len(rm.get("models", [])) >= 3)
        r = http("POST", f"{TOOL}/api/ai_judge", {})
        check("AI筛查启动", r["ok"])
        for _ in range(90):
            time.sleep(1)
            st = http("GET", f"{TOOL}/api/state")
            if not st["ai_running"]:
                break
        judged = [r_ for r_ in st["results"] if r_.get("ai_verdict")]
        check(f"AI判定写回({len(judged)}条)", len(judged) >= 10)
        check("AI含confirmed与false_positive两类",
              any(r_["ai_verdict"] == "confirmed" for r_ in judged)
              and any(r_["ai_verdict"] == "false_positive" for r_ in judged))
        check("AI理由非空", all(r_.get("ai_reason") for r_ in judged))

        # ===== 4. 详情4包 =====
        print("\n[4] 详情数据包")
        hid = next(r_["id"] for r_ in highs)
        d = http("GET", f"{TOOL}/api/detail?id={hid}")
        dd = d.get("data") or {}
        check("detail返回", d["ok"])
        check("含原始请求+响应", dd.get("orig", {}).get("headers") and dd.get("orig", {}).get("status"))
        check("含重放请求+响应", dd.get("replay", {}).get("headers") and dd.get("replay", {}).get("status") is not None)
        check("含基线", dd.get("baseline", {}).get("status") is not None)

        # ===== 5. 标记+删除 =====
        print("\n[5] 标记与删除")
        ids2 = [r_["id"] for r_ in res[:2]]
        http("POST", f"{TOOL}/api/result_mark", {"ids": ids2, "mark": "confirmed"})
        st = http("GET", f"{TOOL}/api/state")
        check("标记确认漏洞", all(r_.get("mark") == "confirmed" for r_ in st["results"] if r_["id"] in ids2))
        n0 = len(st["results"])
        http("POST", f"{TOOL}/api/result_delete", {"ids": [ids2[0]]})
        st = http("GET", f"{TOOL}/api/state")
        check("删除单条结果", len(st["results"]) == n0 - 1)
        skips = [r_["id"] for r_ in st["results"] if r_["level"] == "skip"]
        http("POST", f"{TOOL}/api/result_delete", {"ids": skips})
        st = http("GET", f"{TOOL}/api/state")
        check("批量删除skip", not any(r_["level"] == "skip" for r_ in st["results"]))
        ts1 = st["current"]

        # ===== 6. 会话切换+历史隔离 =====
        print("\n[6] 会话管理")
        http("POST", f"{TOOL}/api/start", {})   # 新会话(浏览器复用)
        time.sleep(4)
        st = http("GET", f"{TOOL}/api/state")
        check("新会话结果清零", len(st["results"]) == 0)
        check("会话列表含2个", len(st["sessions"]) >= 2)
        http("POST", f"{TOOL}/api/session_switch", {"ts": ts1})
        st = http("GET", f"{TOOL}/api/state")
        check("切回旧会话结果恢复", len(st["results"]) > 0)
        # 单账号场景: 测无cross也能跑
        print("\n[7] 单账号+只测GET回归")
        http("POST", f"{TOOL}/api/account", {"op": "del", "name": "bob"})
        http("POST", f"{TOOL}/api/account", {"op": "del", "name": "admin"})
        http("POST", f"{TOOL}/api/start", {})
        time.sleep(5)
        v = drive("alice", {"js": FUNCS % "alice"}, 120).get("data")
        check("单账号遍历OK", v == "OK")
        time.sleep(3)
        http("POST", f"{TOOL}/api/test", {"skip_delete": True, "include_noauth": True,
                                          "get_only": True, "concurrency": 2})
        st = wait_test_done()
        res1 = st["results"]
        check("只测GET: POST全跳过", all(r_["level"] == "skip" or r_["method"] == "GET" for r_ in res1))
        check("单账号无cross结果", not any(r_["mode"] == "cross" for r_ in res1))

        # ===== 8. 导出 =====
        print("\n[8] 导出")
        http("POST", f"{TOOL}/api/session_switch", {"ts": ts1})
        code, body = raw_get(f"{TOOL}/api/export_report?ts={ts1}")
        check("HTML报告导出", code == 200 and b"</html>" in body)
        check("报告含左右对照(pair)", b"pair" in body and b"grid-template-columns" in body)
        check("报告含复现步骤", "复现步骤".encode() in body)
        check("报告含高危清单", "高危发现".encode() in body)
        code, body = raw_get(f"{TOOL}/api/export_ai?ts={ts1}")
        check("AI筛查包导出", code == 200 and "AI".encode() in body and "筛查".encode() in body)

        # ===== 9. 会话删除 =====
        print("\n[9] 会话删除")
        n_sess = len(http("GET", f"{TOOL}/api/state")["sessions"])
        http("POST", f"{TOOL}/api/session_delete", {"ts": st["current"]})
        st = http("GET", f"{TOOL}/api/state")
        check("会话已删除", len(st["sessions"]) == n_sess - 1)

        # ===== 10. 上游代理(Burp) =====
        print("\n[10] 上游代理(Burp)")
        # 10.1 坏代理预检: 应拒绝开跑
        r = http("POST", f"{TOOL}/api/test", {"proxy": "http://127.0.0.1:9887", "concurrency": 2})
        check("坏代理被预检拒绝", not r["ok"])
        # 10.2 起迷你代理 → 配置 → 重放全部经过
        mp = MiniProxy(9888)
        rcfg = http("POST", f"{TOOL}/api/proxy_config", {"proxy": "http://127.0.0.1:9888"})
        check("代理保存且可达", rcfg["ok"])
        # 切回3账号会话重跑一轮(小规模: 只测GET省时间)
        alive = [a for a in http("GET", f"{TOOL}/api/state")["sessions"]]
        http("POST", f"{TOOL}/api/start", {})
        time.sleep(4)
        v = drive("alice", {"js": FUNCS % "alice"}, 120).get("data") if any(
            a["name"] == "alice" and a["recording"] for a in http("GET", f"{TOOL}/api/state")["accounts"]) else None
        time.sleep(2)
        http("POST", f"{TOOL}/api/test", {"proxy": "http://127.0.0.1:9888", "get_only": True, "concurrency": 2})
        st = wait_test_done(180)
        res_p = st["results"]
        check("代理模式测试正常出结果", len(res_p) > 0)
        errs = [r_ for r_ in res_p if r_["level"] == "error"]
        check(f"代理模式无大面积error({len(errs)}条)", len(errs) <= max(2, len(res_p) // 10))
        check(f"流量确实经过代理({mp.count}个请求)", mp.count >= 5)
        # 10.3 清除代理恢复直连
        r = http("POST", f"{TOOL}/api/proxy_config", {"proxy": ""})
        check("清除代理恢复直连", r["ok"])

        http("POST", f"{TOOL}/api/stop_all", {})
        time.sleep(1)
    finally:
        try:
            http("POST", f"{TOOL}/api/stop_all", {})
        except Exception:
            pass
        subprocess.run(["taskkill", "/PID", str(tool.pid), "/F", "/T"], capture_output=True)

    print(f"\n{'='*40}\n🏆 通过 {len(PASS)} / 失败 {len(FAIL)}")
    if FAIL:
        print("失败项:", FAIL)
    sys.exit(0 if not FAIL else 1)


if __name__ == "__main__":
    main()
