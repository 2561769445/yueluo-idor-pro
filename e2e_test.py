#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""e2e_test.py — 端到端自动验收: mock靶场 + 工具全流程(headless)
流程: 起mock_lab → 起idor_pro → 添加3账号 → start(3个headless Chrome, 欢迎页自动跳转) →
通过工具内部_drive驱动登录+遍历功能点(与录制同一CDP连接) → test → 轮询完成 → 核对判定矩阵"""
import json
import os
import subprocess
import sys
import time
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MOCK_PORT = 9900
TOOL_PORT = 8777
ACCTS = ["alice", "bob", "admin"]

NAV_URL = "http://127.0.0.1:%d/" % MOCK_PORT

LOGIN_JS = """(async()=>{
  const r=await fetch('/api/login',{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'%s',password:'123456'})});
  return (await r.text()).slice(0,60);
})()"""

FUNCS_JS = """(async () => {
  const f = (u, o) => fetch(u, Object.assign({credentials:'same-origin'}, o||{}));
  await f('/api/order/detail?orderId=A1');
  await f('/api/order/detail?orderId=B1');
  await f('/api/profile/detail?userId=1');
  await f('/api/profile/detail?userId=2');
  await f('/api/user/info', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({userId:1})});
  await f('/api/config/list');
  await f('/api/dict/city');
  await f('/api/notice/list');
  await f('/api/order/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({orderId:'A1'})});
  await f('/api/admin/stats');
  await f('/api/admin/audit');
  return 'OK';
})()"""


def http(method, url, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def wait_url(url, timeout=25):
    for _ in range(timeout * 4):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(0.25)
    return False


def drive(name, js):
    r = http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/_drive", {"name": name, "js": js}, timeout=90)
    return r.get("data")


def nav(name, url):
    r = http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/_drive", {"name": name, "nav": url}, timeout=60)
    return r.get("ok"), r.get("msg")


def kill_stale():
    """清理残留的旧工具进程(按命令行精确匹配, 避免误杀)"""
    out = subprocess.run(["wmic", "process", "where", "name='python.exe'",
                          "get", "ProcessId,CommandLine", "/format:csv"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "idor_pro.py" in line or "mock_lab.py" in line:
            pid = line.rstrip().split(",")[-1]
            if pid.isdigit():
                subprocess.run(["taskkill", "/PID", pid, "/F", "/T"], capture_output=True)
                print(f"  清理残留进程 {pid}")


def main():
    kill_stale()
    time.sleep(1)
    # 1) mock靶场
    p_mock = subprocess.Popen([sys.executable, os.path.join(BASE, "mock_lab.py")],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_url(f"http://127.0.0.1:{MOCK_PORT}/api/dict/city"), "mock_lab启动失败"
    print(f"[1] mock靶场就绪 :{MOCK_PORT}")
    # 2) 工具(headless模式)
    env = dict(os.environ, IDR_HEADLESS="1", PYTHONIOENCODING="utf-8")
    p_tool = subprocess.Popen([sys.executable, os.path.join(BASE, "idor_pro.py")],
                              env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_url(f"http://127.0.0.1:{TOOL_PORT}/api/state"), "idor_pro启动失败"
    print(f"[2] 工具就绪 :{TOOL_PORT}")
    try:
        # 3) 清默认账号 + 添加3账号
        st = http("GET", f"http://127.0.0.1:{TOOL_PORT}/api/state")
        for a in st["accounts"]:
            http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/account", {"op": "del", "name": a["name"]})
        for i, name in enumerate(ACCTS):
            http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/account", {"op": "add"})
            http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/account",
                 {"op": "upd", "idx": i, "key": "name", "value": name})
            http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/account",
                 {"op": "upd", "idx": i, "key": "start_url", "value": f"http://127.0.0.1:{MOCK_PORT}/"})
        print("[3] 3账号已配置(alice/bob/admin)")
        # 4) 开启测试
        r = http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/start", {})
        assert r["ok"], f"start失败: {r}"
        print("[4] 会话已开启, 等浏览器+录制就绪...")
        for _ in range(80):
            st = http("GET", f"http://127.0.0.1:{TOOL_PORT}/api/state")
            if st["accounts"] and all(a["recording"] for a in st["accounts"]):
                break
            time.sleep(0.5)
        else:
            raise AssertionError("录制器未就绪: " + json.dumps(st["accounts"], ensure_ascii=False))
        print(f"[5] 3个浏览器就绪: {[(a['name'], a['port']) for a in st['accounts']]}")
        # 欢迎页不自动跳转(人工点击), e2e模拟点击: 导航到靶场
        print("[5.5] 等待page就绪并驱动各窗口进入靶场...")
        for name in ACCTS:
            w = http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/_drive",
                     {"name": name, "wait": 15}, timeout=30)
            print(f"  [{name}] page就绪: {w.get('ok')} {w.get('msg','')}")
            ok, msg = nav(name, NAV_URL)
            print(f"  [{name}] 导航: ok={ok} {msg}")
        time.sleep(3)
        # 5) 驱动登录+遍历(通过工具内部连接)
        for name in ACCTS:
            lr = drive(name, LOGIN_JS % name)
            print(f"  [{name}] 登录: {lr}")
            assert lr and '"code":0' in lr.replace(" ", ""), f"{name} 登录失败"
        for name in ACCTS:
            fr = drive(name, FUNCS_JS)
            print(f"  [{name}] 功能遍历: {fr}")
            assert fr == "OK", f"{name} 遍历失败"
        print("[6] 功能遍历完成, 等录制落池...")
        last = -1
        for _ in range(30):
            time.sleep(1.2)
            st = http("GET", f"http://127.0.0.1:{TOOL_PORT}/api/state")
            total = sum(a["captured"] for a in st["accounts"])
            if total == last and total >= 20:
                break
            last = total
        caps = {a["name"]: a["captured"] for a in st["accounts"]}
        print(f"[7] 录制合计 {sum(caps.values())} 条 {caps}")
        assert sum(caps.values()) >= 20, "录制数量不足, recorder可能有问题"
        # 6) 开始越权测试
        r = http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/test",
                 {"skip_delete": True, "include_noauth": True, "concurrency": 4})
        assert r["ok"], f"test失败: {r}"
        print("[8] 越权测试启动...")
        for _ in range(300):
            time.sleep(1)
            st = http("GET", f"http://127.0.0.1:{TOOL_PORT}/api/state")
            if not st["testing"]:
                break
        print(f"[9] 测试完成: {st['done']}/{st['total']} → {len(st['results'])}条结果")
        return st
    finally:
        pass


if __name__ == "__main__":
    try:
        st = main()
    finally:
        try:
            http("POST", f"http://127.0.0.1:{TOOL_PORT}/api/stop_all", {})
        except Exception:
            pass
    # 判定核对
    results = st["results"]
    from collections import Counter
    cnt = Counter(r["level"] for r in results)
    print("\n===== 判定分布 =====")
    for k, v in cnt.items():
        print(f"  {k}: {v}")
    print("\n===== 高危明细 =====")
    for r in results:
        if r["level"] == "high":
            print(f"  [{r['id']}] {r['mode']} {r['owner']}→{r['cross_account'] or '裸'} {r['method']} {r['url'][:70]}")
            print(f"       {r['evidence'][:110]}")
    print("\n===== 中危明细 =====")
    for r in results:
        if r["level"] == "mid":
            print(f"  [{r['id']}] {r['mode']} {r['owner']}→{r['cross_account'] or '裸'} {r['method']} {r['url'][:66]} | {r['category']}")
    print("\n===== 跳过明细 =====")
    for r in results:
        if r["level"] == "skip":
            print(f"  [{r['id']}] {r['owner']} {r['method']} {r['url'][:70]}")
    highs = [r for r in results if r["level"] == "high"]
    VULN_URLS = ("/api/profile/detail", "/api/user/info", "/api/config/list")  # mock设计的真漏洞接口②⑦③
    fp = [r for r in highs if not any(u in r["url"] for u in VULN_URLS)]
    checks = [
        ("②水平越权检出(profile/detail高危)", any("/api/profile/detail" in r["url"] for r in highs)),
        ("⑥删除接口全部跳过", any(r["level"] == "skip" and "delete" in r["url"] for r in results)
         and not any("delete" in r["url"] and r["mode"] != "skip" for r in results)),
        ("⑧管理接口mid告警", any(r["level"] == "mid" and "管理类" in r.get("category", "") for r in results)),
        ("③未授权检出(config/list)", any("config/list" in r["url"] for r in highs)),
        ("①订单归属防护正常(ok)", any(r["level"] == "ok" and "order/detail" in r["url"] for r in results)),
        ("⑤公共接口降噪(public)", any(r["level"] == "public" for r in results)),
        ("无高危误报(高危仅②⑦③接口)", len(fp) == 0),
    ]
    print("\n===== 验收断言 =====")
    allpass = True
    for name, ok in checks:
        print(f"  {'✅' if ok else '❌'} {name}")
        allpass = allpass and ok
    print(f"\n{'🏆 全部通过' if allpass else '💥 存在失败项'} (共{len(results)}条结果)")
    sys.exit(0 if allpass else 1)
