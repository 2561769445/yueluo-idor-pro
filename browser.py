#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""browser.py — Chrome/Edge 探测启动 + 精确进程管理
铁律: 停止只用精确PID taskkill, 绝不按进程名通配杀 (防误杀用户其他浏览器)"""
import os
import socket
import subprocess
import time
import urllib.request

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
]


def _from_registry(exe_name):
    """注册表 App Paths 探测 (自定义安装位置也能找到)"""
    try:
        import winreg
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for view in (winreg.KEY_READ, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
                         winreg.KEY_READ | winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(hive,
                                        rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}",
                                        0, view) as k:
                        v, _ = winreg.QueryValueEx(k, None)
                        if v and os.path.isfile(v):
                            return v
                except OSError:
                    continue
    except Exception:
        pass
    return None


def find_browser():
    """按优先级探测浏览器: 常见路径 → 注册表 → PATH。
    Chrome优先, Edge兜底(Win10/11自带, Chromium内核完全支持CDP)"""
    for p in CHROME_CANDIDATES:
        if p and os.path.isfile(p):
            return p
    for exe in ("chrome.exe", "msedge.exe"):
        p = _from_registry(exe)
        if p:
            return p
    try:
        import shutil
        for exe in ("chrome", "chrome.exe", "msedge", "msedge.exe"):
            p = shutil.which(exe)
            if p and os.path.isfile(p):
                return p
    except Exception:
        pass
    return None


def port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def find_free_port(start=9222, used=()):
    """从start起找未被占用且不在used里的端口"""
    port = start
    while True:
        if port not in used and not port_in_use(port):
            return port
        port += 1


def cdp_alive(port):
    """CDP调试端口是否已就绪"""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1) as r:
            return r.status == 200
    except Exception:
        return False


def launch(account_key, start_url, workdir, port, idx=0):
    """启动一个独立profile的浏览器实例, 返回 dict(browser, port, pid, profile)
    idx: 窗口序号(级联位置错开, 便于区分)"""
    browser = find_browser()
    if not browser:
        raise RuntimeError("未找到 Chrome/Edge, 请安装 Google Chrome 后重试")
    profile = os.path.join(workdir, "profiles", account_key)
    os.makedirs(profile, exist_ok=True)
    cmd = [
        browser,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile}",
        "--remote-allow-origins=*",   # 新版Chrome要求: 允许本地ws客户端连接CDP
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-session-crashed-bubble",
        "--disable-background-timer-throttling",
        f"--window-position={30 + idx * 70},{30 + idx * 70}",   # 级联排列便于区分
    ]
    if os.environ.get("IDOR_HEADLESS"):   # 自动化验收用: 无头模式
        cmd += ["--headless=new", "--disable-gpu", "--window-size=1280,900"]
    cmd += ["--new-window", start_url or "about:blank"]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    # 等CDP就绪 (最多15秒)
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError(f"浏览器进程启动即退出 (code={proc.returncode}), 端口或profile可能被占用")
        if cdp_alive(port):
            break
        time.sleep(0.25)
    else:
        kill_pid(proc.pid)
        raise RuntimeError("浏览器已启动但CDP调试端口15秒内未就绪")
    return {"browser": browser, "port": port, "pid": proc.pid, "profile": profile}


def kill_pid(pid):
    """精确杀单个进程树 (绝不使用进程名通配)"""
    if not pid:
        return
    try:
        subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"],
                       capture_output=True, timeout=10)
    except Exception:
        pass
