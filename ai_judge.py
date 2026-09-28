#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ai_judge.py — AI语义判定 (升级二: 误报自动清零)
对 high/mid 疑似项逐条组装上下文 → OpenAI兼容chat接口 → 返回 confirmed/false_positive/manual
支持智谱GLM/OpenAI/任何 /chat/completions 兼容端点。temperature=0 保证稳定。"""
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import requests

PROMPT = """你是资深越权漏洞判定专家(渗透测试背景)。根据以下自动化越权测试数据, 判定该发现是真实漏洞还是误报。

## 背景
- 测试账号角色: {roles}
- 测试类型: {mode_desc}
- 自动判定: {category} ({level})

## 数据
- 接口: {method} {url}
- 录制账号「{owner}」正常访问的响应(HTTP {orig_status}):
{orig_body}

- 越权测试的响应(HTTP {replay_status}) {replay_note}:
{replay_body}

## 判定要求
- confirmed: 响应确实返回了不属于当前凭证身份的数据/未授权可访问 → 真实漏洞
- false_positive: 响应实际为空数据/错误页/模板页/公开数据/与身份匹配的正常数据 → 误报
- manual: 数据不足以判断(如加密体/响应未捕获/需特定状态) → 需人工
注意: code!=0或data为空通常是正常拒绝; 公开字典/配置类无敏感数据不算漏洞; 时间戳差异不是漏洞。

仅输出一行JSON(不要多余文字):
{{"verdict": "confirmed|false_positive|manual", "reason": "一句话中文理由", "severity": "high|medium|low"}}"""

MODE_DESC = {
    "cross": "凭证替换重放(用其他账号的Cookie/Token访问原账号的请求)",
    "noauth": "去凭证重放(不带任何登录凭证直接访问)",
    "param_swap": "ID交叉重放(用A的凭证+把ID参数替换为B的值)",
    "bypass": "防护绕过尝试(XFF伪造/方法翻转)",
}


class AIJudge:
    """用法: j = AIJudge(cfg dict, log); j.start(results, on_update)  # 后台线程"""

    def __init__(self, cfg, log=print):
        self.base = (cfg.get("base_url") or "").rstrip("/")
        self.key = cfg.get("api_key") or ""
        self.model = cfg.get("model") or "glm-4-flash"
        self.log = log
        self.running = False
        self.stop_flag = threading.Event()
        self.done = self.total = 0

    def configured(self):
        return bool(self.base and self.key)

    # ---------- 单条判定 ----------
    def _chat(self, prompt, timeout=60):
        r = requests.post(
            f"{self.base}/chat/completions",
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json"},
            json={"model": self.model, "temperature": 0.1, "max_tokens": 300,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=timeout, verify=False,
            proxies={"http": None, "https": None})
        r.raise_for_status()
        return (r.json()["choices"][0]["message"]["content"] or "").strip()

    @staticmethod
    def _parse(txt):
        m = json.loads(txt[txt.find("{"):txt.rfind("}") + 1])
        v = m.get("verdict", "manual")
        if v not in ("confirmed", "false_positive", "manual"):
            v = "manual"
        return {"verdict": v, "reason": str(m.get("reason", ""))[:200],
                "severity": m.get("severity", "medium")}

    def judge_one(self, r, roles=""):
        body = PROMPT.format(
            roles=roles or "未标注",
            mode_desc=MODE_DESC.get(r.get("mode"), r.get("mode", "?")),
            category=r.get("category", ""), level=r.get("level", ""),
            method=r.get("method", ""), url=r.get("url", ""),
            owner=r.get("owner", ""),
            orig_status=(r.get("orig") or {}).get("status", "?"),
            orig_body=((r.get("orig") or {}).get("body") or "(未捕获)")[:900],
            replay_status=(r.get("replay") or {}).get("status", "?"),
            replay_note=f"(凭证={r.get('cross_account') or '无'})",
            replay_body=((r.get("replay") or {}).get("body") or "(未捕获)")[:900])
        txt = self._chat(body)
        try:
            return self._parse(txt)
        except Exception:
            # 重试一次(模型偶尔输出多余文字)
            try:
                return self._parse(self._chat(body + "\n再次提醒: 只输出一行JSON。"))
            except Exception:
                return {"verdict": "manual", "reason": "AI输出解析失败", "severity": "medium"}

    # ---------- 批量 ----------
    def start(self, results, on_update=None, roles=""):
        """后台批量判定 results(list, 将就地写 ai_verdict/ai_reason) + on_update(每条回调)"""
        if self.running:
            return False
        if not self.configured():
            return False
        self.running = True
        self.stop_flag.clear()
        items = [r for r in results if r.get("level") in ("high", "mid")
                 and not r.get("ai_verdict")]
        self.total, self.done = len(items), 0

        def worker():
            def one(r):
                if self.stop_flag.is_set():
                    return
                try:
                    v = self.judge_one(r, roles)
                    r["ai_verdict"] = v["verdict"]
                    r["ai_reason"] = v["reason"]
                    r["ai_severity"] = v["severity"]
                    self.done += 1
                    if on_update:
                        on_update(r)
                except Exception as e:
                    # 单条失败不拖垮整批
                    try:
                        r["ai_verdict"] = "manual"
                        r["ai_reason"] = f"AI处理异常: {str(e)[:100]}"
                        self.done += 1
                        if on_update:
                            on_update(r)
                    except Exception:
                        pass
            try:
                with ThreadPoolExecutor(max_workers=3) as ex:
                    list(ex.map(one, items))
                self.log(f"[ai] AI筛查完成: {self.done}/{self.total} 条")
            except Exception as e:
                self.log(f"[ai] AI筛查异常终止: {e} (已完成{self.done}/{self.total})")
            finally:
                self.running = False

        threading.Thread(target=worker, daemon=True).start()
        return True
