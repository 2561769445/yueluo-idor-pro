#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""replayer.py — 越权重放 + 判定引擎
三重测试: baseline(原样) / cross(换其他账号凭证) / noauth(去凭证)
判定分级: high(疑似越权/未授权) mid(需人工) ok(防护正常) public(公共接口)
          waf(被拦截) skip(已跳过-删除) base_reject(基线被拒) error(重放失败)
经验降噪: JSON归一化忽略时间戳字段 / 公共接口识别 / 管理路径启发式 / 敏感字段提取"""
import difflib
import json
import random
import re
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- 正则配置 ----------
DELETE_RE = re.compile(r"(delete|remove|destroy|\bdel\b|\bdrop\b|\bclear\b)", re.I)
CRED_HDR_RE = re.compile(r"(token|auth|sign|ticket|session|jwt|secret|csrf)", re.I)
CRED_PARAM_RE = re.compile(r"(token|auth|sign|ticket|session|jwt|secret|csrf|password)", re.I)
# 认证类端点: 本来就无鉴权且body是用户名密码, 测它=纯噪声, 直接跳过
AUTH_PATH_RE = re.compile(
    r"(login|logout|signin|sign-in|signup|register|captcha|verif|sms|sendcode|sso|oauth"
    r"|/token|/jwt|password|resetpwd|forget|kaptcha|vcode|getcode|登录|注册|验证码|登出)", re.I)
# 身份ID参数: public+敏感+带身份ID = 对ID无归属校验 → 高危而非公共
ID_PARAM_RE = re.compile(
    r"(user|uid|\bid\b|userid|order|account|member|emp|staff|student|patient|owner|cust|person|车牌|工号|卡号)", re.I)
HOP_HEADERS = {"host", "content-length", "connection", "accept-encoding", "keep-alive",
               "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer"}
NOISE_KEY_RE = re.compile(
    r"(timestamp|_?ts$|nonce|req_?id|request_?id|trace_?id|serial|signature|uuid|gmt"
    r"|create_?time|update_?time|_?time$|_?date$|expire)", re.I)
SENS_FIELD_RE = re.compile(
    r"(phone|mobile|idcard|id_?card|identity|身份证|手机|password|passwd|pwd|email|邮箱"
    r"|balance|amount|salary|工资|address|住址|bank|银行卡"
    r"|db_|jdbc|datasource|redis|mysql|secret|access_?key|私钥|口令)", re.I)
ADMIN_PATH_RE = re.compile(r"(admin|manage|system|internal|audit|console|backstage|priv|后台|管理)", re.I)
WAF_BODY_RE = re.compile(
    r"(拦截|intercept|blocked|attack|waf|防火墙|非法请求|访问被拒|请勿|雷池|safeline"
    r"|aliyun.*waf|腾讯云.*waf|云盾|forbidden request|security check)", re.I)
LOGIN_LOC_RE = re.compile(r"(login|signin|sign-in|sso|cas|oauth|auth|登录|passport)", re.I)
CODE_KEYS = ("code", "status", "errcode", "errorCode", "error_code", "ret", "resultCode", "resultCode".lower())
DATA_KEYS = ("data", "result", "rows", "list", "records", "content", "items", "payload")

LEVEL_NAME = {"high": "🔴高危", "mid": "🟡中危", "ok": "🟢正常", "public": "⚪公共",
              "waf": "🚫WAF", "skip": "⏭️跳过", "base_reject": "⚠️基线被拒", "error": "❌失败"}


# ---------- 工具函数 ----------
def try_json(s):
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def norm_obj(o):
    """递归去掉噪声键(时间戳/流水号/sign), 用于响应等价比较"""
    if isinstance(o, dict):
        return {k: norm_obj(v) for k, v in sorted(o.items()) if not NOISE_KEY_RE.search(str(k))}
    if isinstance(o, list):
        return [norm_obj(x) for x in o]
    return o


def parse_biz(body):
    """解析业务结构 → (code, has_data, is_json)。code=None表示无code字段默认成功"""
    j = try_json(body)
    if not isinstance(j, dict):
        return (None, False, isinstance(j, (list, str, int)))
    code = None
    for k in CODE_KEYS:
        if k in j:
            code = j[k]
            break
    data = None
    for k in DATA_KEYS:
        if isinstance(j.get(k), (dict, list)):
            data = j[k]
            break
    has = bool(data) or (data is None and bool({k: v for k, v in j.items()
                                                 if k not in CODE_KEYS and k not in ("msg", "message")}))
    return (code, has, True)


def biz_success(code):
    if code is None:
        return True
    return code in (0, "0", 200, "200", "success", "ok", True, "true", "0000")


def equivalent(a, b):
    """响应体等价判定(JSON归一化/文本直比)"""
    ja, jb = try_json(a), try_json(b)
    if isinstance(ja, dict) and isinstance(jb, dict):
        return norm_obj(ja) == norm_obj(jb)
    if ja is None and jb is None:
        ta, tb = (a or "").strip(), (b or "").strip()
        if ta == tb:
            return True
        return difflib.SequenceMatcher(None, ta[:2000], tb[:2000]).ratio() > 0.9
    return False


def similarity(a, b):
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, (a or "")[:2000], (b or "")[:2000]).ratio()


def sens_hint(body):
    """响应中出现的敏感字段名(用于证据增色)"""
    j = try_json(body)
    names = set()
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if SENS_FIELD_RE.search(str(k)) and v not in (None, "", [], {}):
                    names.add(str(k))
                walk(v)
        elif isinstance(o, list):
            for x in o[:5]:
                walk(x)
    walk(j)
    if not names and isinstance(j, str):
        m = SENS_FIELD_RE.findall(j)
        names = set(m[:3])
    return sorted(names)[:4]


def is_waf(status, body, ctype):
    if status in (403, 406, 412, 418, 429, 509) and "json" not in (ctype or "").lower():
        return bool(WAF_BODY_RE.search(body or ""))
    if status == 403 and (body or "").startswith("<!"):
        return bool(WAF_BODY_RE.search(body or ""))
    return False


def cred_keys_of(headers):
    """该请求里的凭证头名字集合(保留原始大小写)"""
    out = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl == "cookie" or kl == "authorization" or CRED_HDR_RE.search(kl):
            out[kl] = v
    return out


# ---------- 重放器 ----------
class Replayer:
    """captures_by_account: {账号名: [录制请求dict...]}
       settings: {skip_delete:bool, get_only:bool, include_noauth:bool, concurrency:int, delay:float}
       on_result: 每条结果回调(result dict)
       stop_flag: threading.Event"""

    def __init__(self, captures_by_account, settings, on_result, stop_flag, log=print):
        self.caps = captures_by_account
        self.st = settings
        self.on_result = on_result
        self.stop = stop_flag
        self.log = log
        self.proxy = (self.st.get("proxy") or "").strip() or None   # 如 http://127.0.0.1:8080 (Burp)
        if self.proxy:
            self.log(f"[test] 上游代理已启用: {self.proxy} (全部重放流量将经过代理留档)")
        self._rid = 0
        self._lock = threading.Lock()

    # ---------- 凭证库 ----------
    def _build_cred_pool(self):
        """每个账号的凭证头值池: {账号: {头名小写: 最新值}}"""
        pool = {}
        for acct, lst in self.caps.items():
            p = {}
            for e in sorted(lst, key=lambda x: x.get("ts", 0)):  # 旧的→新的, 后面覆盖=最新
                for kl, v in cred_keys_of(e.get("headers") or {}).items():
                    p[kl] = v
            pool[acct] = p
        return pool

    def _public_index(self):
        """公共接口索引: (method, url, post哈希) 在≥2账号的原始录制中都2xx → public
        (请求完全相同含query → 业务上双方都可见)"""
        from collections import defaultdict
        seen = defaultdict(set)   # key -> {账号}
        for acct, lst in self.caps.items():
            for e in lst:
                if e.get("resp_status") and 200 <= e["resp_status"] < 300:
                    k = (e["method"], e["url"], (e.get("post_data") or "")[:512])
                    seen[k].add(acct)
        return {k for k, v in seen.items() if len(v) >= 2}

    # ---------- 请求构造/发送 ----------
    def _base_headers(self, entry):
        return {k: v for k, v in (entry.get("headers") or {}).items()
                if k.lower() not in HOP_HEADERS}

    def _swap_cred(self, headers, target_pool):
        """把headers中的凭证头替换为目标账号的值(没有则删除)"""
        h = dict(headers)
        for k in list(h.keys()):
            kl = k.lower()
            if kl == "cookie" or kl == "authorization" or CRED_HDR_RE.search(kl):
                del h[k]
                if target_pool.get(kl):
                    h[k] = target_pool[kl]
        return h

    def _strip_cred(self, headers):
        return {k: v for k, v in headers.items()
                if k.lower() != "cookie" and k.lower() != "authorization"
                and not CRED_HDR_RE.search(k.lower())}

    # ---------- URL/body 内的凭证参数 ----------
    def _url_param_pool(self, acct):
        """账号的URL凭证参数值池: {参数名: 最新值} (token在URL里的系统)"""
        p = {}
        for e in sorted(self.caps.get(acct, []), key=lambda x: x.get("ts", 0)):
            for k, v in parse_qsl(urlsplit(e["url"]).query, keep_blank_values=True):
                if CRED_PARAM_RE.search(k):
                    p[k] = v
        return p

    def _swap_url_cred(self, url, post, target_acct, pool):
        """cross时把URL/body里的token类参数替换为目标账号的值"""
        tp = self._url_param_pool(target_acct)
        if not tp:
            return url, post
        sp = urlsplit(url)
        q = parse_qsl(sp.query, keep_blank_values=True)
        hit = False
        for i, (k, v) in enumerate(q):
            if k in tp and tp[k] != v:
                q[i] = (k, tp[k])
                hit = True
        new_url = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q), sp.fragment)) if hit else url
        return new_url, post

    def _strip_url_cred(self, url, post):
        """noauth时去掉URL里的token类参数"""
        sp = urlsplit(url)
        q = [(k, v) for k, v in parse_qsl(sp.query, keep_blank_values=True)
             if not CRED_PARAM_RE.search(k)]
        if len(q) == len(parse_qsl(sp.query, keep_blank_values=True)):
            return url, post
        new_url = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q), sp.fragment))
        return new_url, post

    def _send(self, url, method, headers, post_data):
        """单次重放, 不跟随重定向。配置了上游代理则全量经代理(如Burp留档)。"""
        proxies = ({"http": self.proxy, "https": self.proxy} if self.proxy
                   else {"http": None, "https": None})
        try:
            r = requests.request(
                method, url, headers=headers, data=post_data,
                allow_redirects=False, timeout=20, verify=False,
                proxies=proxies)
            body = r.text if len(r.content or b"") <= 512 * 1024 else r.text[:512 * 1024]
            return {"status": r.status_code, "location": r.headers.get("Location", ""),
                    "ctype": r.headers.get("Content-Type", ""), "body": body, "err": ""}
        except requests.RequestException as e:
            return {"status": 0, "location": "", "ctype": "", "body": "", "err": f"{type(e).__name__}: {e}"[:120]}
        except Exception as e:
            return {"status": 0, "location": "", "ctype": "", "body": "", "err": f"{type(e).__name__}: {e}"[:120]}

    # ---------- 主流程 ----------
    def run(self):
        pool = self._build_cred_pool()
        public_idx = self._public_index()
        # 原始响应索引: cross响应与"凭证账号本人"的响应等价 → 按身份返回(正常)
        self._orig_idx = {}
        for acct, lst in self.caps.items():
            for e in lst:
                self._orig_idx[(acct, e["method"], e["url"])] = e.get("resp_body") or ""
        tasks = []
        # 1) 生成任务: 每账号每条录制
        for acct, lst in self.caps.items():
            for e in lst:
                tasks.append((acct, e, pool, public_idx))
        ps_tasks = self._param_swap_tasks()
        self.log(f"[test] 录制请求合计 {len(tasks)} 条, ID交叉配对 {len(ps_tasks)} 对")
        self.log(f"[test] 开始五重测试: baseline基线 + cross换凭证 + noauth去凭证 + param_swap身份ID交叉")
        conc = max(1, int(self.st.get("concurrency", 4)))
        with ThreadPoolExecutor(max_workers=conc) as ex:
            futs = [ex.submit(self._run_one, t) for t in tasks]
            futs += [ex.submit(self._run_param_swap, t, pool) for t in ps_tasks]
            for f in futs:
                try:
                    f.result()
                except Exception as exn:
                    self.log(f"[test] 任务异常: {exn}")
        self.log("[test] 测试完成")

    def _next_id(self):
        with self._lock:
            self._rid += 1
            return f"r{self._rid:04d}"

    def _emit(self, **kw):
        rec = {"id": self._next_id(), "ts": time.strftime("%H:%M:%S"), **kw}
        self.on_result(rec)

    # ---------- param_swap: ID交叉实锤 ----------
    @staticmethod
    def _path_template(path):
        """REST路径模板化: 纯数字/UUID段 → {id}, 让 /user/1/x 与 /user/2/x 配对"""
        def tpl(s):
            if re.fullmatch(r"\d+", s):
                return "{n}"
            if re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}[0-9a-fA-F]{12}", s):
                return "{uuid}"
            return s
        return "/".join(tpl(s) for s in path.split("/"))

    def _param_swap_tasks(self):
        """跨账号同端点配对: A凭证+B的ID参数值 → 拿到B的数据 = 水平越权实锤
        每账号每path保留多条候选, 找到参数值不同的组合才生成任务"""
        by_path = defaultdict(lambda: defaultdict(list))
        for acct, lst in self.caps.items():
            for e in lst:
                sp = urlsplit(e["url"])
                key = (e["method"], sp.netloc + self._path_template(sp.path))
                lst_ = by_path[key][acct]
                if len(lst_) < 8:                 # 每账号每path最多8条候选
                    lst_.append(e)
        tasks = []
        for (method, path), m in by_path.items():
            if len(m) < 2:
                continue
            for a, las in m.items():
                for b, lbs in m.items():
                    if a == b:
                        continue
                    for ea in las:
                        hit = None
                        for eb in lbs:
                            if self._swap_ids(ea, eb):
                                hit = (a, b, ea, eb)
                                break
                        if hit:
                            tasks.append(hit)     # 每账号每path只取一对
                            break
        return tasks

    @staticmethod
    def _swap_ids(ea, eb):
        """把A请求中与B同名不同值的业务ID参数换成B的值(URL query + body)。
        返回 (new_url, new_post, swapped_keys) 或 None"""
        sa, sb = urlsplit(ea["url"]), urlsplit(eb["url"])
        qa = parse_qsl(sa.query, keep_blank_values=True)
        qb = dict(parse_qsl(sb.query, keep_blank_values=True))
        swapped = []
        for i, (k, v) in enumerate(qa):
            if k in qb and qb[k] != v and not CRED_PARAM_RE.search(k):
                qa[i] = (k, qb[k])
                swapped.append(f"{k}:{v}→{qb[k]}")
        new_url = ea["url"]
        if swapped:
            new_url = urlunsplit((sa.scheme, sa.netloc, sa.path, urlencode(qa), sa.fragment))
        new_post = ea.get("post_data")
        if new_post:
            ja, jb = try_json(new_post), try_json(eb.get("post_data") or "")
            if isinstance(ja, dict) and isinstance(jb, dict):
                hit = False
                for k in list(ja.keys()):
                    if (k in jb and ja[k] != jb[k] and not CRED_PARAM_RE.search(k)
                            and isinstance(ja[k], (str, int, float))
                            and isinstance(jb[k], (str, int, float))):
                        swapped.append(f"body.{k}:{ja[k]}→{jb[k]}")
                        ja[k] = jb[k]
                        hit = True
                if hit:
                    new_post = json.dumps(ja, ensure_ascii=False)
            else:
                fa = parse_qsl(new_post, keep_blank_values=True)
                fb = dict(parse_qsl(eb.get("post_data") or "", keep_blank_values=True))
                hit = False
                for i, (k, v) in enumerate(fa):
                    if k in fb and fb[k] != v and not CRED_PARAM_RE.search(k):
                        fa[i] = (k, fb[k])
                        swapped.append(f"form.{k}:{v}→{fb[k]}")
                        hit = True
                if hit:
                    new_post = urlencode(fa)
        if not swapped:
            return None
        return (new_url, new_post, swapped)

    def _run_param_swap(self, args, pool):
        a, b, ea, eb = args
        if self.stop.is_set():
            return
        method, url = ea["method"], ea["url"]
        # 删除语义/认证类/只测GET 同样跳过
        if self.st.get("skip_delete", True) and (method.upper() == "DELETE" or DELETE_RE.search(url)):
            return   # 已在常规任务里报过skip, 不重复
        if AUTH_PATH_RE.search(urlsplit(url).path):
            return
        if self.st.get("get_only") and method.upper() not in ("GET", "HEAD"):
            return
        sw = self._swap_ids(ea, eb)
        if not sw:
            return
        new_url, new_post, keys = sw
        time.sleep(random.uniform(0.03, 0.12))
        h = self._base_headers(ea)          # A的凭证原样保留
        rp = self._send(new_url, method, h, new_post)
        bl = self._send(ea["url"], method, dict(h), ea.get("post_data"))   # A原样基线
        lvl, cat, ev = self._judge_param_swap(a, b, keys, ea, eb, rp, bl)
        self._emit(owner=a, mode="param_swap", cross_account=b, method=method, url=new_url,
                   level=lvl, category=cat, evidence=ev,
                   orig=self._pack(ea), replay=self._pack_resp(rp, h, new_post, method, new_url),
                   baseline={"status": bl["status"], "body": (bl["body"] or "")[:2048]})

    def _judge_param_swap(self, a, b, keys, ea, eb, rp, bl):
        """判定: A凭证 + B的ID → 与B原始响应等价 = 水平越权实锤"""
        s = rp["status"]
        if rp.get("err"):
            return ("error", "重放失败", f"请求异常: {rp['err']}")
        keys_s = ",".join(keys[:4])
        if s in (401, 403):
            if is_waf(s, rp["body"], rp["ctype"]):
                return ("waf", "被WAF拦截", "ID交叉重放被拦截页拦截")
            return ("ok", "防护正常", f"把ID换成{b}的值({keys_s})后被服务端拒绝({s}), 归属校验有效")
        if s in (301, 302, 303, 307, 308) and LOGIN_LOC_RE.search(rp.get("location", "")):
            return ("ok", "防护正常", "ID交叉后跳转登录")
        if not 200 <= s < 300:
            return ("mid", "异常状态码", f"ID交叉重放返回{s}, 需人工确认")
        code, has_data, is_json = parse_biz(rp["body"])
        if is_json and not biz_success(code):
            return ("ok", "防护正常(业务层)", f"ID换成{b}的值后业务code={code}, 数据级拒绝")
        if is_json and not has_data:
            return ("ok", "防护正常", f"ID换成{b}的值后返回空数据, 归属校验有效")
        b_body = eb.get("resp_body") or ""
        a_body = ea.get("resp_body") or ""
        sens = sens_hint(rp["body"])
        sens_s = f"(含敏感字段: {'/'.join(sens)})" if sens else ""
        if b_body and equivalent(rp["body"], b_body):
            return ("high", "水平越权实锤(ID交叉)",
                    f"【漏洞描述】{a}的凭证 + 把ID换成{b}的值({keys_s}) = 拿到了与{b}完全相同的数据{sens_s}。\n"
                    f"【复现步骤】1.使用账号「{a}」正常登录; 2.将请求中的ID参数({keys_s})修改为账号「{b}」的ID值; "
                    f"3.发送请求, 响应返回的是「{b}」的数据 — 越权铁证。\n"
                    f"【影响】低权限用户可按ID遍历读取任意用户数据, 建议立即修复归属校验。")
        if a_body and equivalent(rp["body"], a_body):
            return ("mid", "ID参数未生效",
                    f"ID换成{b}的值后响应仍与{a}原始一致 — 该参数可能被忽略, 需人工确认")
        if b_body and 200 <= (eb.get("resp_status") or 0) < 300:
            return ("mid", "ID交叉返回数据需确认",
                    f"{a}的凭证+{b}的ID({keys_s})拿到另一份数据{sens_s}, 无法自动等价比对, 需人工确认是否{b}的数据")
        return ("mid", "ID交叉2xx需确认", f"ID换成{b}的值后返回2xx, 需人工确认数据归属{sens_s}")

    def _run_one(self, args):
        acct, e, pool, public_idx = args
        if self.stop.is_set():
            return
        url, method = e["url"], e["method"]
        base_h = self._base_headers(e)
        post = e.get("post_data")
        orig_body = e.get("resp_body") or ""
        orig_status = e.get("resp_status") or 0
        has_cred = bool(cred_keys_of(e.get("headers") or {}))
        is_public = (method, url, (post or "")[:512]) in public_idx
        admin_url = bool(ADMIN_PATH_RE.search(url))

        # ---- 删除语义: 直接跳过 ----
        if self.st.get("skip_delete", True) and (method.upper() == "DELETE" or DELETE_RE.search(url)):
            self._emit(owner=acct, mode="skip", cross_account="", method=method, url=url,
                       level="skip", category="已跳过-删除类操作",
                       evidence="命中删除语义(方法DELETE或URL含delete/remove/del等), 按安全策略未重放",
                       orig=self._pack(e), replay=None, baseline=None)
            return
        # ---- 认证类端点: 跳过(本来就无鉴权, 测它纯噪声) ----
        if AUTH_PATH_RE.search(urlsplit(url).path):
            self._emit(owner=acct, mode="skip", cross_account="", method=method, url=url,
                       level="skip", category="已跳过-认证类接口",
                       evidence="登录/注册/验证码类接口, 不在越权测试范围",
                       orig=self._pack(e), replay=None, baseline=None)
            return
        # ---- 只测GET开关 ----
        if self.st.get("get_only") and method.upper() not in ("GET", "HEAD"):
            self._emit(owner=acct, mode="skip", cross_account="", method=method, url=url,
                       level="skip", category="已跳过-写操作(只测GET模式)",
                       evidence="当前设置为仅测试GET请求", orig=self._pack(e), replay=None, baseline=None)
            return

        time.sleep(random.uniform(0.03, 0.12) * (1 if self.st.get("delay") is None else float(self.st.get("delay", 1))))

        # ---- baseline: 原样重放 ----
        bl = self._send(url, method, dict(base_h), post)
        bl_ok = 200 <= bl["status"] < 300

        # ---- cross: 每个其他账号凭证 (仅原始请求带凭证时才有意义, 否则=原样重放纯噪声) ----
        cross_all_ok = True      # 全部cross被拒 → 深度绕过轮再验一次
        if has_cred:
            for other in [a for a in self.caps.keys() if a != acct]:
                if self.stop.is_set():
                    return
                h2 = self._swap_cred(base_h, pool.get(other, {}))
                cross_url, cross_post = self._swap_url_cred(url, post, other, pool)
                rp = self._send(cross_url, method, h2, cross_post)
                lvl, cat, ev = self._judge_cross(acct, other, e, bl, bl_ok, rp, orig_body, is_public, admin_url)
                if lvl not in ("ok", "public"):
                    cross_all_ok = False
                self._emit(owner=acct, mode="cross", cross_account=other, method=method, url=cross_url,
                           level=lvl, category=cat, evidence=ev,
                           orig=self._pack(e), replay=self._pack_resp(rp, h2, cross_post, method, cross_url),
                           baseline={"status": bl["status"], "body": (bl["body"] or "")[:2048]})
                # 深度绕过: cross被拒(看似有防护) → XFF内网伪造/方法翻转再验一次
                if lvl == "ok" and self.st.get("deep_bypass", True):
                    time.sleep(random.uniform(0.03, 0.1))
                    hx = dict(h2)
                    hx["X-Forwarded-For"] = "127.0.0.1"
                    hx["X-Real-IP"] = "127.0.0.1"
                    rpx = self._send(cross_url, method, hx, cross_post)
                    code2, has2, isj2 = parse_biz(rpx["body"])
                    if 200 <= rpx["status"] < 300 and (has2 or (isj2 and biz_success(code2))) \
                            and not equivalent(rpx["body"], rp["body"]):
                        self._emit(owner=acct, mode="bypass", cross_account=other, method=method, url=cross_url,
                                   level="high", category="防护绕过(XFF伪造内网)",
                                   evidence=f"【漏洞描述】{other}的凭证访问原本被拒({rp['status']}), 但添加内网伪造头"
                                            f"(X-Forwarded-For: 127.0.0.1)后返回了业务数据 — 服务端信任XFF头做鉴权。\n"
                                            f"【复现步骤】1.使用账号「{other}」登录; 2.在请求头加 X-Forwarded-For: 127.0.0.1 与 X-Real-IP: 127.0.0.1; "
                                            f"3.重放请求即得到数据。\n"
                                   f"【影响】任意用户伪造内网来源即可绕过访问控制。",
                                   orig=self._pack(e), replay=self._pack_resp(rpx, hx, cross_post, method, cross_url),
                                   baseline={"status": bl["status"], "body": ""})
                    # 方法翻转: GET↔POST (REST鉴权按方法分别配置, 常见GET有鉴权POST没有)
                    if self.stop.is_set():
                        return
                    alt = "POST" if method.upper() == "GET" else "GET"
                    rpm = self._send(cross_url, alt, dict(h2), cross_post)
                    codem, hasm, isjm = parse_biz(rpm["body"])
                    if 200 <= rpm["status"] < 300 and (hasm or (isjm and biz_success(codem))):
                        self._emit(owner=acct, mode="bypass", cross_account=other, method=alt, url=cross_url,
                                   level="mid", category=f"方法级鉴权差异({method}→{alt})",
                                   evidence=f"【描述】{method}请求被拒, 但改用{alt}方法请求同一URL返回了业务数据 — "
                                            f"服务端对不同HTTP方法的鉴权配置不一致, 需人工确认。\n"
                                            f"【复现】用{alt}方法重放下方请求包即可。",
                                   orig=self._pack(e), replay=self._pack_resp(rpm, h2, cross_post, alt, cross_url),
                                   baseline={"status": bl["status"], "body": ""})

        # ---- noauth: 去凭证(仅原始带凭证时才有意义) ----
        if self.st.get("include_noauth", True) and has_cred:
            h3 = self._strip_cred(base_h)
            na_url, na_post = self._strip_url_cred(url, post)
            rp = self._send(na_url, method, h3, na_post)
            lvl, cat, ev = self._judge_noauth(acct, e, rp, orig_body, is_public)
            self._emit(owner=acct, mode="noauth", cross_account="", method=method, url=na_url,
                       level=lvl, category=cat, evidence=ev,
                       orig=self._pack(e), replay=self._pack_resp(rp, h3, na_post, method, na_url),
                       baseline={"status": bl["status"], "body": (bl["body"] or "")[:2048]})
        elif not has_cred:
            # 原始请求本来就不带凭证 → 录制本身即无认证访问, 若有敏感数据给一条提示(无论是否公共)
            if orig_status and 200 <= orig_status < 300 and sens_hint(orig_body):
                self._emit(owner=acct, mode="noauth", cross_account="", method=method, url=url,
                           level="mid", category="无凭证接口返回敏感数据",
                           evidence=f"原始请求未携带任何凭证却返回数据(含敏感字段: {'/'.join(sens_hint(orig_body))}), 请确认该接口是否应公开",
                           orig=self._pack(e), replay=None, baseline=None)

    # ---------- 打包 ----------
    def _pack(self, e):
        return {"method": e.get("method"), "url": e.get("url"),
                "headers": e.get("headers") or {}, "post_data": e.get("post_data"),
                "status": e.get("resp_status"),
                "body": (e.get("resp_body") or "")[:8192]}

    @staticmethod
    def _pack_resp(rp, headers, post, method, url):
        return {"method": method, "url": url, "headers": headers, "post_data": post,
                "status": rp["status"], "location": rp.get("location", ""),
                "ctype": rp.get("ctype", ""), "body": (rp.get("body") or "")[:8192],
                "err": rp.get("err", "")}

    # ---------- 判定 ----------
    def _judge_cross(self, owner, other, e, bl, bl_ok, rp, orig_body, is_public, admin_url):
        s = rp["status"]
        if rp.get("err"):
            return ("error", "重放失败", f"请求异常: {rp['err']}")
        if s in (401, 403):
            if is_waf(s, rp["body"], rp["ctype"]):
                return ("waf", "被WAF/防护设备拦截", "403且响应含拦截页特征, 越权与否被防护设备掩盖, 建议人工换方式验证")
            return ("ok", "防护正常", f"{other}的凭证访问返回{s}, 服务端正确拒绝")
        if s in (301, 302, 303, 307, 308):
            loc = rp.get("location", "")
            if LOGIN_LOC_RE.search(loc):
                return ("ok", "防护正常", f"重定向到登录({loc[:80]}), 会话校验有效")
            return ("mid", "重定向需确认", f"30x跳转到 {loc[:80]}, 需人工确认是否登录跳转")
        if not 200 <= s < 300:
            return ("mid", "异常状态码", f"交叉重放返回状态码 {s}, 需人工确认")
        # ---- 2xx: 业务层分析 ----
        code, has_data, is_json = parse_biz(rp["body"])
        sens = sens_hint(rp["body"])
        if not bl_ok:
            # 基线都被拒 → 该接口可能有防重放, 交叉结果仅供参考
            if has_data:
                return ("base_reject", "基线被拒但交叉有数据",
                        f"原凭证重放返回{bl['status']}(疑有防重放/时效签名), 但{other}凭证却返回数据 — 值得人工深挖")
            return ("base_reject", "基线被拒", f"原凭证重放返回{bl['status']}, 疑有防重放/时效签名, 本条交叉结果仅供参考")
        if is_json and not biz_success(code):
            return ("ok", "防护正常(业务层)", f"返回2xx但业务code={code}, 属数据级拒绝")
        if is_json and not has_data:
            return ("ok", "防护正常", "返回2xx但data为空, 属数据级拒绝")
        eq = equivalent(orig_body, rp["body"])
        sens_s = f"(含敏感字段: {'/'.join(sens)})" if sens else ""
        if eq:
            if is_public:
                # 公共但带身份ID参数+敏感字段 → 接口对ID无归属校验, 是越权不是公共
                q_keys = [k for k, _ in parse_qsl(urlsplit(e["url"]).query)]
                jb = try_json(e.get("post_data") or "")
                if isinstance(jb, dict):
                    q_keys += list(jb.keys())
                has_id = any(ID_PARAM_RE.search(str(k)) for k in q_keys)
                if has_id and sens:
                    return ("high", "水平越权(对ID参数无归属校验)",
                            f"【漏洞描述】双方账号带各自ID请求均返回相同敏感数据{sens_s} — 接口不校验ID归属, "
                            f"任意登录账号可查任意ID对应的数据。\n"
                            f"【复现步骤】1.使用任一普通账号登录; 2.将请求中的ID参数替换为其他任意用户的ID(参考下方对照); "
                            f"3.响应即返回该ID对应的敏感数据。\n"
                            f"【影响】通过遍历ID可批量拉取全量用户敏感信息(手机号/身份证等), 数据泄露面极大。")
                if has_id and not sens:
                    return ("mid", "公共接口带身份ID参数",
                            "双方均可按ID取到数据(无敏感字段), 请人工确认ID归属校验是否存在")
                if admin_url:
                    return ("mid", "管理类接口普通账号可访问",
                            f"路径含管理特征且任意登录账号都能拿到相同数据{sens_s} — 疑似垂直越权, 请人工确认权限设计")
                if sens:
                    return ("mid", "公共接口但返回敏感字段",
                            f"双方账号均可访问且响应含敏感字段{sens_s}, 请确认该数据是否应对所有用户可见")
                return ("public", "公共接口", "双方账号原始请求均正常访问, 属业务公开数据")
            if sens:
                return ("high", "疑似水平越权(高危)",
                        f"【漏洞描述】{other}的凭证重放{owner}的请求, 拿到了与{owner}完全相同的数据{sens_s}。\n"
                        f"【复现步骤】1.使用账号「{other}」正常登录系统; 2.按下方「重放请求」原样发送(凭证为{other}, 请求内容为{owner}的操作); "
                        f"3.观察「重放响应」——返回了{owner}的数据即越权成立。\n"
                        f"【影响】任意登录用户可遍历查看其他用户的敏感数据, 造成横向信息泄露。")
            return ("high", "疑似越权(高危)",
                    f"【漏洞描述】{other}的凭证重放{owner}的请求, 拿到了与{owner}完全相同的数据。\n"
                    f"【复现步骤】1.使用账号「{other}」正常登录; 2.发送下方「重放请求」; 3.响应返回{owner}的原始数据即成立。\n"
                    f"【影响】越权访问他人数据/功能。")
        # 数据不等价: 与"凭证账号本人"的同URL原始响应等价 → 按身份返回, 正常
        other_orig = self._orig_idx.get((other, e.get("method"), e["url"]), "")
        if other_orig and equivalent(rp["body"], other_orig):
            return ("ok", "按凭证身份返回(正常)",
                    f"响应与{other}本人请求该接口的结果完全一致, 服务端按当前身份返回数据, 属正常行为")
        # 数据不等价
        sim = similarity(orig_body, rp["body"])
        if sim > 0.9:
            return ("mid", "响应高度相似需确认",
                    f"相似度{sim:.0%}但有差异{sens_s}, 可能是时间戳噪声或部分数据越权, 建议人工比对")
        return ("mid", "返回数据但与原始不同",
                f"{other}的凭证拿到了另一份数据(相似度{sim:.0%}){sens_s} — "
                f"可能是按当前身份返回(正常), 也可能是越权访问了他人数据, 需人工确认")

    def _judge_noauth(self, owner, e, rp, orig_body, is_public):
        s = rp["status"]
        if rp.get("err"):
            return ("error", "重放失败", f"请求异常: {rp['err']}")
        if s in (401, 403):
            if is_waf(s, rp["body"], rp["ctype"]):
                return ("waf", "被WAF拦截", "403且响应含拦截页特征")
            return ("ok", "防护正常", f"无凭证访问返回{s}, 认证有效")
        if s in (301, 302, 303, 307, 308):
            loc = rp.get("location", "")
            if LOGIN_LOC_RE.search(loc):
                return ("ok", "防护正常", f"无凭证跳转登录({loc[:80]})")
            return ("mid", "重定向需确认", f"无凭证30x到 {loc[:80]}")
        if not 200 <= s < 300:
            return ("mid", "异常状态码", f"无凭证重放返回{s}")
        code, has_data, is_json = parse_biz(rp["body"])
        sens = sens_hint(rp["body"])
        sens_s = f"(含敏感字段: {'/'.join(sens)})" if sens else ""
        if is_json and not biz_success(code):
            return ("ok", "防护正常", f"返回2xx但业务code={code}, 数据级拒绝")
        if is_json and not has_data:
            return ("ok", "防护正常", "返回2xx但data为空")
        eq = equivalent(orig_body, rp["body"])
        if has_data or eq:
            if sens:
                return ("high", "未授权访问(高危)",
                        f"【漏洞描述】去掉全部凭证(不登录)仍返回业务数据{sens_s}" +
                        ("且与登录时响应完全一致" if eq else "") + "。\n"
                        f"【复现步骤】1.退出登录(或开无痕窗口); 2.直接发送下方「重放请求」(无任何Cookie/Token); "
                        f"3.响应仍返回敏感数据即成立。\n"
                        f"【影响】未授权用户可直接获取敏感数据, 属严重访问控制缺失。")
            if is_public:
                return ("public", "公开接口(无需登录)",
                        "无需认证即可访问且无敏感数据, 属正常公开接口(字典/门户页类)")
            return ("high", "未授权访问(高危)",
                    f"【漏洞描述】去掉全部凭证仍返回业务数据" + ("且与登录时响应一致" if eq else "") + "。\n"
                    f"【复现步骤】1.不带任何凭证直接发送「重放请求」; 2.响应返回业务数据即成立。\n"
                    f"【影响】未授权访问业务数据。")
        return ("mid", "无凭证2xx需确认", "无凭证返回2xx, 内容需人工确认")
