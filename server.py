#!/usr/bin/env python3
"""可疑ID 登记处 — 输入一段字串即登记，同一 ID 被登记超过 20 次即判为「外挂」。

纯标准库，无依赖。
  GET  /              → 页面（首次访问签发身份 cookie）
  POST /api/register  → {"id": "xxx", "fp": "<浏览器指纹>"}  登记一次
  GET  /api/list      → 全部登记现状
  GET  /api/query?id= → 查单个 ID 的登记情况
数据落盘在 DATA_FILE (JSON)，重名按大小写不敏感归一。
ID 严格 7 位：^[A-Z0-9]{4}-[A-Z0-9]{3}$（如 2VDE-THE），不合规直接拒绝登记。

身份去重：服务端签发的 `sid` cookie（HMAC 签名）+ 前端算的浏览器指纹，
两者都只存加盐哈希；同一个身份对同一个 ID 只能登记一次。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import unicodedata
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.environ.get("SUSPECT_DATA", os.path.join(HERE, "data.json"))

try:                                  # 社交分享卡（1200x630），部署包里带；缺了不影响别的
    with open(os.path.join(HERE, "og.png"), "rb") as _f:
        _OG_PNG = _f.read()
except OSError:
    _OG_PNG = b""
PORT = int(os.environ.get("PORT", "8792"))
HOST = os.environ.get("HOST", "0.0.0.0")   # 前面有 nginx 反代时可设 127.0.0.1
THRESHOLD = 20          # 登记数 > 20 → 外挂
DAILY_CAP = 5           # 同一出口网络每天最多登记 5 次：防单人刷数误伤正常玩家
DAY = 86400
ID_RE = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{3}$")   # 严格 7 位：4 位字母数字 + "-" + 3 位字母数字
ID_ERR = "ID 格式不对：必须是 7 位（4 位字母/数字 + - + 3 位字母/数字，如 2VDE-THE）"

# 输入自动格式化用：各种横杠统一映射成 '-'，零宽/软连字符直接删除
_HYPHENS = dict.fromkeys(
    [0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0x2043, 0xFE63, 0xFE58, 0xFF0D], "-")
_INVISIBLE = dict.fromkeys([0x00AD, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF], None)

_lock = threading.Lock()
_state: dict = {"ids": {}, "quota": {}}   # quota: {"<UTC日>": {<出口哈希>: 已用次数}}
_QUOTA_KEEP = 8                          # 配额桶只留最近几天，data.json 不会无限涨


def load() -> None:
    global _state
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, encoding="utf-8") as fp:
                raw = json.load(fp)
            if isinstance(raw, dict) and isinstance(raw.get("ids"), dict):
                if not isinstance(raw.get("quota"), dict):
                    raw["quota"] = {}
                _state = raw
        except Exception as exc:                      # 数据坏了就重来，不让服务挂掉
            print(f"[warn] 读取 {DATA_FILE} 失败: {exc}", flush=True)


def save() -> None:
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump(_state, fp, ensure_ascii=False, indent=1)
    os.replace(tmp, DATA_FILE)


def snapshot() -> dict:
    rows = []
    for key, rec in _state["ids"].items():
        count = int(rec.get("count", 0))
        rows.append({
            "id": str(rec.get("display", key)).upper(),   # 页面统一显示全大写 ID
            "count": count,
            "cheater": count > THRESHOLD,
            "last": rec.get("last", 0),
        })
    # 外挂优先、次数多的靠前，同档次按最近登记时间倒序
    rows.sort(key=lambda r: (r["cheater"], r["count"], r["last"]), reverse=True)
    cheaters = sum(1 for r in rows if r["cheater"])
    return {
        "threshold": THRESHOLD,
        "total": len(rows),
        "cheaters": cheaters,
        "registrations": sum(r["count"] for r in rows),   # 累计登记次数
        "list": rows,
    }


def similar_ids(name: str, limit: int = 3) -> list[dict]:
    """只差 1~2 个字符的已登记 code。错一位登记，罪证就落到别人头上 —— 提前提示。

    调用方持锁。按「越像、次数越多」排前面，最多 limit 条。
    """
    out = []
    target = name.upper()
    for key, rec in _state["ids"].items():
        other = str(rec.get("display", key)).upper()
        if other == target:
            continue
        diff = sum(1 for a, b in zip(target, other) if a != b) + abs(len(target) - len(other))
        if diff <= 2:
            out.append({"id": other, "count": int(rec.get("count", 0)), "diff": diff})
    out.sort(key=lambda r: (r["diff"], -r["count"]))
    return out[:limit]


def format_id(raw: str) -> str:
    """输入自动格式化：全角→半角、各种横杠→'-'、去掉零宽字符、空白收敛、统一大写。

    例：`３QQN－０NH` → `3QQN-0NH`，`2vde–the` → `2VDE-THE`（含零宽字符也能清掉）
    """
    s = unicodedata.normalize("NFKC", str(raw))      # ３→3、Ｑ→Q、－→-
    s = s.translate(_INVISIBLE).translate(_HYPHENS)  # 零宽/软连字符删掉，横杠统一成 '-'
    return " ".join(s.split()).upper()               # 空白收敛 + 全大写


# ---------- 身份识别：服务端签发的 Cookie + 浏览器指纹（都只落加盐哈希） ----------
COOKIE = "sid"
COOKIE_AGE = 63072000                    # 2 年
SECRET_FILE = os.environ.get("SUSPECT_SECRET", os.path.join(HERE, ".secret"))


def _load_secret() -> bytes:
    """签名/加盐密钥。首次运行生成，重启后不变（否则所有人都被当成新浏览器）。"""
    try:
        with open(SECRET_FILE, "rb") as fp:
            raw = fp.read().strip()
        if len(raw) >= 32:
            return raw
    except FileNotFoundError:
        pass
    raw = secrets.token_hex(32).encode()
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fp:
        fp.write(raw)
    return raw


SECRET = _load_secret()
_SID_RE = re.compile(r"[0-9a-f]{32}")


def sign_sid(sid: str) -> str:
    mac = hmac.new(SECRET, sid.encode(), hashlib.sha256).hexdigest()[:20]
    return f"{sid}.{mac}"


def unsign_sid(value: str | None) -> str | None:
    """校验 cookie 签名；伪造/改动的值一律当成新浏览器。"""
    if not value or "." not in value:
        return None
    sid, _, mac = value.rpartition(".")
    if not _SID_RE.fullmatch(sid):
        return None
    good = hmac.new(SECRET, sid.encode(), hashlib.sha256).hexdigest()[:20]
    return sid if hmac.compare_digest(mac, good) else None


def voter(kind: str, value: str) -> str:
    """身份信号 → 不可逆短哈希，落盘不留原始 cookie / 指纹。"""
    return hmac.new(SECRET, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:16]


def identity_tokens(sid: str | None, fp: str | None) -> list[str]:
    """cookie 命中就够；cookie 被清了还有指纹兜底。"""
    toks = []
    if sid:
        toks.append(voter("c", sid))
    fp = (fp or "").strip()[:128]
    if len(fp) >= 8:                     # 太短的指纹没区分度，宁可不认
        toks.append(voter("f", fp))
    return toks


def _day_key(now: float | None = None) -> str:
    """配额按 UTC 自然日分桶。"""
    t = time.gmtime(now if now is not None else time.time())
    return time.strftime("%Y%m%d", t)


def ip_bucket(addr: str | None) -> str:
    """出口地址 → 不可逆短哈希。明文不落盘、不进日志（与 cookie/指纹同一口径）。"""
    if not addr:
        return ""
    host = addr.strip().strip("[]").split("%")[0]
    if ":" in host:                       # IPv6：前 64 位当一个出口看待
        host = ":".join(host.split(":")[:4])
    return voter("ip", host)


def check_quota(bucket: str) -> tuple[int, int]:
    """(还能登记几次, 今日已用几次)。只读，不预扣。调用方持锁。"""
    if not bucket:
        return DAILY_CAP, 0
    used = int((_state.get("quota") or {}).get(_day_key(), {}).get(bucket, 0))
    return max(0, DAILY_CAP - used), used


def take_quota(bucket: str) -> None:
    """登记成功后扣一次额度，顺手清掉旧日桶。调用方持锁。"""
    if not bucket:
        return
    today = _day_key()
    q = _state.setdefault("quota", {})
    q.setdefault(today, {})[bucket] = int(q.get(today, {}).get(bucket, 0)) + 1
    for key in sorted(k for k in q if k != today)[:-max(0, _QUOTA_KEEP - 1)]:
        q.pop(key, None)


def register(raw: str, sid: str | None = None, fp: str | None = None, ip: str | None = None):
    """登记一次。返回 (结果, 错误, 是否重复登记)。

    同一个身份（cookie 或浏览器指纹任一命中）对同一个 ID 只能登记一次。
    """
    name = format_id(raw)
    if not name:
        return None, "请输入要登记的 ID", False
    if not ID_RE.fullmatch(name):        # 严格 7 位，不合规不登记
        return None, ID_ERR, False
    key = name.lower()
    toks = identity_tokens(sid, fp)
    bucket = ip_bucket(ip)
    with _lock:
        left, _used = check_quota(bucket)
        if not left:
            # 今天的额度用完了：不新建记录也不加数。攒次数靠不同的人，不是同一个人猛点。
            return None, (f"这个网络今天登记满了（每天 {DAILY_CAP} 次），明天再来 —— "
                          "登记次数要靠不同的人攒。"), False
        rec = _state["ids"].get(key)
        now = time.time()
        if rec is None:
            rec = {"display": name, "count": 0, "first": now, "last": now, "voters": []}
            _state["ids"][key] = rec
        voters = rec.setdefault("voters", [])
        if toks and any(t in voters for t in toks):
            return None, "这个 ID 你已经登记过了", True
        rec["count"] = int(rec.get("count", 0)) + 1
        rec["last"] = now
        for t in toks:
            voters.append(t)
        take_quota(bucket)
        save()
        return {"id": rec["display"], "count": rec["count"],
                "cheater": rec["count"] > THRESHOLD}, None, False


PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WARDOGS · 可疑ID 登记处</title>
<meta name="description" content="WARDOGS 可疑ID 登记处：把对局里可疑的玩家 ID 登记下来，同一个 ID 被登记超过 20 次判定为「外挂」。">
<meta name="theme-color" content="#0b0e08">
<meta property="og:type" content="website">
<meta property="og:title" content="WARDOGS 可疑ID 登记处">
<meta property="og:description" content="名字可以顶，CODE 顶不掉。把对局里可疑玩家的 7 位 code 登记下来，同一个 code 超过 20 次自动标红。">
<meta property="og:url" content="https://fxxkwghackers.zaixia108.com/">
<meta property="og:image" content="https://fxxkwghackers.zaixia108.com/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:site_name" content="WARDOGS 可疑ID 登记处">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="https://fxxkwghackers.zaixia108.com/og.png">
<meta name="twitter:title" content="WARDOGS 可疑ID 登记处">
<meta name="twitter:description" content="名字可以顶，CODE 顶不掉。可疑玩家的 7 位 code 登记在这里，超过 20 次自动标红。">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%230b0e08'/%3E%3Cpath d='M10 6h12v12l-6 8-6-8z' fill='%23e0a91b'/%3E%3Ccircle cx='16' cy='11' r='2' fill='%230b0e08'/%3E%3C/svg%3E">
<style>
  :root{--bg:#0b0e08;--card:#141a10;--line:#2b3320;--fg:#e9e7dc;--dim:#98a184;
        --susp:#e0a91b;--cheat:#e5484d;--ok:#8fbf5a;--olive:#7d8c52}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;color:var(--fg);
       background:radial-gradient(1100px 560px at 50% -12%,#1c2415,#0b0e08 62%),
                  repeating-linear-gradient(0deg,rgba(255,255,255,.022) 0 1px,transparent 1px 40px),
                  repeating-linear-gradient(90deg,rgba(255,255,255,.022) 0 1px,transparent 1px 40px),
                  #0b0e08;
       font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       display:flex;flex-direction:column;align-items:center;padding:24px 16px 56px}
  .stripe{position:fixed;inset:0 0 auto;height:5px;z-index:9;opacity:.8;
       background:repeating-linear-gradient(45deg,var(--susp) 0 10px,#0b0e08 10px 20px)}
  h1{margin:0 0 8px;font-size:27px;letter-spacing:1.5px;text-align:center;font-weight:800}
  h1 .en{color:var(--susp)}
  .sub{color:var(--dim);font-size:13px;margin-bottom:14px;text-align:center}
  .sub b{color:var(--fg)}
  .codetip{width:100%;max-width:720px;font-size:13.5px;line-height:1.85;color:var(--fg);
       border-left:3px solid var(--susp);background:rgba(224,169,27,.06);
       padding:11px 14px;margin:0 0 18px}
  .codetip b{color:var(--susp)}
  .codetip .mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:1px;color:var(--fg)}
  .card{position:relative;width:100%;max-width:720px;background:linear-gradient(180deg,#161d12,#11160d);
       border:1px solid var(--line);border-radius:6px;padding:18px;margin-bottom:12px;
       box-shadow:0 12px 30px rgba(0,0,0,.45)}
  .card::before,.card::after{content:"";position:absolute;width:13px;height:13px;
       border:2px solid var(--olive);opacity:.9}
  .card::before{top:-1px;left:-1px;border-right:0;border-bottom:0}
  .card::after{bottom:-1px;right:-1px;border-left:0;border-top:0}
  .fl{font:700 10px/1 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:2px;
       text-transform:uppercase;color:var(--olive);margin-bottom:10px}
  .fl.wide{width:100%;max-width:720px;margin:22px 0 8px}
  .row{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
  .cells{display:flex;align-items:center;gap:8px}
  .cells .cell{flex:0 0 auto;width:46px;height:58px;padding:0;text-align:center;
       background:#090c06;border:1px solid var(--line);border-radius:4px;color:var(--fg);
       font:700 24px/1 ui-monospace,SFMono-Regular,Consolas,monospace;
       box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}
  .cells .cell:focus{outline:none;border-color:var(--susp);box-shadow:0 0 0 3px rgba(224,169,27,.16)}
  .cells .dash{flex:0 0 auto;width:18px;text-align:center;color:var(--susp);user-select:none;
       font:700 22px/1 ui-monospace,SFMono-Regular,Consolas,monospace}
  input{flex:1;min-width:0;background:#090c06;border:1px solid var(--line);border-radius:4px;
       padding:14px;color:var(--fg);font-size:16px;
       font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
  input:focus{outline:none;border-color:var(--susp)}
  button{background:linear-gradient(180deg,#f0b429,#cf9410);color:#17130a;border:0;border-radius:4px;
       padding:0 22px;font-size:15px;font-weight:800;letter-spacing:1px;cursor:pointer;white-space:nowrap}
  button:active{transform:translateY(1px)}
  button.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
  button.ghost:hover{border-color:var(--olive)}
  .btns{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
  .sim{font-size:12.5px;line-height:1.8;color:var(--susp);margin-top:8px}
  .sim .mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:1px;color:var(--fg)}
  .ago{color:var(--dim);font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums}
  .msg{min-height:20px;font-size:13px;margin-top:10px;color:var(--dim)}
  .msg.err{color:var(--cheat)}
  .msg.warn{color:var(--susp)}
  .msg.ok{color:var(--ok)}
  .qres{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--fg)}
  .stats{display:flex;gap:18px;flex-wrap:wrap;color:var(--dim);font-size:13px;
       width:100%;max-width:720px;margin:0 0 14px}
  .stats b{color:var(--fg)}
  ul{list-style:none;padding:0;margin:0;width:100%;max-width:720px}
  li{background:linear-gradient(180deg,#161d12,#11160d);border:1px solid var(--line);border-radius:4px;
       border-left:3px solid var(--olive);padding:12px 14px;margin-bottom:8px;
       display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  li.cheat{border-color:rgba(229,72,77,.6);background:linear-gradient(90deg,rgba(229,72,77,.14),#131810 42%)}
  li.cheat .name{color:#ffd7d7}
  .name{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:16px;flex:1;
       min-width:140px;word-break:break-all;letter-spacing:1px}
  .name::before{content:"";display:inline-block;width:6px;height:6px;margin-right:8px;
       border:1px solid var(--olive);border-radius:50%;vertical-align:1px}
  li.cheat .name::before{border-color:var(--cheat)}
  .cnt{color:var(--dim);font-size:13px;font-variant-numeric:tabular-nums}
  .bar{width:100%;height:5px;border-radius:2px;background:#0a0d07;overflow:hidden;margin-top:8px;flex-basis:100%}
  .bar i{display:block;height:100%;background:linear-gradient(90deg,#8a6d10,var(--susp))}
  li.cheat .bar i{background:linear-gradient(90deg,#8f2020,var(--cheat))}
  .tag{font-size:12px;font-weight:800;padding:4px 10px;border-radius:3px;white-space:nowrap;letter-spacing:.5px}
  .tag.susp{color:var(--susp);border:1px solid rgba(224,169,27,.5);background:rgba(224,169,27,.10)}
  .tag.cheat{color:#fff;background:var(--cheat)}
  .stamp{font:700 10px/1 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:2px;
       color:rgba(229,72,77,.9);border:1px dashed rgba(229,72,77,.6);padding:3px 6px;
       border-radius:3px;transform:rotate(-2deg)}
  .empty{color:var(--dim);text-align:center;padding:28px 0;font-size:14px;
       border:1px dashed var(--line);border-radius:4px}
  .tips{width:100%;max-width:720px;margin:26px 0 0;font-size:13px;line-height:1.85;color:var(--dim);
       border-top:1px dashed var(--line);padding-top:14px}
  .tips b{color:var(--fg)}
  .tips ul{margin:6px 0 0}
  .tips li{background:none;border:0;border-left:2px solid var(--olive);border-radius:0;
       padding:0 0 0 10px;margin:0 0 6px;display:block;font-size:13px;color:var(--dim)}
  .foot{width:100%;max-width:720px;margin-top:22px;padding-top:14px;border-top:1px solid var(--line);
       color:var(--dim);font-size:11.5px;line-height:1.9}
  .foot b{color:var(--fg)}
  .foot .warnline{color:rgba(224,169,27,.9)}
  @media (max-width:430px){
    .cells{gap:5px}
    .cells .cell{width:38px;height:50px;font-size:20px}
    .cells .dash{width:12px;font-size:18px}
    h1{font-size:22px}
    li{gap:8px}
  }
</style>
</head>
<body>
<div class="stripe"></div>

<h1><span class="en">WARDOGS</span> 可疑ID 登记处</h1>
<div class="sub">登记一次 = 一次怀疑 · 同一个 ID 被登记超过 <span id="th">20</span> 次 → 判定为「外挂」</div>

<div class="codetip">
  <b>登记 code：</b>就是<b>积分版上玩家名字右侧的那 7 个字</b>（例：<span class="mono">2VDE-THE</span>）——
  填进下面的方框就行，中间的横线会自动带上。
</div>

<div class="card">
  <div class="fl">// 登记 / 查询 code</div>
  <div class="row">
    <div class="cells" id="idcells" aria-label="7 位玩家 code">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false" aria-label="第 1 位">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false" aria-label="第 2 位">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false" aria-label="第 3 位">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false" aria-label="第 4 位">
      <span class="dash">-</span>
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false" aria-label="第 5 位">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false" aria-label="第 6 位">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false" aria-label="第 7 位">
    </div>
    <div class="btns">
      <button id="qbtn" class="ghost">查询</button>
      <button id="btn">登记为可疑</button>
    </div>
  </div>
  <div class="msg" id="msg">先查一眼：已经有人登记过就不用再填；没查到的话，看清了就直接登记。</div>
  <div class="sim" id="sim"></div>
</div>

<div class="fl wide">// 战场记录 · FIELD LOG</div>

<div class="stats">
  <span>已登记 <b id="s-total">0</b> 个 code</span>
  <span>累计登记 <b id="s-reg">0</b> 次</span>
  <span>判定为外挂 <b id="s-cheat">0</b> 个</span>
  <span>阈值 &gt; 20 次自动判定</span>
  <span id="s-quota-wrap" hidden>今日还能登记 <b id="s-quota">0</b> 次</span>
</div>

<ul id="list"></ul>

<div class="tips">
  <b>// 战场笔记 · FIELD NOTES</b>
  <ul>
    <li>这游戏<b>不给敌人标记</b>：能隔着三堵墙、穿过烟幕把人点名的人，最值得登记一条。</li>
    <li>挂也爱钻 <b>Hot Zone</b>（现金双倍）—— 人多的热点，同一局里撞见同一个 ID 的概率最高。</li>
    <li>登记前<b>核对一遍</b>：错一位就是另一个 code，而且登记了<b>没法撤回</b>。</li>
    <li>登记是匿名的：服务端只存加盐哈希，不记你的游戏 ID；限次用的也只是 IP 的哈希。</li>
    <li>防刷：<b>同一个网络每天最多登记 5 次</b> —— 次数要靠不同的人攒，一个人点不满。</li>
    <li>判定只看次数：<b>登记数超过 20 次即标「外挂」</b>，不代表官方结论。</li>
  </ul>
</div>

<div class="foot">
  <div><b>关于 WARDOGS：</b>BULKHEAD 开发、Team17 发行的 100 人三阵营（Lonestar / Valkyra / Manticore）全兵种 FPS；Control Zone 每 30 秒记一分，先到 100 分取胜；官方反作弊是内核级的 Elytra。</div>
  <div class="warnline">真正的举报请走<b>游戏内 Report</b>（见 wardogs.com/enforcement）—— 官方才会处理账号。本站只是玩家自建的公共登记本，不能代替官方举报。</div>
  <div>玩家自建工具，与 BULKHEAD、Team17 无关联，未获其背书；WARDOGS 及相关名称与商标归其各自所有者。</div>
</div>

<script>
const $ = s => document.querySelector(s);
const esc = s => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

let DATA = { list: [] };            // 最近一次的 /api/list，供实时提示用（不再发请求）

function ago(ts){
  if(!ts) return '';
  const s = Math.max(0, Date.now()/1000 - ts);
  if(s < 90) return '刚刚';
  if(s < 3600*6) return Math.round(s/60) + ' 分钟前';
  if(s < 86400*2) return Math.round(s/3600) + ' 小时前';
  if(s < 86400*30) return Math.round(s/86400) + ' 天前';
  const t = new Date(ts*1000);
  return t.getFullYear()+'-'+String(t.getMonth()+1).padStart(2,'0')+'-'+String(t.getDate()).padStart(2,'0');
}

// 只差 1~2 个字符的已登记 code：错一位就是把罪证记到别人头上
function similarTo(v){
  const out = [];
  for(const r of DATA.list){
    if(r.id === v) continue;
    let diff = Math.abs(r.id.length - v.length);
    for(let i = 0; i < Math.max(r.id.length, v.length); i++){ if(r.id[i] !== v[i]) diff++; }
    if(diff <= 2) out.push(Object.assign({}, r, {diff: diff}));
  }
  out.sort((a,b) => a.diff - b.diff || b.count - a.count);
  return out.slice(0, 3);
}

// 7 格填满就当场给话：这条有没有人登过、板上有没有长得像的
function liveHint(){
  const sim = $('#sim');
  const v = entry.id();
  if(entry.value().length < 7 || !ID_RE.test(v)){ sim.innerHTML = ''; return; }
  const mine = DATA.list.find(r => r.id === v);
  const near = similarTo(v);
  let html = '';
  if(mine){
    html += `「<span class="mono">${esc(v)}</span>」已被登记 <b>${mine.count}</b> 次`
         + (mine.last ? ' · 最近 ' + ago(mine.last) : '')
         + (mine.cheater ? ' · <b>已判定外挂</b>' : '')
         + ' —— 不用再登记，一个人头只能算一次';
  }
  if(near.length){
    html += (html ? '<br>' : '')
      + '板上还有只差 1~2 个字符的 <span class="mono">'
      + near.map(r => esc(r.id) + '(' + r.count + ')').join('、')
      + '</span> —— 看清再登记，登记了没法撤回';
  }
  sim.innerHTML = html;
}

function render(d){
  DATA = d;
  $('#th').textContent = d.threshold;
  $('#s-total').textContent = d.total;
  $('#s-reg').textContent = (typeof d.registrations === 'number')
    ? d.registrations : d.list.reduce((a,r) => a + r.count, 0);
  $('#s-cheat').textContent = d.cheaters;
  const qw = $('#s-quota-wrap');
  if(typeof d.left_today === 'number' && d.used_today > 0){
    qw.hidden = false; $('#s-quota').textContent = d.left_today;
  }else{
    qw.hidden = true;
  }
  const el = $('#list');
  if(!d.list.length){ el.innerHTML = '<div class="empty">还没有人上榜。</div>'; return; }
  el.innerHTML = d.list.map(r => {
    const pct = Math.min(100, r.count / d.threshold * 100);
    return `<li class="${r.cheater?'cheat':''}">
      <span class="name">${esc(r.id)}</span>
      ${r.cheater?'<span class="stamp">CHEATER</span>':''}
      <span class="cnt">${r.count} / ${d.threshold}</span>
      <span class="tag ${r.cheater?'cheat':'susp'}">${r.cheater?'外挂':'可疑ID'}</span>
      <span class="ago">${r.last ? '最近 ' + ago(r.last) : ''}</span>
      <span class="bar"><i style="width:${pct}%"></i></span>
    </li>`;
  }).join('');
  liveHint();
}

// 与后端 format_id 一致：全角→半角、各种横杠→'-'、去零宽字符、空白收敛、全大写
function fmt(s){
  return String(s).normalize('NFKC')
    .replace(/[\u2010-\u2015\u2212\u2043\uFE63\uFE58\uFF0D]/g,'-')
    .replace(/[\u00ad\u200b-\u200f\ufeff]/g,'')
    .replace(/\s+/g,' ').trim().toUpperCase();
}

// 浏览器指纹：只用于登记去重（同一浏览器同一个 ID 只算一次），原文不上报，服务端再加盐哈希
let FP = '';
function fingerprint(){
  const p = [];
  try{
    p.push(navigator.userAgent, navigator.platform||'', navigator.language||'',
           (navigator.languages||[]).join(','), navigator.hardwareConcurrency||0,
           navigator.deviceMemory||0, navigator.maxTouchPoints||0,
           screen.width, screen.height, screen.availWidth, screen.availHeight,
           screen.colorDepth, screen.pixelDepth, window.devicePixelRatio||1,
           new Date().getTimezoneOffset(),
           Intl.DateTimeFormat().resolvedOptions().timeZone||'',
           (navigator.plugins||[]).length);
    const c = document.createElement('canvas');
    c.width = 240; c.height = 60;
    const g = c.getContext('2d');
    if(g){
      const grad = g.createLinearGradient(0,0,240,60);
      grad.addColorStop(0,'#f0b429'); grad.addColorStop(1,'#f85149');
      g.fillStyle = grad; g.fillRect(0,0,240,60);
      g.font = '16px Arial'; g.fillStyle = '#0d1117';
      g.fillText('可疑ID-登记处 AaBb019 !@#', 4, 38);
      g.arc(200, 30, 18, 0, Math.PI*1.7); g.stroke();
      p.push(c.toDataURL().slice(-120));            // canvas 渲染差异
    }
    const gl = document.createElement('canvas').getContext('webgl');
    if(gl){
      p.push(gl.getParameter(gl.VERSION)||'');
      const dbg = gl.getExtension('WEBGL_debug_renderer_info');
      if(dbg) p.push(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)||'',
                     gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)||'');
    }
  }catch(e){}
  const s = p.join('|');
  let h1 = 5381, h2 = 0x811c9dc5;
  for(let i=0;i<s.length;i++){
    const ch = s.charCodeAt(i);
    h1 = (((h1<<5) + h1) + ch) >>> 0;
    h2 = Math.imul(h2 ^ ch, 0x01000193) >>> 0;
  }
  return h1.toString(16).padStart(8,'0') + h2.toString(16).padStart(8,'0');
}

async function refresh(){
  const r = await fetch('/api/list');
  render(await r.json());
}

const ID_RE = /^[A-Z0-9]{4}-[A-Z0-9]{3}$/;   // 严格 7 位，与后端 ID_RE 同一套
const ID_ERR = 'ID 格式不对：必须是 7 位（4 位字母/数字 + - + 3 位字母/数字，如 2VDE-THE）';
const HINT = '先查一眼：已经有人登记过就不用再填；没查到的话，看清了就直接登记。';
function setMsg(text, cls){ const m = $('#msg'); m.className = 'msg' + (cls ? ' ' + cls : ''); m.textContent = text || HINT; }

async function submit(){
  const v = idFromCells();
  const n = cellsValue().length;
  if(n < 7){ setMsg('还差 ' + (7 - n) + ' 位 —— 一共 7 位（4 位 + 3 位，例：2VDE-THE）', 'err'); focusCell(n); return; }
  if(!ID_RE.test(v)){ setMsg(ID_ERR, 'err'); return; }
  $('#btn').disabled = true;
  try{
    if(!FP) FP = fingerprint();
    const r = await fetch('/api/register', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({id: v, fp: FP})
    });
    const d = await r.json();
    if(!r.ok){
      setMsg(d.error || '登记失败', d.dup ? 'warn' : 'err');
    }
    else{
      setMsg(d.cheater
        ? `「${d.id}」已登记 ${d.count} 次 —— 判定为外挂 · CHEATER`
        : `已登记「${d.id}」，当前 ${d.count} 次怀疑`);
      entry.clear();
      entry.focus(0);
      liveHint();
    }
    await refresh();
  }catch(e){ setMsg('网络错误：' + e.message, 'err'); }
  $('#btn').disabled = false;
}

// 方框输入：7 个格子，中间那根「-」由页面自带。查询与登记共用这一组。
// 只收英文数字：可打印按键在 keydown 阶段就被页面接管（preventDefault），输入法不会被唤醒；
// 手机上靠 inputmode=latin 给拉丁键盘；万一输入法还是塞进中文/全角（组词路径），走 fmt() 那一路也会被归一或丢掉
function boxInputs(boxId, onEnter, onType){
  const cells = Array.from(document.querySelectorAll('#' + boxId + ' .cell'));
  const val = () => cells.map(c => c.value).join('');
  const obj = {
    cells,
    value: val,
    id: () => { const v = val(); return v.length > 4 ? v.slice(0, 4) + '-' + v.slice(4) : v; },
    focus: i => { const t = cells[Math.max(0, Math.min(cells.length - 1, i))]; if(t){ t.focus(); t.select(); } },
    clear: () => cells.forEach(c => { c.value = ''; })
  };
  cells.forEach((c, i) => {
    c.addEventListener('input', () => {
      if(c.dataset.im === '1') return;                      // 中文输入法组词中不打断
      const raw = fmt(c.value).replace(/[^A-Z0-9]/g, '');   // 单格只留 A-Z0-9
      if(raw.length > 1){                                   // 粘了整串 → 从这格往后铺开
        for(let k = 0; k < raw.length && i + k < cells.length; k++) cells[i + k].value = raw[k];
        obj.focus(i + raw.length);
      }else{
        c.value = raw;
        if(raw) obj.focus(i + 1);
      }
      onType();
    });
    c.addEventListener('compositionstart', () => { c.dataset.im = '1'; });
    c.addEventListener('compositionend', () => { delete c.dataset.im; c.dispatchEvent(new Event('input')); });
    c.addEventListener('keydown', e => {
      if(e.key === 'Enter'){ e.preventDefault(); onEnter(); return; }
      if(e.ctrlKey || e.metaKey || e.altKey) return;              // 复制/粘贴/全选照旧交给浏览器
      if(e.key === 'Backspace'){ if(!c.value){ e.preventDefault(); if(cells[i-1]) cells[i-1].value = ''; obj.focus(i - 1); } return; }
      if(e.key === 'ArrowLeft'){ e.preventDefault(); obj.focus(i - 1); return; }
      if(e.key === 'ArrowRight'){ e.preventDefault(); obj.focus(i + 1); return; }
      if(e.key === 'Tab') return;                                 // Tab 正常跳走
      if(e.key.length === 1){                                     // 可打印键：拦下默认行为，页面自己填
        e.preventDefault();                                       // ← 输入法拿不到这个键，就不会弹候选窗
        const ch = e.key.toUpperCase();
        if(!/[A-Z0-9]/.test(ch)) return;                          // 横线/中文/符号一律丢掉；只认英文数字
        cells[i].value = ch;
        onType();
        obj.focus(i + 1);
      }
    });
  });
  return obj;
}

async function query(){
  const msg = $('#msg');
  const v = entry.id();
  const n = entry.value().length;
  if(n < 7){ setMsg('还差 ' + (7 - n) + ' 位 —— 一共 7 位（4 位 + 3 位，例：2VDE-THE）', 'err'); entry.focus(n); return; }
  if(!ID_RE.test(v)){ setMsg(ID_ERR, 'err'); return; }
  $('#qbtn').disabled = true;
  try{
    const r = await fetch('/api/query?id=' + encodeURIComponent(v));
    const d = await r.json();
    if(!r.ok){ msg.className='msg err'; msg.textContent = d.error || '查询失败'; }
    else if(!d.found){
      msg.className='msg warn';
      msg.textContent = `「${d.id}」还没有被登记过 —— 如果你确实看到了可疑行为，点旁边的「登记为可疑」，它就是第一条`;
    }
    else{
      msg.className = d.cheater ? 'msg err' : 'msg ok';
      msg.innerHTML = `「<span class="qres">${esc(d.id)}</span>」已被登记 <b>${d.count}</b> 次`
                    + `（阈值 ${d.threshold}）· 判定：<b>${d.cheater ? '外挂' : '可疑ID'}</b>`
                    + (d.last ? ` · 最近 ${ago(d.last)}` : '');
    }
    liveHint();
  }catch(e){ msg.className='msg err'; msg.textContent='网络错误：'+e.message; }
  $('#qbtn').disabled = false;
}

// 一组方框两种动作：查询看次数，登记落一条
const entry = boxInputs('idcells', () => submit(), () => { setMsg(''); liveHint(); });
const cells = entry.cells;                   // 兼容旧名字
const cellsValue = entry.value;
const idFromCells = entry.id;
const focusCell = entry.focus;

$('#btn').addEventListener('click', submit);
$('#qbtn').addEventListener('click', query);
// 触屏一进页面就聚焦会立刻糊上来一个键盘挡住半屏 —— 只在有实体键盘的设备上自动聚焦
if(!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches)) focusCell(0);
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SuspectID/1.1"
    _set_cookie: str | None = None

    def log_message(self, fmt, *args):        # 静音访问日志
        pass

    def _cookie_value(self, name: str) -> str | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v.strip()
        return None

    def _client_ip(self) -> str | None:
        """出口地址：反代后先看 X-Forwarded-For 第一段，否则取连接对端。

        只喂给 ip_bucket() 加盐哈希，明文不进数据文件、不进日志。
        """
        fwd = self.headers.get("X-Forwarded-For") or ""
        for hop in [h.strip() for h in fwd.split(",") if h.strip()]:
            if hop and hop.lower() != "unknown":
                return hop
        return self.client_address[0] if self.client_address else None

    def _identity(self) -> str:
        """取出或新签发这个浏览器的身份 cookie（签名过，改一个字都算新浏览器）。"""
        sid = unsign_sid(self._cookie_value(COOKIE))
        if not sid:
            sid = secrets.token_hex(16)
            self._set_cookie = (f"{COOKIE}={sign_sid(sid)}; Path=/; Max-Age={COOKIE_AGE}; "
                                f"SameSite=Lax; HttpOnly")
        return sid

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self._set_cookie:
            self.send_header("Set-Cookie", self._set_cookie)
            self._set_cookie = None
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def do_GET(self):
        self._identity()                      # 第一眼就发身份 cookie
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/api/list":
            with _lock:
                data = snapshot()
                left, used = check_quota(ip_bucket(self._client_ip()))
            data.update({"daily_cap": DAILY_CAP, "left_today": left, "used_today": used})
            self._json(data)
        elif path == "/api/query":
            q = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            name = format_id((q.get("id") or [""])[0])
            if not ID_RE.fullmatch(name):
                self._json({"error": ID_ERR, "found": False}, 400)
                return
            with _lock:
                rec = _state["ids"].get(name.lower())
                count = int(rec.get("count", 0)) if rec else 0
                similar = similar_ids(name)
                self._json({
                    "id": str(rec.get("display", name)).upper() if rec else name,
                    "found": rec is not None,
                    "count": count,
                    "cheater": count > THRESHOLD,
                    "threshold": THRESHOLD,
                    "last": rec.get("last", 0) if rec else 0,
                    "similar": similar,
                })
        elif path == "/og.png":
            if not _OG_PNG:
                self._json({"error": "not found"}, 404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(_OG_PNG)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(_OG_PNG)
        elif path == "/healthz":
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        sid = self._identity()
        if self.path.split("?")[0] != "/api/register":
            self._json({"error": "not found"}, 404)
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n) or b"{}")
            raw = payload.get("id", "")
            fp = payload.get("fp", "")
        except Exception:
            self._json({"error": "请求格式错误"}, 400)
            return
        result, err, dup = register(raw, sid=sid, fp=fp, ip=self._client_ip())
        if result:
            self._json(result)
        else:
            self._json({"error": err, "dup": dup}, 409 if dup else 400)


def main() -> None:
    load()
    with _lock:
        snap = snapshot()
    print(f"可疑ID 登记处 → http://{HOST}:{PORT}  (阈值 {THRESHOLD}，现有 {snap['total']} 条)", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
