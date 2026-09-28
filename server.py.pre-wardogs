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
PORT = int(os.environ.get("PORT", "8792"))
HOST = os.environ.get("HOST", "0.0.0.0")   # 前面有 nginx 反代时可设 127.0.0.1
THRESHOLD = 20          # 登记数 > 20 → 外挂
ID_RE = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{3}$")   # 严格 7 位：4 位字母数字 + "-" + 3 位字母数字
ID_ERR = "ID 格式不对：必须是 7 位（4 位字母/数字 + - + 3 位字母/数字，如 2VDE-THE）"

# 输入自动格式化用：各种横杠统一映射成 '-'，零宽/软连字符直接删除
_HYPHENS = dict.fromkeys(
    [0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0x2043, 0xFE63, 0xFE58, 0xFF0D], "-")
_INVISIBLE = dict.fromkeys([0x00AD, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF], None)

_lock = threading.Lock()
_state: dict = {"ids": {}}


def load() -> None:
    global _state
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, encoding="utf-8") as fp:
                raw = json.load(fp)
            if isinstance(raw, dict) and isinstance(raw.get("ids"), dict):
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
            "_last": rec.get("last", 0),
        })
    # 外挂优先、次数多的靠前，同档次按最近登记时间倒序
    rows.sort(key=lambda r: (r["cheater"], r["count"], r["_last"]), reverse=True)
    for r in rows:
        r.pop("_last", None)
    cheaters = sum(1 for r in rows if r["cheater"])
    return {
        "threshold": THRESHOLD,
        "total": len(rows),
        "cheaters": cheaters,
        "list": rows,
    }


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


def register(raw: str, sid: str | None = None, fp: str | None = None):
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
    with _lock:
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
        save()
        return {"id": rec["display"], "count": rec["count"],
                "cheater": rec["count"] > THRESHOLD}, None, False


PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>可疑ID 登记处</title>
<style>
  :root{--bg:#0d1117;--card:#161b22;--line:#262d38;--fg:#e6edf3;--dim:#8b949e;
        --susp:#d29922;--cheat:#f85149;--ok:#3fb950}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;background:radial-gradient(1200px 600px at 50% -10%,#1b2430,#0d1117 60%);
       color:var(--fg);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       display:flex;flex-direction:column;align-items:center;padding:32px 16px 64px}
  h1{margin:0 0 6px;font-size:26px;letter-spacing:.5px}
  .sub{color:var(--dim);font-size:13px;margin-bottom:24px;text-align:center}
  .card{width:100%;max-width:720px;background:var(--card);border:1px solid var(--line);
        border-radius:14px;padding:18px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
  .row{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
  .cells{display:flex;align-items:center;gap:8px}
  .cells .cell{flex:0 0 auto;width:46px;height:58px;padding:0;text-align:center;
        font:700 24px/1 ui-monospace,SFMono-Regular,Consolas,monospace}
  .cells .cell:focus{border-color:var(--susp);box-shadow:0 0 0 3px rgba(240,180,41,.15)}
  .cells .dash{flex:0 0 auto;width:18px;text-align:center;color:var(--dim);user-select:none;
        font:700 22px/1 ui-monospace,SFMono-Regular,Consolas,monospace}
  input{flex:1;min-width:0;background:#0d1117;border:1px solid var(--line);border-radius:10px;
        padding:14px 14px;color:var(--fg);font-size:16px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
  input:focus{outline:none;border-color:var(--susp)}
  button{background:#f0b429;color:#1a1400;border:0;border-radius:10px;padding:0 22px;
         font-size:16px;font-weight:700;cursor:pointer;white-space:nowrap}
  button:active{transform:translateY(1px)}
  .msg{min-height:20px;font-size:13px;margin-top:10px;color:var(--dim)}
  .msg.err{color:var(--cheat)}
  .msg.warn{color:var(--susp)}
  .msg.ok{color:var(--ok)}
  .qcard{margin-top:8px}
  button.ghost{background:#21262d;color:var(--fg);border:1px solid var(--line)}
  .qres{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--fg)}
  .stats{display:flex;gap:18px;flex-wrap:wrap;color:var(--dim);font-size:13px;
         margin:22px 0 10px;width:100%;max-width:720px}
  .stats b{color:var(--fg)}
  ul{list-style:none;padding:0;margin:0;width:100%;max-width:720px}
  li{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:10px;
     display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  li.cheat{border-color:rgba(248,81,73,.55);background:linear-gradient(90deg,rgba(248,81,73,.10),var(--card) 45%)}
  .name{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:16px;flex:1;min-width:140px;
        word-break:break-all}
  .cnt{color:var(--dim);font-size:13px;font-variant-numeric:tabular-nums}
  .bar{width:100%;height:4px;border-radius:3px;background:#0d1117;overflow:hidden;margin-top:8px;flex-basis:100%}
  .bar i{display:block;height:100%;background:var(--susp)}
  li.cheat .bar i{background:var(--cheat)}
  .tag{font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px;white-space:nowrap}
  .tag.susp{color:var(--susp);border:1px solid rgba(210,153,34,.45);background:rgba(210,153,34,.10)}
  .tag.cheat{color:#fff;background:var(--cheat)}
  .empty{color:var(--dim);text-align:center;padding:28px 0;font-size:14px}
</style>
</head>
<body>
<h1>可疑ID 登记处</h1>
<div class="sub">登记一次 = 一次怀疑 · 同一个 ID 被登记超过 <span id="th">20</span> 次 → 判定为「外挂」</div>

<div class="card">
  <div class="row">
    <div class="cells" id="idcells" aria-label="7 位玩家 ID">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <span class="dash">-</span>
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
    </div>
    <button id="btn">登记为可疑ID</button>
  </div>
  <div class="msg" id="msg">输入 7 位 ID，中间的横线会自动带上（例：2VDE-THE）。</div>
</div>

<div class="card qcard">
  <div class="row">
    <div class="cells" id="qcells" aria-label="7 位玩家 ID（查询）">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <span class="dash">-</span>
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
      <input class="cell" maxlength="1" inputmode="latin" autocapitalize="characters" autocomplete="off" spellcheck="false">
    </div>
    <button id="qbtn" class="ghost">查询</button>
  </div>
  <div class="msg" id="qmsg">输入一个 ID，查询它被登记了多少次。</div>
</div>

<div class="stats">
  <span>已登记 <b id="s-total">0</b> 个 ID</span>
  <span>判定为外挂 <b id="s-cheat">0</b> 个</span>
</div>

<ul id="list"></ul>

<script>
const $ = s => document.querySelector(s);
const esc = s => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function render(d){
  $('#th').textContent = d.threshold;
  $('#s-total').textContent = d.total;
  $('#s-cheat').textContent = d.cheaters;
  const box = $('#list');
  if(!d.list.length){ box.innerHTML = '<div class="empty">还没有人上榜。</div>'; return; }
  box.innerHTML = d.list.map(r => {
    const pct = Math.min(100, r.count / d.threshold * 100);
    return `<li class="${r.cheater?'cheat':''}">
      <span class="name">${esc(r.id)}</span>
      <span class="cnt">${r.count} / ${d.threshold}</span>
      <span class="tag ${r.cheater?'cheat':'susp'}">${r.cheater?'外挂':'可疑ID'}</span>
      <span class="bar"><i style="width:${pct}%"></i></span>
    </li>`;
  }).join('');
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
const HINT = '输入 7 位 ID，中间的横线会自动带上（例：2VDE-THE）。';
function setMsg(text, cls){ const m = $('#msg'); m.className = 'msg' + (cls ? ' ' + cls : ''); m.textContent = text || HINT; }
const QHINT = '输入一个 ID，查询它被登记了多少次。';
function setQMsg(text, cls){ const m = $('#qmsg'); m.className = 'msg' + (cls ? ' ' + cls : ''); m.textContent = text || QHINT; }

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
        ? `「${d.id}」已登记 ${d.count} 次 —— 判定为外挂 ✅`
        : `已登记「${d.id}」，当前 ${d.count} 次怀疑`);
      reg.clear();
      focusCell(0);
    }
    await refresh();
  }catch(e){ setMsg('网络错误：' + e.message, 'err'); }
  $('#btn').disabled = false;
}

// 方框输入：7 个格子，中间那根「-」由页面自带。
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
  const msg = $('#qmsg');
  const v = qry.id();
  const n = qry.value().length;
  if(n < 7){ setQMsg('还差 ' + (7 - n) + ' 位 —— 一共 7 位（4 位 + 3 位，例：2VDE-THE）', 'err'); qry.focus(n); return; }
  if(!ID_RE.test(v)){ setQMsg(ID_ERR, 'err'); return; }
  $('#qbtn').disabled = true;
  try{
    const r = await fetch('/api/query?id=' + encodeURIComponent(v));
    const d = await r.json();
    if(!r.ok){ msg.className='msg err'; msg.textContent = d.error || '查询失败'; }
    else if(!d.found){ msg.className='msg warn'; msg.textContent = `「${d.id}」还没有被登记过`; }
    else{
      msg.className = d.cheater ? 'msg err' : 'msg ok';
      msg.innerHTML = `「<span class="qres">${esc(d.id)}</span>」已被登记 <b>${d.count}</b> 次`
                    + `（阈值 ${d.threshold}）· 判定：<b>${d.cheater ? '外挂' : '可疑ID'}</b>`;
    }
  }catch(e){ msg.className='msg err'; msg.textContent='网络错误：'+e.message; }
  $('#qbtn').disabled = false;
}

// 两个框同一套方框行为：登记框 #idcells、查询框 #qcells
const reg = boxInputs('idcells', () => submit(), () => setMsg(''));
const qry = boxInputs('qcells', () => query(), () => setQMsg(''));
const cells = reg.cells;                     // 兼容旧名字
const cellsValue = reg.value;
const idFromCells = reg.id;
const focusCell = reg.focus;

$('#btn').addEventListener('click', submit);
$('#qbtn').addEventListener('click', query);
focusCell(0);
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
                self._json(snapshot())
        elif path == "/api/query":
            q = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            name = format_id((q.get("id") or [""])[0])
            if not ID_RE.fullmatch(name):
                self._json({"error": ID_ERR, "found": False}, 400)
                return
            with _lock:
                rec = _state["ids"].get(name.lower())
                count = int(rec.get("count", 0)) if rec else 0
                self._json({
                    "id": str(rec.get("display", name)).upper() if rec else name,
                    "found": rec is not None,
                    "count": count,
                    "cheater": count > THRESHOLD,
                    "threshold": THRESHOLD,
                })
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
        result, err, dup = register(raw, sid=sid, fp=fp)
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
