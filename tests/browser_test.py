#!/usr/bin/env python3
"""真实浏览器端到端测试（裸 CDP，不依赖 selenium/puppeteer）。

验证：
  1. 页面里的 JS 指纹算得出来
  2. 身份 cookie 是服务端下发的 HttpOnly cookie
  3. 输入全角 ID → 输入框里当场被格式化成半角大写
  4. 点登记 → 成功；再点一次 → 被拦（同一浏览器只能登记一次）
  5. 用 CDP 清掉 cookie 再点 → 仍然被拦（指纹兜底）

用法: chromium --headless=new --remote-debugging-port=9222 ... &
      /usr/bin/python3 tests/browser_test.py [BASE_URL] [CDP_PORT]
"""
from __future__ import annotations

import base64
import json
import random
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(os.path.dirname(HERE), "server.py")
BASE = "http://127.0.0.1:8792"           # 默认值；main() 里按参数/隔离实例覆盖
CDP_PORT = 9222
PORT_ISO = 8795
TMP_DATA = "/tmp/browser-test.json"
TMP_SECRET = "/tmp/browser-test.secret"
OK, FAIL = [], []


def check(name, cond, detail=""):
    (OK if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' — ' + str(detail)) if detail else ''}")


class WS:
    """够用就好的 WebSocket 客户端（只为 CDP 服务）。"""

    def __init__(self, url: str, timeout: float = 20.0):
        u = urllib.parse.urlparse(url)
        self.sock = socket.create_connection((u.hostname, u.port or 80), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f"GET {u.path} HTTP/1.1\r\nHost: {u.netloc}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("WS 握手失败：连接被关")
            buf += chunk
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        if b"101" not in head.split(b"\r\n")[0]:
            raise RuntimeError("WS 握手失败: " + head[:120].decode("latin1"))
        self._id = 0

    def _exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(1 << 16)
            if not chunk:
                raise EOFError("WS 已关闭")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            head = bytes([0x80 | opcode, 0x80 | n])
        elif n < 65536:
            head = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", n)
        else:
            head = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(head + mask + masked)

    def call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self._frame(0x1, json.dumps({"id": self._id, "method": method,
                                    "params": params or {}}).encode())
        while True:
            b1, b2 = self._exact(2)
            op, ln = b1 & 0x0F, b2 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._exact(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._exact(8))[0]
            payload = self._exact(ln)
            if op == 0x9:                                   # ping → pong
                self._frame(0xA, payload)
                continue
            if op == 0x8:
                raise EOFError("WS 被对端关闭")
            if op == 0x1:
                msg = json.loads(payload.decode())
                if msg.get("id") == self._id:
                    return msg

    def js(self, expr: str):
        r = self.call("Runtime.evaluate", {"expression": expr, "returnByValue": True,
                                          "awaitPromise": True})
        res = r.get("result", {})
        if "exceptionDetails" in res:
            return f"<<JS 异常: {res['exceptionDetails'].get('text')}>>"
        return res.get("result", {}).get("value")

    def close(self):
        try:
            self._frame(0x8, b"")
        except Exception:
            pass
        self.sock.close()


def new_tab(url: str = "about:blank") -> dict:
    r = requests.put(f"http://127.0.0.1:{CDP_PORT}/json/new?{urllib.parse.quote(url)}", timeout=10)
    if r.status_code >= 400:
        r = requests.get(f"http://127.0.0.1:{CDP_PORT}/json/new?{urllib.parse.quote(url)}", timeout=10)
    return r.json()


ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
TID = "TSTX-" + "".join(random.choice(ALPHABET) for _ in range(3))    # 每跑一次换一个，不跟上一轮残留撞车
TID2 = "TSTX-" + "".join(random.choice(ALPHABET) for _ in range(3))
TID3 = "TSTX-" + "".join(random.choice(ALPHABET) for _ in range(3))


def fullwidth(text: str) -> str:
    """转成全角（用来测归一），- 用全角横杠。"""
    return "".join("－" if c == "-" else chr(ord(c) + 0xFEE0) for c in text)


def rows_of(ws):
    return ws.js("[...document.querySelectorAll('#list li')].map(e=>e.innerText.replace(/\\n/g,' ')).join(' // ')")


def cells_of(ws, box="idcells"):
    """读出某个方框里 7 格的内容（不含页面自带的横线）。"""
    return ws.js("[...document.querySelectorAll('#%s .cell')].map(c=>c.value).join('')" % box)


def paste_id(ws, value, box="idcells"):
    """把整串粘进第 1 格（触发 input），格子会自动往后铺开。"""
    ws.js("""(() => { const c=document.querySelectorAll('#%s .cell')[0];
              c.focus(); c.value=%s;
              c.dispatchEvent(new Event('input', {bubbles:true})); return true })()"""
           % (box, json.dumps(value)))


def type_keys(ws, value, box="idcells"):
    """逐格敲进去（每格派发 input），模拟真实打字。"""
    for i, ch in enumerate(value[:7]):
        ws.js("""(() => { const c=document.querySelectorAll('#%s .cell')[%d]; c.focus();
                  c.value=%s; c.dispatchEvent(new Event('input', {bubbles:true})); return true })()"""
              % (box, i, json.dumps(ch)))
    return cells_of(ws, box)


def clear_cells(ws, box="idcells"):
    ws.js("[...document.querySelectorAll('#%s .cell')].forEach(c => { c.value = ''; })" % box)


def msg_text(ws, sel="#msg"):
    return ws.js(f"document.querySelector('{sel}').textContent")


def wait_msg(ws, sel="#msg", prev=None, timeout=30.0):
    """等提示文案真的变了（公网那台小机器往返慢，固定 sleep 会读到旧文案）。"""
    end = time.time() + timeout
    while time.time() < end:
        t = msg_text(ws, sel)
        if t and t != prev:
            return t
        time.sleep(0.3)
    return msg_text(ws, sel)


def do_register(ws, value):
    """粘进格子再点登记，等提示变化后返回文案。"""
    paste_id(ws, value)
    time.sleep(0.3)
    prev = msg_text(ws)               # 粘贴会先把提示清空 → 以粘贴后的文案为基准
    ws.js("document.querySelector('#btn').click()")
    return wait_msg(ws, "#msg", prev)


def do_query(ws, value):
    """在查询框里填好再点查询，等提示变化后返回文案。"""
    clear_cells(ws, "qcells")
    paste_id(ws, value, "qcells")
    time.sleep(0.3)
    prev = msg_text(ws, "#qmsg")      # 同上：粘贴后重新取基准
    ws.js("document.querySelector('#qbtn').click()")
    return wait_msg(ws, "#qmsg", prev)


def my_row(ws, tid):
    """只取我自己那条（公网上有真人同时在登记，不能拿整页列表做前后比较）。"""
    return ws.js("[...document.querySelectorAll('#list li')].filter(e=>e.textContent.includes(%s))"
                 ".map(e=>e.innerText.replace(/\\n/g,' '))[0] || ''" % json.dumps(tid))


def main() -> None:
    """默认自己拉起一个干净实例（固定 ID 才能反复跑）；带 --base URL 则打真站点。"""
    global BASE, CDP_PORT
    if "--port" in sys.argv:
        CDP_PORT = int(sys.argv[sys.argv.index("--port") + 1])
    proc = None
    if "--base" in sys.argv:
        BASE = sys.argv[sys.argv.index("--base") + 1].rstrip("/")
    else:
        for f in (TMP_DATA, TMP_SECRET):
            if os.path.exists(f):
                os.remove(f)
        env = dict(os.environ, PORT=str(PORT_ISO), HOST="127.0.0.1",
                   SUSPECT_DATA=TMP_DATA, SUSPECT_SECRET=TMP_SECRET)
        proc = subprocess.Popen([sys.executable, SERVER], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        BASE = f"http://127.0.0.1:{PORT_ISO}"
        for _ in range(40):
            time.sleep(0.25)
            try:
                if requests.get(BASE + "/healthz", timeout=3).status_code == 200:
                    break
            except Exception:
                pass
    try:
        _run()
    finally:
        if proc:
            proc.terminate()
            proc.wait(timeout=10)
            for f in (TMP_DATA, TMP_SECRET):
                if os.path.exists(f):
                    os.remove(f)


def _run() -> None:
    tgt = new_tab()
    ws = WS(tgt["webSocketDebuggerUrl"])
    print(f"=== 真实浏览器端到端 @ {BASE} ===")
    try:
        ws.call("Page.enable")
        ws.call("Network.enable")
        ws.call("Network.clearBrowserCookies")      # 每次都从干净身份开始
        time.sleep(0.3)
        ws.call("Page.navigate", {"url": BASE + "/"})
        for _ in range(60):
            time.sleep(0.25)
            if ws.js("document.readyState") == "complete":
                break
        t = ws.js("document.title")
        check("页面加载", "可疑ID 登记处" in (t or "") and "WARDOGS" in (t or ""), t)
        check("WARDOGS 元素在场（登记 code 提示 / 战场笔记 / 免责页脚）",
              all(ws.js(f"!!document.querySelector('{s}')") for s in (".codetip", ".tips", ".foot")))
        check("顶部 banner 与战场简报已移除",
              not ws.js("!!document.querySelector('.opbar, .brief')"))

        print("\n[1] 指纹")
        fp = ws.js("FP || fingerprint()")
        check("指纹是 16 位十六进制", isinstance(fp, str) and len(fp) == 16 and all(c in "0123456789abcdef" for c in fp), fp)
        check("多次计算结果一致（稳定）", ws.js("fingerprint()") == ws.js("fingerprint()"))
        check("指纹里没有把 UA 原文暴露在页面上", "Mozilla" not in str(fp))

        print("\n[2] 身份 cookie（HttpOnly，JS 读不到）")
        ck = ws.call("Network.getCookies", {"urls": [BASE + "/"]})["result"]["cookies"]
        sid = [c for c in ck if c["name"] == "sid"]
        check("服务端下发了 sid cookie", bool(sid), str(ck)[:160])
        if sid:
            check("cookie 是 HttpOnly", sid[0].get("httpOnly") is True)
            check("cookie 有效期 ~2 年", sid[0].get("expires", 0) - time.time() > 300 * 86400)
        check("JS 读不到 cookie", ws.js("document.cookie") in ("", None))

        print("\n[3] 逐格输入全角 → 每格当场归一，横线由页面自带")
        got = type_keys(ws, fullwidth(TID.replace("-", "")))
        check("全角被转成半角大写，格子只有 7 位", got == TID.replace("-", ""), repr(got))
        check(f"拼出来的 ID 是 {TID}", ws.js("idFromCells()") == TID, ws.js("idFromCells()"))
        check("横线是中间那格（第 5 个位置）", ws.js(
            "[...document.querySelector('#idcells').children].findIndex(e=>e.classList.contains('dash'))") == 4)
        check("查询框排在登记框下面、列表上面", ws.js(
            "[...document.querySelectorAll('#idcells,#qcells,#list')].map(e=>e.id).join(',')") == "idcells,qcells,list")

        print(f"\n[4] 第一次登记（就用格子里拼好的 {TID}）")
        msg = wait_msg(ws, "#msg", "")
        ws.js("document.querySelector('#btn').click()")
        msg = wait_msg(ws, "#msg", msg)
        check("提示为成功文案", "已登记" in msg and TID in msg, msg)
        check("登记成功后 7 格被清空", cells_of(ws) == "", repr(cells_of(ws)))
        row = my_row(ws, TID)
        print(f"    我这条: {row}")
        check(f"列表里出现 {TID}", TID in (row or ""), row)

        print("\n[5] 同一浏览器再登记同一个 ID")
        msg = do_register(ws, TID)
        check("提示「已经登记过」", "已经登记过" in msg, msg)
        check("提示样式是 warn", ws.js("document.querySelector('#msg').className") == "msg warn",
              ws.js("document.querySelector('#msg').className"))
        check("计数没有涨", my_row(ws, TID) == row, my_row(ws, TID))

        print("\n[6] 用 CDP 清掉 cookie（模拟清空浏览器数据）再登记")
        ws.call("Network.clearBrowserCookies")
        time.sleep(0.5)
        msg = do_register(ws, TID)
        check("靠指纹仍然被拦", "已经登记过" in msg, msg)
        check("计数仍未涨", my_row(ws, TID) == row, my_row(ws, TID))

        print(f"\n[7] 换个 ID 登记（整串粘进第 1 格，带横线）→ 允许：{TID2}")
        paste_id(ws, TID2)
        time.sleep(0.3)
        prev = msg_text(ws)
        check("粘进来的横线被丢掉、格子只留 7 位", cells_of(ws) == TID2.replace("-", ""),
              repr(cells_of(ws)))
        ws.js("document.querySelector('#btn').click()")
        msg = wait_msg(ws, "#msg", prev)
        check("换 ID 能登记", "已登记" in msg and TID2 in msg, msg)
        row2 = my_row(ws, TID2)

        print("\n[8] 只填 4 位就点登记 → 前端拦住并说还差几位")
        prev = msg_text(ws)
        paste_id(ws, TID2[:4])
        ws.js("document.querySelector('#btn').click()")
        msg = wait_msg(ws, "#msg", prev, timeout=8.0)
        check("提示还差 3 位", "还差 3 位" in msg, msg)
        check("列表没多出条目", my_row(ws, TID2) == row2, my_row(ws, TID2))

        print("\n[9] 查询框和登记框是同一套方框（横线也自动带）")
        check("查询框也是 7 格", ws.js("document.querySelectorAll('#qcells .cell').length") == 7,
              ws.js("document.querySelectorAll('#qcells .cell').length"))
        check("查询框的横线也在中间那格", ws.js(
            "[...document.querySelector('#qcells').children].findIndex(e=>e.classList.contains('dash'))") == 4)
        type_keys(ws, fullwidth(TID.replace("-", "")), "qcells")
        check(f"查询框逐格输入后拼出 {TID}", ws.js("qry.id()") == TID, ws.js("qry.id()"))
        time.sleep(0.3)
        prev = msg_text(ws, "#qmsg")     # 打字也会先清提示
        ws.js("document.querySelector('#qbtn').click()")
        q = wait_msg(ws, "#qmsg", prev)
        check("查询结果显示次数与判定", TID in q and "已被登记" in q and "可疑ID" in q, q)

        print(f"\n[10] 查询没登记过的 ID（整串粘进第一格）：{TID3}")
        paste_id(ws, TID3, "qcells")
        time.sleep(0.3)
        prev = msg_text(ws, "#qmsg")
        check("粘进来的横线不算格子内容", cells_of(ws, "qcells") == TID3.replace("-", ""),
              repr(cells_of(ws, "qcells")))
        ws.js("document.querySelector('#qbtn').click()")
        q = wait_msg(ws, "#qmsg", prev)
        check("提示还没被登记过", "还没有被登记过" in q, q)

        print("\n[11] 查询框只填 3 位就点查询 → 前端拦住并说还差几位")
        clear_cells(ws, "qcells")
        type_keys(ws, "ZZZ", "qcells")
        ws.js("document.querySelector('#qbtn').click()")
        time.sleep(0.8)
        q = ws.js("document.querySelector('#qmsg').textContent")
        check("提示还差 4 位", "还差 4 位" in q, q)

        print("\n[12] 打字只走英文：可打印按键被页面自己接管（输入法不会被唤醒）")
        clear_cells(ws)
        ws.js("document.querySelectorAll('#idcells .cell')[0].focus()")
        ws.js("window.__ime=[];document.addEventListener('keydown',e=>{window.__ime.push([e.key,e.defaultPrevented])},false)")
        for key, code, vk in (("Q", "KeyQ", 81), ("7", "Digit7", 55)):
            ws.call("Input.dispatchKeyEvent", {"type": "keyDown", "key": key, "code": code,
                                              "text": key, "unmodifiedText": key,
                                              "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk})
        seen = ws.js("window.__ime")
        check("真实按键的默认行为都被页面拦下（输入法拿不到这些键）",
              bool(seen) and all(x[1] is True for x in seen), seen)
        check("按键直接落进格子并往后走", cells_of(ws)[:2] == "Q7", repr(cells_of(ws)))
        ws.js("""(() => { const c=document.querySelectorAll('#idcells .cell')[2]; c.focus();
                  c.value='中'; c.dispatchEvent(new Event('input',{bubbles:true})); return true })()""")
        check("万一输入法真塞进中文，格子会把它丢掉", cells_of(ws) == "Q7", repr(cells_of(ws)))
    finally:
        ws.close()
        try:
            requests.get(f"http://127.0.0.1:{CDP_PORT}/json/close/{tgt['id']}", timeout=5)
        except Exception:
            pass

    print(f"\n=== 结果: {len(OK)} 通过 / {len(FAIL)} 失败 ===")
    if FAIL:
        print("失败项: " + "; ".join(FAIL))
        sys.exit(1)


if __name__ == "__main__":
    main()
