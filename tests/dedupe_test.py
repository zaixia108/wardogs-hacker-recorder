#!/usr/bin/env python3
"""身份去重测试：同一个浏览器（cookie / 指纹）对同一个 ID 只能登记一次。

默认自己拉起一个隔离实例（8793 端口 + /tmp 下的数据文件与密钥）跑全流程，不动线上数据：
    /usr/bin/python3 tests/dedupe_test.py
对着已有站点跑（只登记 DEDA-*/DEDB-* 这类测试 ID，跑完记得用 tests/prune_testdata.py 清）：
    /usr/bin/python3 tests/dedupe_test.py --base https://fxxkwghackers.zaixia108.com
"""
from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(os.path.dirname(HERE), "server.py")
TMP_DATA = "/tmp/dedup-test.json"
TMP_SECRET = "/tmp/dedup-test.secret"
PORT = 8793

OK, FAIL = [], []


def check(name: str, cond: bool, detail: str = "") -> None:
    (OK if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")


class Browser:
    """一个「浏览器」：有 cookie 罐子 + 一个指纹。"""

    def __init__(self, base: str, fp: str | None = None, cookie: str | None = None):
        self.base = base
        self.fp = fp
        self.cookie = cookie            # 形如 "sid=xxx.yyy"
        self.last_set_cookie = None

    def _conn(self):
        u = urllib.parse.urlparse(self.base)
        return http.client.HTTPConnection(u.hostname, u.port or 80, timeout=15)

    def req(self, method: str, path: str, body: dict | None = None,
            cookie: str | None = None, fp: str | None = None):
        c = self._conn()
        headers = {}
        use = self.cookie if cookie is None else cookie
        if use:
            headers["Cookie"] = use
        data = None
        if body is not None:
            body = dict(body)
            if fp is None and self.fp is not None:
                body.setdefault("fp", self.fp)
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        raw = r.read().decode()
        sc = r.getheader("Set-Cookie")
        if sc:
            self.last_set_cookie = sc
            self.cookie = sc.split(";")[0]
        c.close()
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"_raw": raw}
        return r.status, parsed

    def register(self, i: str, **kw):
        return self.req("POST", "/api/register", {"id": i}, **kw)


def run(base: str, data_file: str | None) -> None:
    print(f"\n=== 身份去重测试 @ {base} ===")
    ID = "DEDA-AAA"
    ID2 = "DEDB-BBB"

    A = Browser(base, fp="fpA-aaaaaaaaaaaaaaaa")
    print("\n[1] 首次访问是否签发身份 cookie")
    st, _ = A.req("GET", "/")
    check("GET / 放 Set-Cookie", bool(A.last_set_cookie), A.last_set_cookie or "无")
    sc = A.last_set_cookie or ""
    check("cookie 带 HttpOnly", "HttpOnly" in sc)
    check("cookie 带 SameSite=Lax", "SameSite=Lax" in sc)
    check("cookie 带 Path=/", "Path=/" in sc)
    check("cookie 带 2 年有效期", "Max-Age=63072000" in sc)
    check("cookie 值是 <32位hex>.<签名>", bool(re.fullmatch(r"sid=[0-9a-f]{32}\.[0-9a-f]{20}.*", sc)))

    print("\n[2] 同一个浏览器第一次登记 → 成功")
    st, d = A.register(ID)
    check("HTTP 200", st == 200, f"实际 {st} {d}")
    check("count=1", d.get("count") == 1, str(d))

    print("\n[3] 同一个浏览器再登记同一个 ID → 拒绝，且计数不变")
    st, d = A.register(ID)
    check("HTTP 409", st == 409, f"实际 {st}")
    check("标记 dup=true", d.get("dup") is True, str(d))
    check("提示文案", "已经登记过" in (d.get("error") or ""), d.get("error") or "")

    print("\n[4] 换 cookie 但指纹一样（模拟清 cookie）→ 仍然拒绝")
    B = Browser(base, fp="fpA-aaaaaaaaaaaaaaaa")
    st, _ = B.req("GET", "/")                      # 拿到自己的新 cookie
    check("B 拿到了不同的 cookie", B.cookie != A.cookie)
    st, d = B.register(ID)
    check("HTTP 409", st == 409, f"实际 {st} {d}")

    print("\n[5] 换浏览器（cookie + 指纹都不同）→ 可以登记，计数上涨")
    C = Browser(base, fp="fpC-cccccccccccccccc")
    C.req("GET", "/")
    st, d = C.register(ID)
    check("HTTP 200", st == 200, f"实际 {st} {d}")
    check("count=2", d.get("count") == 2, str(d))

    print("\n[6] 伪造/篡改 cookie → 服务端不认，当新浏览器并重发 cookie")
    F = Browser(base, fp="fpF-ffffffffffffffff")
    forged = "sid=" + "a" * 32 + ".deadbeefdeadbeefdead"
    st, d = F.register(ID, cookie=forged)
    check("HTTP 200（伪造 cookie 没被当成本人）", st == 200, f"实际 {st} {d}")
    check("响应里重发了 cookie", bool(F.last_set_cookie))
    check("count=3", d.get("count") == 3, str(d))
    # 用刚拿到的真 cookie + 同指纹再登记 → 应被拒
    st, d = F.register(ID)
    check("拿真 cookie 再来 → 409", st == 409, f"实际 {st} {d}")

    print("\n[7] 不带指纹（禁用 JS 的场景）也能靠 cookie 去重")
    D = Browser(base, fp=None)
    D.req("GET", "/")
    st, d = D.register(ID2)
    check("HTTP 200", st == 200, f"实际 {st} {d}")
    st, d = D.register(ID2)
    check("同 cookie 再来 → 409", st == 409)

    print("\n[8] 同一身份对不同 ID 各能登记一次（只在「同一 ID」上去重）")
    st, d = A.register(ID2)
    check("A 登记另一个 ID → 200", st == 200, f"实际 {st} {d}")

    print("\n[9] 指纹原文 / cookie 原文没有落盘")
    if data_file and os.path.exists(data_file):
        blob = open(data_file, encoding="utf-8").read()
        check("data.json 里没有 fpA- 原文", "fpA-" not in blob)
        check("data.json 里没有指纹字段名", '"fp"' not in blob)
        ids = json.loads(blob).get("ids", {})
        rec = ids.get(ID.lower(), {})
        check("voters 是加盐哈希(16位hex)", all(re.fullmatch(r"[0-9a-f]{16}", v) for v in rec.get("voters", [])),
              str(rec.get("voters")))
        check("voters 数量 == count×2（cookie+指纹两条令牌）",
              len(rec.get("voters", [])) == rec.get("count", -1) * 2, str(rec))
    else:
        print("  (跳过：没有本地数据文件)")

    print(f"\n=== 结果: {len(OK)} 通过 / {len(FAIL)} 失败 ===")
    if FAIL:
        print("失败项: " + "; ".join(FAIL))
        sys.exit(1)


def main() -> None:
    if "--base" in sys.argv:
        base = sys.argv[sys.argv.index("--base") + 1]
        run(base, None)
        return
    base = f"http://127.0.0.1:{PORT}"
    for f in (TMP_DATA, TMP_SECRET):
        if os.path.exists(f):
            os.remove(f)
    env = dict(os.environ, PORT=str(PORT), HOST="127.0.0.1",
               SUSPECT_DATA=TMP_DATA, SUSPECT_SECRET=TMP_SECRET)
    proc = subprocess.Popen([sys.executable, SERVER], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):                      # 等实例就绪
            time.sleep(0.25)
            try:
                b = Browser(base)
                if b.req("GET", "/healthz")[0] == 200:
                    break
            except Exception:
                pass
        run(base, TMP_DATA)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        for f in (TMP_DATA, TMP_SECRET):
            if os.path.exists(f):
                os.remove(f)


if __name__ == "__main__":
    main()
