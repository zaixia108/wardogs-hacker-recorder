#!/usr/bin/env python3
"""严格 7 位格式 + 查询接口测试。

默认自起一个隔离实例（8796 端口 + /tmp 下临时文件），不动线上数据：
    /usr/bin/python3 tests/strict_test.py
对已上线站点跑：
    /usr/bin/python3 tests/strict_test.py --base https://fxxkwghackers.zaixia108.com

覆盖：后端 ID_RE / 前端 ID_RE（node 真跑）判定一致 · 非法格式被拒且不落盘 ·
合法格式（含全角、小写、怪横杠）被接受 · /api/query 的已登记/未登记/非法三种情况 ·
页面文案与控件（查询按钮、maxlength=8）。
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(os.path.dirname(HERE), "server.py")
TMP_DATA = "/tmp/strict-test.json"
TMP_SECRET = "/tmp/strict-test.secret"
PORT = 8796

# (输入, 是否合法)
VALID = ["2VDE-THE", "3QQN-0NH", "ab12-cd3", "０ＫＲＡ－ＺＦＨ", "　2vde-the　", "2vde–the", "１２３４－５６７"]
INVALID = ["", "2VDE-TH", "2VDE-THEE", "2VDETHE", "2VDE_THE", "2VDE THE", "2VDE - THE",
           "中文ID-123", "ABCDEFG", "-X", "2VDE-THE!", "2VDE-TH3-X"]

OK, FAIL = [], []


def check(name: str, cond: bool, detail: str = "") -> None:
    (OK if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")


def client(base: str):
    u = urllib.parse.urlparse(base)
    return lambda m, p, body=None: _req(u, m, p, body)


def _req(u, method: str, path: str, body: dict | None = None):
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=15)
    data, headers = None, {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    raw = r.read().decode()
    c.close()
    try:
        return r.status, json.loads(raw), raw
    except Exception:
        return r.status, {}, raw


def load_server_module():
    """直接 import 服务的源码，测它真正的 ID_RE / format_id。"""
    os.environ.setdefault("SUSPECT_SECRET", "/tmp/strict-import.secret")
    spec = importlib.util.spec_from_file_location("suspect_server", SERVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(base: str, data_file: str | None) -> None:
    import re as _re
    print(f"\n=== 严格 7 位格式 + 查询接口 @ {base} ===")
    req = client(base)
    mod = load_server_module()

    print("\n[1] 后端：合法/非法一览")
    bad = [v for v in VALID if not mod.ID_RE.fullmatch(mod.format_id(v))]
    check(f"{len(VALID)} 个合法输入全通过", not bad, f"被误判: {bad}")
    bad2 = [v for v in INVALID if mod.ID_RE.fullmatch(mod.format_id(v))]
    check(f"{len(INVALID)} 个非法输入全拒绝", not bad2, f"被放过: {bad2}")
    check("全角 ０ＫＲＡ－ＺＦＨ → 0KRA-ZFH", mod.format_id("０ＫＲＡ－ＺＦＨ") == "0KRA-ZFH", mod.format_id("０ＫＲＡ－ＺＦＨ"))
    check("１２３４－５６７ → 1234-567（数字也合法）", mod.format_id("１２３４－５６７") == "1234-567")

    print("\n[2] 前端：页面里的 ID_RE 与后端判定一致（node 真跑）")
    st, _, html = _req(urllib.parse.urlparse(base), "GET", "/")
    m = _re.search(r"const ID_RE = /(.+?)/;", html)
    check("页面里存在 ID_RE", bool(m), m.group(1) if m else "没抠到")
    if m:
        try:
            cases = [(mod.format_id(v), True) for v in VALID] + [(mod.format_id(v), False) for v in INVALID]
            js = ("const RE = new RegExp(" + json.dumps(m.group(1)) + ");\n"
                  "const cases = " + json.dumps(cases) + ";\n"
                  "let bad = 0;\n"
                  "for (const [s, want] of cases) { if (RE.test(s) !== want) { bad++;"
                  " console.log(' 不一致:', JSON.stringify(s), want); } }\n"
                  "console.log('[前端 ID_RE]', cases.length - bad + '/' + cases.length, '通过');\n"
                  "process.exit(bad ? 1 : 0);\n")
            p = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=30)
            check("node 跑前端正则全部一致", p.returncode == 0, (p.stdout + p.stderr).strip()[-200:])
        except FileNotFoundError:
            print("  (跳过：本机没有 node)")

    print("\n[3] HTTP：非法格式 → 400，且没落盘")
    st, lst, _ = req("GET", "/api/list")
    total_before = lst.get("total")
    st, d, _ = req("POST", "/api/register", {"id": "2VDE-THEE", "fp": "strict-fp-0001-aaaaaaaa"})
    check("太长 → 400", st == 400, f"实际 {st} {d}")
    check("error 有提示 7 位", "7 位" in (d.get("error") or ""), d.get("error") or "")
    st, d, _ = req("POST", "/api/register", {"id": "2VDETHE", "fp": "strict-fp-0002-aaaaaaaa"})
    check("缺横杠 → 400", st == 400, f"实际 {st} {d}")
    st, d, _ = req("POST", "/api/register", {"id": "2VDE_THE", "fp": "strict-fp-0003-aaaaaaaa"})
    check("下划线 → 400", st == 400, f"实际 {st} {d}")
    st, d, _ = req("POST", "/api/register", {"id": "", "fp": "strict-fp-0004-aaaaaaaa"})
    check("空 → 400", st == 400, f"实际 {st} {d}")
    st, lst, _ = req("GET", "/api/list")
    check("列表里没被塞进垃圾条目", lst.get("total") == total_before, f"前后 total: {total_before} → {lst.get('total')}")

    print("\n[4] HTTP：合法格式（全角/小写/怪横杠）→ 200 且归一")
    st, d, _ = req("POST", "/api/register", {"id": "０ＳＲＴ－ＡＡＡ", "fp": "strict-fp-0010-aaaaaaaa"})
    check("全角 → 200 且显示 0SRT-AAA", st == 200 and d.get("id") == "0SRT-AAA", f"{st} {d}")
    st, d, _ = req("POST", "/api/register", {"id": "2vde—the", "fp": "strict-fp-0011-aaaaaaaa"})
    check("em dash → 200 且显示 2VDE-THE", st == 200 and d.get("id") == "2VDE-THE", f"{st} {d}")
    st, d, _ = req("POST", "/api/register", {"id": "０ＳＲＴ－ＣＣＣ", "fp": "strict-fp-0012-aaaaaaaa"})
    check("全角数字字母 → 200 且显示 0SRT-CCC", st == 200 and d.get("id") == "0SRT-CCC", f"{st} {d}")

    print("\n[5] /api/query 查询接口")
    st, d, _ = req("GET", "/api/query?id=0SRT-AAA")
    check("已登记 → found:true", st == 200 and d.get("found") is True, f"{st} {d}")
    check("次数=1", d.get("count") == 1, str(d))
    check("带阈值字段", d.get("threshold") == 20, str(d))
    st, d, _ = req("GET", "/api/query?id=" + urllib.parse.quote("０ＳＲＴ－ＡＡＡ"))
    check("全角查询也能查到同一条", st == 200 and d.get("found") is True and d.get("id") == "0SRT-AAA", f"{st} {d}")
    st, d, _ = req("GET", "/api/query?id=ZZZZ-ZZZ")
    check("没登记过 → found:false", st == 200 and d.get("found") is False, f"{st} {d}")
    st, d, _ = req("GET", "/api/query?id=BAD-ID")
    check("格式不对 → 400", st == 400, f"实际 {st} {d}")
    st, d, _ = req("GET", "/api/query")
    check("不带参数 → 400", st == 400, f"实际 {st} {d}")

    print("\n[6] 页面文案与控件")
    check("页面上没有「只能登记一次」这句文案", "只能登记一次" not in html)
    check("登记框和查询框都是 7 个方框", html.count('class="cell"') == 14, str(html.count('class="cell"')))
    check("两个框各有一根自动带的横线", html.count('class="dash"') == 2, str(html.count('class="dash"')))
    check("查询按钮在", 'id="qbtn"' in html)
    check("旧的单框输入已不存在", 'id="idbox"' not in html and 'id="qbox"' not in html)
    check("查询窗口排在登记下面、列表上面",
          html.index('id="idcells"') < html.index('id="qcells"') < html.index('id="list"'))
    check("不用手打横线（页面有说明）", "横线" in html or "自动" in html)
    check("手机上给的是拉丁键盘、不给输入法机会", html.count('inputmode="latin"') == 14,
          str(html.count('inputmode="latin"')))

    print(f"\n=== 结果: {len(OK)} 通过 / {len(FAIL)} 失败 ===")
    if FAIL:
        print("失败项: " + "; ".join(FAIL))
        sys.exit(1)


def main() -> None:
    if "--base" in sys.argv:
        run(sys.argv[sys.argv.index("--base") + 1].rstrip("/"), None)
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
        for _ in range(40):
            time.sleep(0.25)
            try:
                if _req(urllib.parse.urlparse(base), "GET", "/healthz")[0] == 200:
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
