#!/usr/bin/env python3
"""校验输入自动格式化：后端 format_id、前端 JS fmt()、以及真实 HTTP 登记接口三者行为一致。

用法: python3 tests/fmt_test.py [BASE_URL]
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)          # 仓库根目录，别写死绝对路径

sys.path.insert(0, ROOT)
import server  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8792"

# 这个测试会真的调用登记接口（而且用的是固定 ID），只许打本机的隔离实例。
# 想强行对别处跑：ALLOW_REMOTE=1
_host = urllib.parse.urlsplit(BASE).hostname or ""
if _host not in ("127.0.0.1", "localhost", "::1") and os.environ.get("ALLOW_REMOTE") != "1":
    print(f"[拒绝] {BASE} 不是本机地址。这个测试会往目标站写真实登记，"
          f"固定 ID 还会把别人的计数刷上去。\n"
          f"       要本机隔离实例（CI 就是这么跑的）；确实要跑：ALLOW_REMOTE=1 再执行。")
    sys.exit(2)
SRC = open(os.path.join(ROOT, "server.py"), encoding="utf-8").read()
# 测试实例的数据文件：CI 里是临时目录，本机默认就是仓库里那份
DATA = os.environ.get("SUSPECT_DATA", os.path.join(ROOT, "data.json"))

# 从 server.py 里原样抠出前端 fmt() 函数，保证测的就是线上那份 JS
m = re.search(r"function fmt\(s\)\{.*?\n\}", SRC, re.S)
assert m, "没有在 server.py 里找到前端 fmt() 函数"
JS_FMT = m.group(0)

CASES = [
    ("３QQN－０NH", "3QQN-0NH"),        # 全角数字+全角连字符（用户报的那种）
    ("２ＶＤＥ－ＴＨＥ", "2VDE-THE"),   # 全角字母/数字/连字符
    ("2vde-the", "2VDE-THE"),           # 普通小写
    ("2vde–the", "2VDE-THE"),           # en dash
    ("2vde—the", "2VDE-THE"),           # em dash
    ("2vde−the", "2VDE-THE"),           # 数学减号 U+2212
    ("2vde‐the", "2VDE-THE"),           # U+2010
    ("2vde‑the", "2VDE-THE"),           # U+2011 不换行连字符
    ("2vde\u200b-the", "2VDE-THE"),     # 零宽空格
    ("2vde\ufeff-the", "2VDE-THE"),     # BOM
    ("2vde\u00ad-the", "2VDE-THE"),     # 软连字符
    ("　2vde-the　", "2VDE-THE"),       # 全角空格包着
    ("  2vde   the  ", "2VDE THE"),     # 空白收敛
    ("  ", ""),                         # 纯空白 → 空
]

def check_backend():
    bad = []
    for raw, want in CASES:
        got = server.format_id(raw)
        if got != want:
            bad.append((raw, want, got))
    print(f"[后端 format_id] {len(CASES) - len(bad)}/{len(CASES)} 通过")
    for raw, want, got in bad:
        print(f"  ✗ {raw!r} 期望 {want!r} 实得 {got!r}")
    return not bad


def check_frontend():
    js = JS_FMT + "\nconst cases = " + json.dumps([[r, w] for r, w in CASES]) + ";\n"
    js += "let bad=0;\nfor(const [raw,want] of cases){const got=fmt(raw);"
    js += "if(got!==want){bad++;console.log('  ✗',JSON.stringify(raw),'期望',JSON.stringify(want),'实得',JSON.stringify(got));}}\n"
    js += "console.log('[前端 fmt()]', cases.length-bad+'/'+cases.length, '通过');process.exit(bad?1:0);\n"
    open("/tmp/fmt_test.js", "w", encoding="utf-8").write(js)
    try:
        node = subprocess.run(["node", "/tmp/fmt_test.js"], capture_output=True, text=True)
    except FileNotFoundError:
        print("[前端 fmt()] 跳过：本机没有 node")
        return None
    if node.returncode not in (0, 1):
        print("[前端 fmt()] 跳过：", (node.stderr or "").strip()[:200] or "node 不可用")
        return None
    print(node.stdout.strip())
    return node.returncode == 0


_n = [0]


_RUN = f"{os.getpid()}{int(time.time())}"   # 每次运行都不同，免得撞上「只能登记一次」的去重


def post(raw):
    """每次换一个身份（不带 cookie + 不同指纹），否则会被「同一浏览器只能登记一次」拦掉。"""
    _n[0] += 1
    req = urllib.request.Request(
        BASE + "/api/register",
        json.dumps({"id": raw, "fp": f"fmt-test-{_RUN}-{_n[0]:04d}-abcdefgh"}).encode(),
        {"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def check_http():
    ok = True
    # 同一个人的多种全角/半角写法必须归到同一条，且显示全半角正确
    variants = ["３QQN－０NH", "3QQN-0NH", "2vde–the", "２ＶＤＥ－ＴＨＥ"]
    seen = {}
    for v in variants:
        d = post(v)
        seen[v] = (d["id"], d["count"])
        print(f"  登记 {v!r:22} → 显示 {d['id']!r:12} 第 {d['count']} 次")
    # 前两个应归到同一条、第二次数比第一次多 1；后两个同理。
    # 用「相对 +1」而不是写死 1/2：同一个实例上反复跑也说得通。
    if seen["３QQN－０NH"][0] != "3QQN-0NH" or seen["3QQN-0NH"][1] != seen["３QQN－０NH"][1] + 1:
        ok = False
        print("  ✗ 全角/半角没有归到同一条")
    if seen["2vde–the"][0] != "2VDE-THE" or seen["２ＶＤＥ－ＴＨＥ"][1] != seen["2vde–the"][1] + 1:
        ok = False
        print("  ✗ en dash / 全角写法没有归到同一条")
    # 入库的值必须已经是格式化后的（存盘文件里不该出现全角）
    if not os.path.exists(DATA):
        print(f"  · 没找到数据文件 {DATA}，落盘检查跳过（想查就把 SUSPECT_DATA 指对）")
    else:
        data = open(DATA, encoding="utf-8").read()
        for bad in ["３", "Ｑ", "－", "–", "\u200b"]:
            if bad in data:
                ok = False
                print(f"  ✗ 落盘数据里仍残留 {bad!r}")
    if ok:
        print("[HTTP] 登记接口 + 落盘数据 全部通过")
    return ok


if __name__ == "__main__":
    r1 = check_backend()
    r2 = check_frontend()
    print(f"[目标] {BASE}")
    r3 = check_http()
    sys.exit(0 if (r1 and r3 and r2 is not False) else 1)
