#!/usr/bin/env python3
"""体检 data.json：列出条目、检查 voters 全是加盐哈希、检查有没有全角/怪字符残留。

用法: /usr/bin/python3 tests/inspect_data.py [data.json 路径]
"""
import json
import re
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "/root/suspect-id/data.json"
blob = open(PATH, encoding="utf-8").read()
d = json.loads(blob)
ids = d.get("ids", {})
TH = int(d.get("threshold", 20))
print(f"阈值 {TH} · 共 {len(ids)} 条 · 外挂 {sum(1 for v in ids.values() if int(v.get('count', 0)) > TH)} 个")
for key, v in sorted(ids.items(), key=lambda kv: -int(kv[1].get("count", 0))):
    vs = v.get("voters", [])
    hashes_ok = all(re.fullmatch(r"[0-9a-f]{16}", x) for x in vs)
    flag = "" if int(v.get("count", 0)) <= TH else "  ← 外挂"
    print(f"  {str(v.get('display')):14} count={v.get('count'):<3} voters={len(vs):<3} "
          f"哈希合法={hashes_ok}{flag}")
junk = {c: blob.count(c) for c in "３ＱＮ－–—　\u200b\ufeff" if c in blob}
print("残留全角/怪字符:", junk if junk else "无")
print("有没有明文指纹字段:", "有(!)" if '"fp"' in blob else "无")
