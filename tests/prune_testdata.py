#!/usr/bin/env python3
"""只在服务器上删掉小庄做测试产生的那几条，保留用户自己登记的。

必须先 `systemctl stop suspect-id` 再跑（否则服务内存里的旧状态会盖回文件），跑完再 start。
"""
import json

PATH = "/root/suspect-id/data.json"
PREFIXES = ("tstx",)   # 只清小庄回归测试用的随机 ID；3qqn/2vde/0srt 等现在是正式数据，不能删了
MINE = {k for k in json.load(open(PATH, encoding="utf-8"))["ids"] if k[:4] in PREFIXES}

d = json.load(open(PATH, encoding="utf-8"))
before = list(d["ids"])
for k in MINE:
    d["ids"].pop(k, None)
with open(PATH, "w", encoding="utf-8") as f:
    json.dump(d, f, ensure_ascii=False, indent=1)
print("已删除(小庄的测试数据):", [k for k in before if k in MINE])
print("保留:", [(k, d["ids"][k]["count"]) for k in d["ids"]])
