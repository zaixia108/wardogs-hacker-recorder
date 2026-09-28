#!/usr/bin/env python3
"""按指定次数把「登记数」直接写到位（给已知的外挂/可疑 ID 落数据）。

登记数 = 不同身份（sid cookie / 浏览器指纹的哈希）的个数。所以补次数时要连占位身份凭证
一起补上：不然数字是写进去了，真人再来登记还是从旧数字往上加、去重也拦不住同一个浏览器。

用法:
    python3 seed_counts.py                      # 落下面 SPEC 里那组
    python3 seed_counts.py '2VDE-THE=32'        # 也可以临时指定

改文件前会先备份成 data.json.bak-<时间戳>；跑之前请先停服务（systemctl stop suspect-id），
不然运行中的进程会拿内存里的旧状态覆盖回去。
"""
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.environ.get("SUSPECT_DATA", os.path.join(HERE, "data.json"))

# 用户给的登记次数（展示层统一全大写）
SPEC = {
    "2VDE-THE": 32,   # > 20 → 外挂
    "3QQN-0NH": 18,
    "0KRA-ZFH": 6,
    "ONDJ-3F2": 15,
}


def disp(name: str) -> str:
    return name.strip().upper()


def dummy(key: str, i: int) -> str:
    """占位身份凭证：长得跟真身份哈希一样，但是确定可复现的。"""
    return hashlib.sha256(f"seed|{key}|{i}".encode()).hexdigest()


def main(argv):
    spec = dict(SPEC)
    for arg in argv:
        if "=" in arg:
            k, v = arg.split("=", 1)
            spec[k] = int(v)

    if not os.path.exists(DATA_FILE):
        print("没有数据文件:", DATA_FILE)
        return 1

    with open(DATA_FILE, encoding="utf-8") as fp:
        state = json.load(fp)
    ids = state.setdefault("ids", {})

    bak = DATA_FILE + time.strftime(".bak-%Y%m%d-%H%M%S")
    with open(bak, "w", encoding="utf-8") as fp:
        json.dump(state, fp, ensure_ascii=False, indent=1)

    now = time.time()
    for name, target in spec.items():
        key = name.strip().lower()
        rec = ids.get(key)
        if rec is None:
            rec = {"display": disp(name), "count": 0, "first": now, "last": now, "voters": []}
            ids[key] = rec
        voters = rec.setdefault("voters", [])
        have = len(voters)
        rec["display"] = disp(name)
        rec["count"] = int(target)
        rec["last"] = now
        if target > have:
            for i in range(have, target):
                voters.append(dummy(key, i))
            print(f"  {disp(name)}: 登记数 {target}（原有身份 {have}，补占位身份 {target - have}）")
        else:
            print(f"  {disp(name)}: 登记数 {target}（原有身份 {have} 已够用，不再补）")

    with open(DATA_FILE, "w", encoding="utf-8") as fp:
        json.dump(state, fp, ensure_ascii=False, indent=1)
    print("已写入:", DATA_FILE)
    print("备份:", bak, "· 现在共", len(ids), "条")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
