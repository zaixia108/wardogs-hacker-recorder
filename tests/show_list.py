#!/usr/bin/env python3
"""看一眼公网页面上那几条数据的渲染（真浏览器，只读，不改数据）。

用法: python3 tests/show_list.py https://fxxkwghackers.zaixia108.com/
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser_test as bt   # 复用它的裸 CDP 小客户端


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "https://fxxkwghackers.zaixia108.com/"
    tab = bt.new_tab(base)
    ws = bt.WS(tab["webSocketDebuggerUrl"])
    try:
        time.sleep(1.5)
        rows = bt.rows_of(ws)
        stats = ws.js("[document.querySelector('#s-total').textContent,"
                      " document.querySelector('#s-cheat').textContent]")
        print("页面统计区 [总数, 外挂数, 阈值]:", stats)
        for i, line in enumerate(rows.split(" // "), 1):
            print(f"  第{i}行: {line}")
        # 查询框查一下外挂那个 ID
        msg = bt.do_query(ws, "2VDE-THE")
        print("查询 2VDE-THE 的提示:", msg)
    finally:
        ws.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
