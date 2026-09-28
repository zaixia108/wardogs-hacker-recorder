#!/usr/bin/env python3
"""看一眼公网页面的实际排版（格子是不是方框、横线位置、查询行是否在列表上面）。"""
import json
import sys
import time
import urllib.request

sys.path.insert(0, "/root/suspect-id/tests")
import browser_test as bt   # 复用它的裸 CDP 客户端

URL = sys.argv[1] if len(sys.argv) > 1 else "https://fxxkwghackers.zaixia108.com/"
tab = [t for t in json.load(urllib.request.urlopen("http://127.0.0.1:9222/json")) if t["type"] == "page"][0]
ws = bt.WS(tab["webSocketDebuggerUrl"])
ws.call("Page.enable")
ws.call("Page.navigate", {"url": URL})
time.sleep(2.5)

print("页面文字：")
print(ws.js("document.body.innerText").strip())
print("\n各元素尺寸 / 位置：")
print(ws.js("""[...document.querySelectorAll('#idcells .cell, #idcells .dash, #btn, #qcells .cell, #qcells .dash, #qbtn, #list')]
 .map(e => { const r = e.getBoundingClientRect();
             return (e.id || e.className) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height)
                    + ' x=' + Math.round(r.left) + ' y=' + Math.round(r.top); }).join('\\n')"""))
print("\n空格子时输入框是否被边框框住：")
print(ws.js("""(() => { const c = document.querySelector('#idcells .cell'); const s = getComputedStyle(c);
 return '边框 ' + s.borderTopWidth + ' ' + s.borderTopColor + ' / 圆角 ' + s.borderRadius
        + ' / 聚焦色 ' + getComputedStyle(document.querySelector('#idcells .dash')).color; })()"""))
ws.close()
