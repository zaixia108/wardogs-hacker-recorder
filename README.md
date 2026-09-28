# 可疑ID 登记处（WARDOGS Hacker Recorder）

一个单文件的小网站：**输入一串 ID 就把它登记为「可疑 ID」；同一个 ID 被登记超过 20 次，自动判定为「外挂」。**

线上：<https://fxxkwghackers.zaixia108.com/>

- 纯 Python 标准库，零依赖，一个 `server.py` 就是全部（HTTP 服务 + 页面 + API）
- 前端也是自带的一页：HTML/CSS/JS 全在 `server.py` 里，没有构建步骤
- 数据就一个 `data.json`，删掉等于清空
- 写入是**故意公开**的 —— 这个站就是给大家登记、给大家看的，不加口令、不加验证码

## 给 WARDOGS 做的

这是给 **WARDOGS** 玩家用的站：BULKHEAD 开发、Team17 发行，最多 100 人分三阵营
（Lonestar / Valkyra / Manticore）抢 2×2 km 的 Control Zone，每 30 秒记一分、先到 100 分取胜，
每人起始 $10,000、装备现买现用，官方反作弊是内核级的 **Elytra**。这游戏**不给敌人标记**，
所以「隔墙点名」这种事只能靠玩家自己看见、自己对上号 —— 也就是这个站存在的原因。

页面上的 WARDOGS 元素（纯外观与说明，不影响登记/查询逻辑，也没加任何新字段）：

- **顶部状态条**：`WARDOGS · ALL-OUT WARFARE` / `SECTOR KAVKAZI` / `3 阵营 · 100 人` / `CONTROL ZONE 2×2 KM` / `◆ STATUS: ONLINE`
- **标题与简报**：把「登记一次 = 一次怀疑，超过 20 次判外挂」跟游戏的记分规则摆在一起讲
- **卡片标签**：`// 目标 ID · TARGET`、`// 查询登记次数 · QUERY`；列表上方 `// 战场记录 · FIELD LOG`
- **列表**：超阈值的行盖一个 `CHEATER` 印章、进度条转红；阈值那格写成 `36 / 20`
- **页脚**：`// 战场笔记 · FIELD NOTES`（三条抓挂经验）+ 关于 WARDOGS 与官方举报渠道的说明
- **配色**：暗橄榄底 `#0b0e08` + 军用琥珀 `#e0a91b` + 血红旗标 `#e5484d`；HUD 直角边框、
  顶部警戒条、细网格背景，标签一律等宽大写带字距；`<title>` 与 favicon（军牌形状）也换成了这个味道

**免责**：本站是玩家自建的公共登记本，与 BULKHEAD、Team17 无关联，未获其背书；
WARDOGS 及相关名称与商标归其各自所有者。判定「外挂」只看登记次数，**不等于官方结论** ——
真正的举报请走游戏内 Report（官方页面 <https://www.wardogs.com/enforcement>）。

## 跑起来

```bash
PORT=8792 python3 server.py            # 默认 0.0.0.0:8792
# 或者用 systemd（见下面的部署）
```

环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `8792` | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址。反代后面就设 `127.0.0.1` |
| `SUSPECT_DATA` | `./data.json` | 数据文件路径 |
| `SUSPECT_SECRET` | 无 | 身份哈希的盐；不给就首次运行生成 `.secret`（0600） |

## 规则

- **ID 格式严格 7 位**：`^[A-Z0-9]{4}-[A-Z0-9]{3}$`（4 位字母/数字 + `-` + 3 位字母/数字，如 `2VDE-THE`）。
  不合规**直接拒绝**，不登记、不落盘。前端先拦一次，后端 `register()` 再拦一次，用的是同一条正则。
- **阈值 20**：`count > 20`（也就是第 21 次登记）判「外挂」。常量在 `server.py` 的 `THRESHOLD`。
- **展示只显示全大写的 ID**，不显示任何名字。
- **输入自动格式化**（前后端同一套规则：后端 `format_id()`，页面里 `fmt()`）：
  全角→半角（`３QQN－０NH` → `3QQN-0NH`）、各种横杠统一成 `-`（`‐ ‑ ‒ – — ― − －`）、
  零宽/软连字符删掉、空白收敛、统一转大写。同一个人的不同写法会归到同一条记录上。
- **登记框和查询框是同一套 7 个方框**：4 格 + 中间自动带上的 `-` + 3 格。
  横线不用手打（敲 `-` 只跳到下一格），整串粘进第 1 格会往后铺、当场归一；填满自动跳格、退格回上一格。
  两个框共用同一个 `boxInputs()`，只差提交时调 `submit()` 还是 `query()`。
- **只收英文数字，不弹输入法**：可打印按键在 `keydown` 阶段就被页面自己接管（`e.preventDefault()` + 手动填格），
  输入法拿不到这个键、候选窗不会弹；手机上每格带 `inputmode=latin`；
  万一被塞进中文/全角，`fmt()` 那一路会归一或整格丢掉（`Ctrl/Cmd+C/V/A` 照旧交给浏览器）。

## 登记去重（一个浏览器对一个 ID 只算一次）

两条腿，任一命中就拦（返回 `409 {"dup": true}`，不计数）：

1. **服务端签发的身份 cookie**：`sid = <32位随机hex>.<HMAC签名>`，HttpOnly / SameSite=Lax / 2 年。
   签名密钥在 `.secret`（0600，首次运行自动生成；删了等于把所有人重置成新浏览器）。
2. **浏览器指纹**：页面里 `fingerprint()` 把 UA / 平台 / 语言 / 屏幕 / 时区 / canvas 渲染 / WebGL 型号 / CPU 核数
   等搓成 16 位哈希，清 cookie 也认得出同一个浏览器。

落盘只存 `hmac(密钥, "c:"+sid)` 和 `hmac(密钥, "f:"+指纹)` 的 16 位哈希 —— 原始 cookie 和指纹原文不留存。

所以 `count` 的准确含义是「**有多少个不同浏览器登记过它**」，第 21 个浏览器登记才判外挂。
要放行某个浏览器：停服务后编辑 `data.json`，从那个 ID 的 `voters` 里删掉对应哈希。

## 给已知 ID 直接落登记数

`seed_counts.py` —— 补的次数会**同时补等量的占位身份凭证**，因为 `count` = 不同身份数：只改数字的话，
真人再来登记还是会从旧数字往上加、同一浏览器也拦不住。

```bash
systemctl stop suspect-id                       # 必须先停：运行中的进程会用内存里的旧状态覆盖文件
python3 seed_counts.py                          # 用脚本里那组默认值
python3 seed_counts.py '2VDE-THE=32' 'XXXX-XXX=7'   # 也可以临时指定
systemctl start suspect-id
```

改文件前会自动备份成 `data.json.bak-<时间戳>`。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/register` | body `{"id": "xxx", "fp": "<指纹>"}`；`fp` 可省（省了只靠 cookie 去重）。成功返回当前次数与是否外挂；重复登记返回 409 |
| `GET` | `/api/list` | `{"threshold":20,"total":N,"cheaters":M,"list":[{"id","count","cheater"}...]}`，按次数从高到低 |
| `GET` | `/api/query?id=XXX` | 查一个 ID 被登记了多少次、是否已判外挂 |
| `GET` | `/healthz` | 存活探针 |

## 部署

服务器上是 systemd + nginx 反代，`/etc/systemd/system/suspect-id.service`：

```ini
[Unit]
Description=可疑ID 登记处
After=network.target

[Service]
Environment=HOST=127.0.0.1
Environment=PORT=8792
WorkingDirectory=/root/suspect-id
ExecStart=/usr/bin/python3 /root/suspect-id/server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

nginx（宝塔面板的话放 `/www/server/panel/vhost/nginx/` 下）：

```nginx
server {
    listen 80 default_server;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:8792;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 自动部署（GitHub Actions）

`.github/workflows/deploy.yml`：合进 `main` 就自动推代码上线，也可以在 Actions 页面手动触发。
`deploy/deploy.sh` 只送**代码**（`server.py`、`seed_counts.py`、`README.md`、`tests/*.py`），
`data.json` 和 `.secret` 一律不碰 —— 覆盖了等于把大家的登记记录清空。
脚本还会在部署前后各记一次线上登记条数，条数变少就直接判失败，免得哪天手滑把数据冲了。

仓库里要配 3 个 secret（Settings → Secrets and variables → Actions）：

| Secret | 说明 |
|---|---|
| `DEPLOY_HOST` | 服务器 IP / 域名 |
| `DEPLOY_USER` | SSH 用户名 |
| `DEPLOY_SSH_KEY` | 部署私钥（公钥加到服务器的 `~/.ssh/authorized_keys`）。配成专用 key，别用你的登录密码 |

可选 `SITE_URL`（默认 `https://fxxkwghackers.zaixia108.com/`）—— 部署完会从外网拉首页和 `/api/list` 复查一遍，
页面 200 且接口阈值/条数正常才算成功。

## 回归测试

| 命令 | 说明 |
|---|---|
| `python3 tests/fmt_test.py [URL]` | 14 组全角/横杠格式用例 + 归并 + 落盘检查（前端 JS 部分需 node）。**只打本机隔离实例**：它会真的调登记接口，对着线上跑会把别人的计数刷上去 —— 传给非本机地址会被直接拒绝（真要对别处跑得设 `ALLOW_REMOTE=1`） |
| `python3 tests/strict_test.py [--base URL]` | 严格 7 位格式 + 查询接口 + 页面结构 30 项（默认自起 8796 隔离实例） |
| `python3 tests/dedupe_test.py [--base URL]` | 身份去重 26 项断言（默认自起 8793 隔离实例） |
| `python3 tests/browser_test.py [--base URL] [--port N]` | 真浏览器端到端 34 项（裸 CDP，需 `chromium --headless=new --remote-debugging-port=9222`） |
| `python3 tests/look.py [URL]` | 只看排版：量方框尺寸、横线位置、行序 |
| `python3 tests/show_list.py [URL]` | 只看列表渲染出来的文字（只读，不改数据） |

`browser_test.py` 每次跑用随机 ID（前缀 `TSTX`），所以能连着跑、不跟上一轮残留撞车；
`tests/prune_testdata.py` 按前缀清掉这些假数据（要先停服务）；
「计数没涨」这类断言只比我自己那一行，不受线上真人同时登记的影响。

前三个跑在隔离实例上，CI（`.github/workflows/tests.yml`）里就是它们；真浏览器那条要 chromium，在本机跑。
