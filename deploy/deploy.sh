#!/usr/bin/env bash
# 把站点的代码送到服务器并重启服务 —— CI（GitHub Actions）和本机都能用。
#
# 需要的环境变量:
#   DEPLOY_HOST  服务器 IP / 域名
#   DEPLOY_USER  SSH 用户名（默认 root）
#   DEPLOY_KEY   私钥文件路径（默认 ~/.ssh/id_ed25519）
#   DEPLOY_PORT  SSH 端口（默认 22）
#   APP_DIR      远端目录（默认 /root/suspect-id）
#
# 只送代码。data.json（真人登记的数据）和 .secret 一律不碰 —— 覆盖了等于把大家的登记记录清空。
set -euo pipefail

HOST="${DEPLOY_HOST:?要设 DEPLOY_HOST}"
USER_="${DEPLOY_USER:-root}"
PORT="${DEPLOY_PORT:-22}"
APP_DIR="${APP_DIR:-/root/suspect-id}"
KEY="${DEPLOY_KEY:-$HOME/.ssh/id_ed25519}"

SSH=(ssh -i "$KEY" -p "$PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o BatchMode=yes "$USER_@$HOST")

say() { printf '\n==> %s\n' "$*"; }

say "目标 $USER_@$HOST:$APP_DIR"
"${SSH[@]}" "mkdir -p $APP_DIR/tests"

send() {  # send <本地文件> <远端目录>
  # 用 ssh + cat 送文件：这台小服务器的 scp 偶尔会卡死
  "${SSH[@]}" "cat > $2/$(basename "$1")" < "$1"
  echo "  $(basename "$1") → $2"
}

say "部署前的线上数据（防呆：data.json 绝不能被覆盖）"
total_of() {
  "${SSH[@]}" "curl -s --max-time 5 http://127.0.0.1:8792/api/list" \
    | /usr/bin/env python3 -c "import json,sys; print(json.load(sys.stdin)['total'])"
}
BEFORE="$(total_of)" || BEFORE="?"
echo "  现在线上 ${BEFORE} 条登记"

say "推代码"
send server.py "$APP_DIR"
send seed_counts.py "$APP_DIR"
send README.md "$APP_DIR"
for f in tests/*.py; do send "$f" "$APP_DIR/tests"; done

say "重启服务"
"${SSH[@]}" "systemctl restart suspect-id; sleep 1.2; systemctl is-active suspect-id"

say "冒烟检查"
"${SSH[@]}" "curl -sf --max-time 5 http://127.0.0.1:8792/healthz && echo"
say "复查线上数据没被动过"
AFTER="$(total_of)" || AFTER="?"
echo "  部署后 ${AFTER} 条（部署前 ${BEFORE} 条）"
if [ "$BEFORE" != "?" ] && [ "$AFTER" != "?" ] && [ "$AFTER" -lt "$BEFORE" ]; then
  echo "::error::线上登记数据变少了！部署不该碰 data.json，去查一下"
  exit 1
fi

echo
echo "部署完成"
