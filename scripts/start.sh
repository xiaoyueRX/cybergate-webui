#!/system/bin/sh
# CyberGate WebUI 启动脚本（Android root 环境）
# ------------------------------------------------------------------
# 这是 K40S 参考实现。不同手机/ROM 需要改的地方已抽到顶部变量，
# 详见 docs/ADAPTING.md。核心只需保证：
#   1) 有一个 root 可用的 python3（Termux / 自带 / system 均可）
#   2) 面板端口、网关 IP、本地域名按你的网络填
# ------------------------------------------------------------------
set -e

# ==== 按你的设备修改 ====
INSTALL_DIR="${INSTALL_DIR:-/data/adb/cybergate-webui}"   # 本仓库部署目录
PYTHON="${PYTHON:-python3}"                                # python3 路径或命令
BUSYBOX="${BUSYBOX:-busybox}"                              # 提供 setsid/nohup 的工具（Magisk 上是 /data/adb/magisk/busybox）
WEB_PORT="${WEB_PORT:-51080}"                              # 面板端口（与 config.py 一致）
DNS_PORT="${DNS_PORT:-53053}"                              # 内置 DNS 端口
LOCAL_IPS="${LOCAL_IPS:-}"                                 # 空格分隔的本机网关 IP，如 "192.168.43.1"
LOG="/data/local/tmp/cybergate.log"
# ========================

export TMPDIR=/data/local/tmp

# 可选：把发往本机网关 IP 的 80 端口转到面板，实现 http://<网关>/ 免端口访问。
# 关键：必须带 -d <本机IP> 限定，绝不全局劫持 dport 80（否则局域网所有 HTTP 被劫进面板，
# 表现为所有网站/CDN 返回 404）。不需要免端口访问就删掉这段。
if [ -n "$LOCAL_IPS" ]; then
    iptables -C INPUT -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT 1 -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null
    for ip in $LOCAL_IPS; do
        iptables -t nat -C PREROUTING -d "$ip" -p tcp --dport 80 -j REDIRECT --to-ports "$WEB_PORT" 2>/dev/null || \
            iptables -t nat -I PREROUTING 1 -d "$ip" -p tcp --dport 80 -j REDIRECT --to-ports "$WEB_PORT" 2>/dev/null
    done
fi

# 可选：把端口 53 的 DNS 查询转给内置解析器（实现本地域名解析）。不需要就删掉这段。
iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null || \
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null

pkill -f "cybergate.py" 2>/dev/null || true
sleep 1
cd "$INSTALL_DIR/webui"

# 后台启动主面板
"$BUSYBOX" setsid "$BUSYBOX" nohup "$PYTHON" "$INSTALL_DIR/webui/cybergate.py" >> "$LOG" 2>&1 < /dev/null &

# 可选：启动 WebDAV（不需要网盘就注释掉下面这行）
# "$BUSYBOX" setsid "$BUSYBOX" nohup "$PYTHON" "$INSTALL_DIR/webui/webdav_server.py" >> /data/local/tmp/cybergate_webdav.log 2>&1 < /dev/null &

sleep 3
if netstat -tln 2>/dev/null | grep -q ":$WEB_PORT"; then
    echo "WEBUI_UP on :$WEB_PORT"
else
    echo "WEBUI_DOWN (check $LOG)"
fi
