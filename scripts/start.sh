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
PYTHON="${PYTHON:-}"                                       # 留空自动探测 PATH 或 Termux python3
BUSYBOX="${BUSYBOX:-}"                                     # 留空自动探测 busybox / Magisk busybox
WEB_PORT="${WEB_PORT:-51080}"                              # 面板端口（与 config.py 一致）
DNS_PORT="${DNS_PORT:-53053}"                              # 内置 DNS 端口
LOCAL_IPS="${LOCAL_IPS:-}"                                 # 空格分隔的本机网关 IP，如 "192.168.43.1"
LOG="${LOG:-/data/local/tmp/cybergate.log}"
# ========================

export TMPDIR=/data/local/tmp

# 自动探测 Python3（兼容 Magisk service.d 无 Termux PATH 的场景）
if [ -z "$PYTHON" ]; then
    if command -v python3 >/dev/null 2>&1; then
        PYTHON="$(command -v python3)"
    elif [ -x "/data/data/com.termux/files/usr/bin/python3" ]; then
        PYTHON="/data/data/com.termux/files/usr/bin/python3"
    else
        echo "ERROR: python3 not found in PATH or Termux" >&2
        exit 1
    fi
fi

# 若使用 Termux Python，补齐其动态库路径（cybergate.py 内部会在执行系统子命令时自动净化环境）
case "$PYTHON" in
    /data/data/com.termux/*)
        export LD_LIBRARY_PATH="/data/data/com.termux/files/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        ;;
esac

# 自动探测 BusyBox（用于 setsid / nohup 脱离会话）
if [ -z "$BUSYBOX" ]; then
    if command -v busybox >/dev/null 2>&1; then
        BUSYBOX="$(command -v busybox)"
    elif [ -x "/data/adb/magisk/busybox" ]; then
        BUSYBOX="/data/adb/magisk/busybox"
    fi
fi

# 可选：把发往本机网关 IP 的 80 端口转到面板，实现 http://<网关>/ 免端口访问。
# 关键：必须带 -d <本机IP> 限定，绝不全局劫持 dport 80（否则局域网所有 HTTP 被劫进面板，
# 表现为所有网站/CDN 返回 404）。不需要免端口访问就删掉这段。
if [ -n "$LOCAL_IPS" ]; then
    iptables -C INPUT -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT 1 -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || true
    for ip in $LOCAL_IPS; do
        iptables -t nat -C PREROUTING -d "$ip" -p tcp --dport 80 -j REDIRECT --to-ports "$WEB_PORT" 2>/dev/null || \
            iptables -t nat -I PREROUTING 1 -d "$ip" -p tcp --dport 80 -j REDIRECT --to-ports "$WEB_PORT" 2>/dev/null || true
    done
fi

# 可选：把端口 53 的 DNS 查询转给内置解析器（实现本地域名解析）。不需要就删掉这段。
iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null || \
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null || true

pkill -f "cybergate.py" 2>/dev/null || true
sleep 1
cd "$INSTALL_DIR/webui"

# 后台启动主面板
if [ -n "$BUSYBOX" ]; then
    "$BUSYBOX" setsid "$BUSYBOX" nohup "$PYTHON" "$INSTALL_DIR/webui/cybergate.py" >> "$LOG" 2>&1 < /dev/null &
else
    nohup "$PYTHON" "$INSTALL_DIR/webui/cybergate.py" >> "$LOG" 2>&1 < /dev/null &
fi

# 可选：启动 WebDAV（不需要网盘就注释掉下面这行）
# if [ -n "$BUSYBOX" ]; then "$BUSYBOX" setsid "$BUSYBOX" nohup "$PYTHON" "$INSTALL_DIR/webui/webdav_server.py" >> /data/local/tmp/cybergate_webdav.log 2>&1 < /dev/null & else nohup "$PYTHON" "$INSTALL_DIR/webui/webdav_server.py" >> /data/local/tmp/cybergate_webdav.log 2>&1 < /dev/null & fi

sleep 3
HEX_PORT=$(printf '%04X' "$WEB_PORT")
if (command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -q ":$WEB_PORT") || \
   (command -v netstat >/dev/null 2>&1 && netstat -tln 2>/dev/null | grep -q ":$WEB_PORT") || \
   grep -qiE "^ *[0-9]+: [0-9A-F]+:${HEX_PORT} " /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
    echo "WEBUI_UP on :$WEB_PORT"
else
    echo "WEBUI_DOWN (check $LOG)"
    exit 1
fi
