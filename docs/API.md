# REST API 一览

所有主面板路径相对面板根（`http://<手机IP>:<web_port>`）。无鉴权。

## GET

| 路径 | 说明 |
|---|---|
| `/` `/index.html` | 前端单页 |
| `/docs` `/docs.html` `/manual` | 内置文档页 |
| `/connecttest.txt` `/ncsi.txt` | Windows NCSI 联网探测应答 |
| `/api/status` | 总览：速率/信号/电池/存储/CPU/内存/VPN IP/开关状态/前端配置 |
| `/api/traffic` | 实时流量计数（`/proc/net/dev`） |
| `/api/traffic/history` | SQLite 历史统计（今日小时 / 近 30 天 / 近 12 个月） |
| `/api/clients` | 在线客户端列表 + 每设备速率 + 上游路由器状态 |
| `/api/cellular/deep` | 服务小区详情（band/ARFCN/PCI/TAC/NCI/RSRP/RSRQ/SINR/APN/IP） |
| `/api/cellular/cells` `?mode=&trigger=` | 主小区与邻区扫描列表（别名 `/api/cellular/scan`） |
| `/api/wifi/status` | Wi-Fi 开关状态（`{"enabled": bool}`） |
| `/api/wifi/list` | Wi-Fi 扫描列表 |
| `/api/hotspot/info` | 热点 SoftAP 配置、实时 SSID/信道与调度状态 |
| `/api/system/processes` | CPU/GPU/内存与进程列表 |
| `/api/logs?type=&lines=` | 读设备日志（`dmesg` / `logcat` / `webui` / `webdav` / `keeper` / `boxguard` / `mihomo`） |
| `/api/screen/frame?quality=&width=` | 单帧截图（`image/png` 原生帧，带 `X-Screen-Width`/`X-Screen-Height` 头；无帧返回 503） |
| `/api/screen/stream.mjpg?quality=&width=` | 投屏 MJPEG 流（`multipart/x-mixed-replace`） |
| `/proxypanel*` | 反代 mihomo `external-controller` API（透传查询参数） |

## POST

| 路径 | Body | 说明 |
|---|---|---|
| `/api/action` | `{"action": "...", "params": {...}}` | 统一动作入口 |
| `/api/hotspot/save` | 热点配置 JSON | 保存热点 SSID/密码/频段/信道/调度 |
| `/api/system/process/kill` | `{"pid": ..., "package": "..."}` | 杀进程（可选同时 force-stop 包名） |
| `/api/screen/control` | `{"action": "tap\|swipe\|key\|text\|wake", "params": {...}}` | 远程触控与按键输入 |
| `/api/terminal/exec` | `{"command": "..."}` | Web Root 终端执行命令 |
| `/proxypanel*` | 任意 | 透传 `POST/PUT/PATCH/DELETE` 到 mihomo `external-controller` |

### `/api/action` 支持的 action

- 开关与守护：`toggle_eth_tether`, `toggle_watchdog`, `toggle_anti_cdrx`, `toggle_wifi_master`, `toggle_wifi_power_save`, `toggle_qos_500b`, `toggle_qos_cs2`, `toggle_hotspot`, `toggle_rps_rfs`
- 蜂窝与 Wi-Fi：`refresh_cellular`, `set_network_mode`, `wifi_connect`, `wifi_forget`
- 客户端与流控：`toggle_client_block`, `kick_client`, `limit_client_speed`, `set_speed_limit`, `set_cake_mode`, `set_tcp_congestion`
- 系统与工具：`wake_pc`, `send_notification`, `remount_swap`, `exec_cmd`, `reboot`

（详见 `webui/cybergate.py` `_execute_action`。依赖外部脚本/二进制的 action，对应 config 项为空时会返回错误但不影响其他功能。）

## 独立 WebDAV 服务（`webui/webdav_server.py`）

WebDAV 为独立进程，默认监听 `http://<手机IP>:<webdav_port>/`（默认 `58080`，根目录 `/sdcard`，可通过 `CYBERGATE_WEBDAV_PORT` / `CYBERGATE_WEBDAV_ROOT` 配置），不挂载在主面板 HTTP 端口下。支持 `GET`, `HEAD`, `PUT`, `POST`, `DELETE`, `PROPFIND`, `MKCOL`, `OPTIONS`。
