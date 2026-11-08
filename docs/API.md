# REST API 一览

所有路径相对面板根（`http://<手机IP>:<web_port>`）。无鉴权。

## GET

| 路径 | 说明 |
|---|---|
| `/` `/index.html` | 前端单页 |
| `/docs` `/docs.html` `/manual` | 内置文档页 |
| `/api/status` | 总览：速率/信号/电池/存储/CPU/开关状态（一次全给） |
| `/api/traffic` | 实时流量计数 |
| `/api/traffic/history` | SQLite 历史（小时/天） |
| `/api/clients` | 在线客户端列表 + 每设备速率 |
| `/api/cellular/deep` | 服务小区详情（band/ARFCN/PCI/RSRP/SINR…） |
| `/api/cellular/cells` `?mode=&trigger=` | 邻区扫描列表 |
| `/api/wifi/status` | Wi-Fi 状态 |
| `/api/wifi/list` | Wi-Fi 扫描列表 |
| `/api/hotspot/info` | 热点 SSID/密码/频段/信道/客户端 |
| `/api/system/processes` | 进程列表 |
| `/api/logs?type=&lines=` | 读设备日志（dmesg 等） |
| `/api/screen/frame` | 单帧截图（JPEG base64） |
| `/api/screen/stream.mjpg` | 投屏 MJPEG 流 |
| `/proxypanel*` | 反代 mihomo external-controller API |
| `/sdcard*` | WebDAV（独立进程，需另启 webdav_server.py） |

## POST

| 路径 | Body | 说明 |
|---|---|---|
| `/api/action` | `{"action": "...", "params": {...}}` | 统一动作入口 |
| `/api/hotspot/save` | 热点配置 JSON | 保存热点 SSID/密码/频段 |
| `/api/system/process/kill` | `{"pid": ...}` | 杀进程 |
| `/api/screen/control` | `{"action": "tap/swipe/...", ...}` | 远程触控 |

### `/api/action` 支持的 action

`toggle_eth_tether` `toggle_watchdog` `toggle_anti_cdrx` `toggle_wifi_master`
`toggle_wifi_power_save` `toggle_rps_rfs` `set_tcp_congestion` `set_cake_mode`
`hotspot_enable` `hotspot_disable` `wifi_connect` 等（详见 cybergate.py `_execute_action`）。
依赖外部脚本/二进制的 action，对应 config 项为空时会返回错误但不影响其他功能。

## PUT / PATCH / DELETE

`/sdcard*`（WebDAV 文件操作，独立进程）。
