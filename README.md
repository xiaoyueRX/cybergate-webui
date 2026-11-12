# CyberGate WebUI

一个跑在 **Android 手机（root）** 上的轻量级 OpenWrt 风格网络管理面板。
把手机变成 5G/4G 网关后，用手机浏览器或局域网电脑就能查看/控制：
蜂窝信号与小区、热点状态、Wi-Fi、在线客户端、流量统计、进程、QoS 开关、
屏幕投屏、内置 WebDAV 网盘、代理（mihomo/clash）控制面板反代等。

单文件后端（Python 标准库 + 可选 Pillow），无框架、无数据库服务，SQLite 记账。

## 它是什么 / 不是什么

- ✅ 是：给「手机当路由器/CPE」这种玩法用的管理面板
- ✅ 是：设备差异全部收敛到 `webui/config.py`（或 `config.json` / 环境变量），**换手机改这一个文件**
- ❌ 不是：开箱支持所有机型。它默认按 **Redmi K40S (munch, crDroid)** 写死了一组参考值；
  其他手机/ROM 需要你按 [docs/ADAPTING.md](docs/ADAPTING.md) 适配（接口名、路径、命令可用性都不同）
- ❌ 不是：网络优化方案本身。面板只是**读取/调用**设备上已有的 iptables/tc/sysctl 规则，
  那些规则（CAKE、DSCP、NAT 等）需要你自己用 keeper 脚本或别的工具建立

## 快速开始（K40S 参考设备）

```sh
# 1. 把整个目录推到手机（示例用 adb）
adb push cybergate-webui /data/adb/cybergate-webui

# 2. 手机上（root shell）启动
adb shell
su
sh /data/adb/cybergate-webui/scripts/start.sh

# 3. 浏览器打开
http://<手机IP>:51080/
```

## 快速开始（任意 Android root 设备）

1. 确认设备上有一个 root 能用的 `python3`（Termux 的、或系统自带的都行）
2. 复制 `webui/config.example.json` → `webui/config.json`，按你的设备改：
   - 接口名：`hotspot_iface` / `wifi_sta_iface` / `eth_iface` / `cellular_iface`
   - 端口：`web_port` / `dns_port` / `controller_port`
   - 本地域名解析：`local_gateway_ip` / `local_domain_keyword` / `upstream_dns`
3. 改 `scripts/start.sh` 顶部的 `INSTALL_DIR` / `PYTHON` / `BUSYBOX` / `LOCAL_IPS`
4. 启动，打开 `http://<手机IP>:<web_port>/`

详见 **[docs/ADAPTING.md](docs/ADAPTING.md)**（如何查接口名、如何确认命令可用、常见坑）。

## 目录结构

```
webui/
  cybergate.py          主程序（HTTP + REST API + 内置 DNS + 流量记账）
  config.py             ★ 设备适配层：所有机型差异集中在这里
  config.example.json   配置示例（复制成 config.json 生效）
  webdav_server.py      可选 WebDAV 网盘（纯标准库）
  static/index.html     前端（单页，相对路径调 API，跨设备通用）
  static/docs.html      内置使用文档页
scripts/
  start.sh              启动脚本（iptables 重定向 + 后台拉起）
docs/
  ADAPTING.md           ★ 换手机怎么适配
  API.md                REST 接口清单
adapters/               适配说明与命令可用性速查
examples/               不同 ROM 的配置样例
```

## 功能一览

| 模块 | 说明 |
|---|---|
| 总览 | 下行/上行速率、5G 信号(RSRP/SINR)、电池/温度、存储、CPU/内存 |
| 实时流量 | SQLite 记账（按小时/按天），历史曲线 |
| 蜂窝详情 | 服务小区 + 邻区列表（ARFCN/PCI/RSRP/RSRQ/SINR），需装 Cellular-Pro 或直接读 dumpsys |
| 客户端 | 在线设备列表、每设备实时速率、厂商(MAC OUI)、限速/拉黑 |
| Wi-Fi | 扫描、连接、热点状态 |
| 开关 | 看门狗、C-DRX 心跳、Wi-Fi 省电、RPS/RFS、TCP 拥塞算法、CAKE 模式（依赖设备已有脚本/二进制） |
| 进程 | 列出/杀进程 |
| 屏幕 | 投屏帧 + 远程点击（依赖 screencap / minicap 类工具） |
| 代理面板 | 反代 mihomo/clash 的 external-controller，单页管理 |
| 内置 DNS | 解析本地域名（如 gateway.lan → 网关 IP），其余转发上游 |
| WebDAV | 把 /sdcard 作为网盘（独立进程，可选） |

## 依赖

- **必需**：Python 3（标准库即可运行核心）
- **可选**：`Pillow`（屏幕投屏图片压缩；没有则投屏功能降级）
- 见 `requirements.txt`

## 安全警告 ⚠️

- 面板**没有任何鉴权**，监听 `0.0.0.0`，能杀进程、能改网络开关。
  **只应在可信局域网使用**，不要暴露公网。生产用途请自行加反代 + Basic Auth / mTLS。
- 需要 **root**：所有控制类操作走 `su`。
- `scripts/start.sh` 会改 iptables（80→面板、53→内置DNS）。这些是**可选**的，
  不需要就删掉对应段落。劫持 80 端口时**必须**用 `-d <本机IP>` 限定，
  否则会把局域网所有设备的 HTTP 流量劫进面板（表现为全网 404）。

## 许可

MIT，见 [LICENSE](LICENSE)。

## 致谢 / 出处

本项目从个人 K40S 蜂窝网关实践中提取开源。默认配置仅保证在
Redmi K40S (munch / crDroid 11.6 / Android 15) 上开箱可用；其余机型按 ADAPTING.md 适配。
