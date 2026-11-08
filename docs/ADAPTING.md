# 换手机怎么适配（ADAPTING）

面板的设备差异全部集中在两处：**`webui/config.py`**（或 `config.json`）和 **`scripts/start.sh` 顶部变量**。
主程序 `cybergate.py` 不直接写死任何机型参数。

## 1. 查你的接口名

```sh
ip -o link show                       # 全部接口
ip route show table all | grep default | grep rmnet   # 蜂窝主接口（可能随承载切换变化）
iw dev                                 # Wi-Fi：type AP 的是热点口，type managed 的是 STA 口
```

常见取值（供参考，因 ROM 而异）：

| 用途 | K40S/crDroid | 部分 MIUI/HyperOS | Pixel/AOSP |
|---|---|---|---|
| 热点 | wlan1 | wlan1 / ap0 / swlan0 | wlan1 |
| Wi-Fi STA | wlan0 | wlan0 | wlan0 |
| USB 网卡 | eth0（可能被改名 lan0） | 同左 | 同左 |
| 蜂窝 | rmnet_data0~5 | rmnet_data* | ccmni*/rmnet_data* |

> 提示：蜂窝接口号会变（rmnet_data1↔2↔3），所以面板里大部分逻辑用
> `ls /sys/class/net | grep rmnet_data` 动态发现；`cellular_iface` 只用于个别展示项，填错不致命。

## 2. 确认命令可用性

面板依赖这些 Android 命令，逐项在你的设备上试（root shell）：

| 命令 | 用途 | 不可用时的表现 |
|---|---|---|
| `dumpsys telephony.registry` | 蜂窝信号/小区 | 蜂窝卡片空白 |
| `dumpsys tethering` | 以太网 tether 状态 | 该开关显示不准 |
| `cmd wifi ...` | Wi-Fi 开关/热点 | 相关按钮报错 |
| `settings get/put global` | Wi-Fi 开关状态、省电 | 显示不准 |
| `getprop gsm.*` | SIM/运营商信息 | 显示为空 |
| `iptables` / `ip` / `tc` / `sysctl` | QoS 读取与开关 | 对应卡片报错 |
| `iw` | Wi-Fi 省电/功率 | 按钮报错 |
| `screencap` | 屏幕投屏 | 投屏不可用 |

**命令缺失不会让面板崩溃**——每个 API 独立 try/except，坏一个只影响那一张卡片。

## 3. 端口与本地域名

- `web_port`：面板端口。改它同时改 `start.sh` 里的 `WEB_PORT`。
- `dns_port` + `start.sh` 的 53→DNS_PORT 重定向：实现 `k40s.com` 这类本地域名免配置解析。
  不需要就删掉 start.sh 里那段 iptables，并把 `local_domain_keyword` 留空意义不大（无妨）。
- `local_gateway_ip`：内置 DNS 应答的 A 记录，填你手机在局域网的网关 IP。
- `controller_port`：如果你跑了 mihomo/clash，填它的 external-controller 端口（默认 9090）；
  没跑就不管，代理面板页打不开而已。

## 4. 可选配套脚本

`watchdog_script` / `anti_cdrx_script` / `tc_cake_bin` 指向你设备上的对应文件。
**没有就留空字符串**——面板对应按钮会报错，但其余功能不受影响。
（K40S 参考实现里它们分别属于 Magisk 模块 cyber_gateway_network / cyber_anti_cdrx。）

## 5. 运行位置

- **推荐：跑在手机上**（`transport=auto` 检测到 `/system/bin/sh` 自动用本机 su，最快最稳）。
- 也可以跑在 PC 上远程管理（`transport=adb` + `adb_serial`），功能相同，延迟略高。

## 6. 已知不需要改的

- 前端 `static/index.html` 全部用相对路径调 API，跟随你访问的地址，天然跨设备。
- 流量记账 SQLite 自动建表建文件。
- `hotspot_schedule.json` / `blocked_macs.json` 首次使用时自动创建。

## 7. 排错

启动后 `curl http://127.0.0.1:<web_port>/api/status` 看 JSON 是否正常；
日志在 `/data/local/tmp/cybergate.log`。
