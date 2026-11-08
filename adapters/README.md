# 设备适配速查表

不同手机/ROM 上，面板用到的命令和路径差异速查。适配时逐项对照。

## 接口命名习惯

| 类别 | 常见名字 | 发现方法 |
|---|---|---|
| 软 AP（热点） | `wlan1`、`ap0`、`swlan0`、`softap` | `iw dev` 看 `type AP` |
| Wi-Fi STA | `wlan0` | `iw dev` 看 `type managed` |
| USB 网卡 | `eth0`、`lan0`、`usb0`、`rndis0`、`ncm0` | 插上网卡后 `ip link` 新增的那个 |
| 蜂窝 | `rmnet_data0..5`（高通）、`ccmni0..`（联发科部分）、`r_rmnet_data*`（IPA 保留口，勿用） | `ip route show table all \| grep default` |
| WireGuard | `wg0` | `wg show` |

## 关键命令差异

| 功能 | 高通/crDroid (K40S) | MIUI/HyperOS | 备注 |
|---|---|---|---|
| 蜂窝详情 | `dumpsys telephony.registry` | 同左 | 输出格式基本一致 |
| 热点启停 | `cmd wifi start-softap/-stop-softap` | 多数可用 | HyperOS 部分版本被裁剪 |
| 以太网 tether | `service call tethering/ethernet` | 同左 | Android 13+ 行为有差异，失败就放弃该卡片 |
| DNS 设置项 | `settings get global private_dns_*` | 同左 | |
| tc/iptables | 随 ROM 的 toybox/busybox | 同左 | Android 的 iptables 是 netd 那套，mangle/nat 表都在 |

## 路径差异

| 用途 | 常见路径 |
|---|---|
| 热点配置 XML | `/data/misc/apexdata/com.android.wifi/WifiConfigStoreSoftAp.xml`（Android 13+ APEX）；旧版在 `/data/misc/wifi/` |
| root shell | `su`（Magisk/KSU/APatch 均可，面板只调 `su`） |
| busybox | Magisk 自带 `/data/adb/magisk/busybox`；其他 ROM 可能没有 → `start.sh` 里 `BUSYBOX=` 换实现或直接 `setsid` 去掉 |
| python3 | Termux 沙箱路径最深：`/data/adb/cyber_python/data/data/com.termux/files/usr/bin/python3`；或 `adb shell` 里 `nohup toybox sh -c` 之类。最通用做法：Magisk 模块带静态 python，或 Termux |

## 命令缺失的行为

面板每个 API 独立 try/except：某命令不存在 → 那张卡片报错/空白，**不影响其他功能、不会崩服务**。适配时按 `docs/API.md` 逐个卡片点亮即可。
