"""
CyberGate WebUI · 设备适配配置层
================================
不同手机/不同 ROM 的差异，全部集中在这里。改这一个文件即可适配你的设备，
不用动主程序 cybergate.py。

优先级：环境变量 > 同目录 config.json > 内置默认值（K40S 参考实现）。

用法：
  1. 复制 config.example.json 为 config.json，按你的设备修改
  2. 或直接设环境变量覆盖单项，例如 CYBERGATE_HOTSPOT_IF=wlan1
"""
import os
import json

_HERE = os.path.dirname(os.path.abspath(__file__))

# ---- 内置默认值：K40S (munch / crDroid) 参考实现 ----
_DEFAULTS = {
    # 服务端口
    "web_port": 51080,          # WebUI 监听端口
    "dns_port": 53053,          # 内置 DNS 解析器监听端口
    "controller_port": 9090,    # mihomo/clash external-controller（代理面板反代目标）
    "webdav_port": 58080,       # WebDAV 网盘监听端口

    # 设备接口名（不同手机差异最大的地方）
    "hotspot_iface": "wlan1",   # 软 AP 接口
    "wifi_sta_iface": "wlan0",  # Wi-Fi 客户端接口
    "eth_iface": "eth0",        # 有线/USB 网卡接口
    "cellular_iface": "rmnet_data3",  # 蜂窝数据主接口（部分逻辑用，多数已动态发现）

    # 内置 DNS 为本地域名解析回的网关 IP（gateway.lan -> 本机）
    "local_gateway_ip": "192.168.43.1",
    "local_domain_keyword": "k40s",   # 匹配该关键词的查询走本地应答
    "upstream_dns": "223.5.5.5",      # 其余查询转发的上游 DNS

    # 路径（Android 上一般通用；自定义 ROM 可改）
    "softap_xml": "/data/misc/apexdata/com.android.wifi/WifiConfigStoreSoftAp.xml",
    "log_dir": "/data/local/tmp",
    "hotspot_guard_log": "/data/local/tmp/hotspot_guard.log",
    "mihomo_log": "/data/adb/side_router/mihomo.log",

    # 可选的配套脚本/二进制（对应面板上的开关按钮；没有就留空，按钮会报错但不影响其他功能）
    "watchdog_script": "/data/adb/modules/cyber_gateway_network/bin/watchdog.sh",
    "anti_cdrx_script": "/data/adb/modules/cyber_anti_cdrx/service.sh",
    "tc_cake_bin": "/data/adb/modules/cyber_gateway_network/bin/tc_cake",

    # 上游路由器探测、WoL 与外观
    "router_probe_url": "",           # 如 "http://192.168.1.1/cgi-bin/5g_clients"；留空则不主动探测
    "wol_mac": "",                    # 默认 Wake-on-LAN 目标 MAC（可留空由前端传入）
    "wol_subnets": ["255.255.255.255"],  # WoL 广播地址列表
    "wallpaper_url": "",              # 可选背景图 URL（默认留空，纯离线安全）

    # 运行模式：auto 自动判定；device 强制本机 su；adb 强制走 adb
    "transport": "auto",
    "adb_serial": "127.0.0.1:5555",   # transport=adb 时的目标序列号
}

_ENV_MAP = {
    "web_port": "CYBERGATE_WEB_PORT",
    "dns_port": "CYBERGATE_DNS_PORT",
    "controller_port": "CYBERGATE_CONTROLLER_PORT",
    "webdav_port": "CYBERGATE_WEBDAV_PORT",
    "hotspot_iface": "CYBERGATE_HOTSPOT_IF",
    "wifi_sta_iface": "CYBERGATE_WIFI_STA_IF",
    "eth_iface": "CYBERGATE_ETH_IF",
    "cellular_iface": "CYBERGATE_CELLULAR_IF",
    "local_gateway_ip": "CYBERGATE_LOCAL_IP",
    "local_domain_keyword": "CYBERGATE_LOCAL_DOMAIN",
    "upstream_dns": "CYBERGATE_UPSTREAM_DNS",
    "softap_xml": "CYBERGATE_SOFTAP_XML",
    "log_dir": "CYBERGATE_LOG_DIR",
    "hotspot_guard_log": "CYBERGATE_HOTSPOT_GUARD_LOG",
    "mihomo_log": "CYBERGATE_MIHOMO_LOG",
    "watchdog_script": "CYBERGATE_WATCHDOG_SCRIPT",
    "anti_cdrx_script": "CYBERGATE_ANTI_CDRX_SCRIPT",
    "tc_cake_bin": "CYBERGATE_TC_CAKE_BIN",
    "router_probe_url": "CYBERGATE_ROUTER_PROBE_URL",
    "wol_mac": "CYBERGATE_WOL_MAC",
    "wol_subnets": "CYBERGATE_WOL_SUBNETS",
    "wallpaper_url": "CYBERGATE_WALLPAPER_URL",
    "transport": "CYBERGATE_TRANSPORT",
    "adb_serial": "CYBERGATE_ADB_SERIAL",
}


def _load():
    cfg = dict(_DEFAULTS)
    cfg["wol_subnets"] = list(_DEFAULTS["wol_subnets"])
    # 1) config.json 覆盖默认
    json_path = os.path.join(_HERE, "config.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                user = json.load(f)
            for k, v in user.items():
                if k in cfg:
                    if isinstance(_DEFAULTS[k], list):
                        if isinstance(v, list):
                            cfg[k] = [str(x).strip() for x in v if str(x).strip()]
                    else:
                        cfg[k] = v
        except Exception as e:
            print(f"[config] 读取 config.json 失败，用默认值：{e}")
    # 2) 环境变量最高优先
    for k, env in _ENV_MAP.items():
        val = os.environ.get(env)
        if val is not None:
            if k.endswith("_port"):
                try:
                    cfg[k] = int(val)
                except ValueError:
                    pass
            elif isinstance(_DEFAULTS[k], list):
                s = val.strip()
                if s.startswith("["):
                    try:
                        arr = json.loads(s)
                        if isinstance(arr, list):
                            cfg[k] = [str(x).strip() for x in arr if str(x).strip()]
                    except Exception:
                        pass
                else:
                    cfg[k] = [x.strip() for x in s.split(",") if x.strip()]
            else:
                cfg[k] = val
    return cfg


CFG = _load()

# 便捷顶层常量，供主程序 import
WEB_PORT = CFG["web_port"]
DNS_PORT = CFG["dns_port"]
CONTROLLER_PORT = CFG["controller_port"]
WEBDAV_PORT = CFG["webdav_port"]
HOTSPOT_IF = CFG["hotspot_iface"]
WIFI_STA_IF = CFG["wifi_sta_iface"]
ETH_IF = CFG["eth_iface"]
CELLULAR_IF = CFG["cellular_iface"]
LOCAL_GATEWAY_IP = CFG["local_gateway_ip"]
LOCAL_DOMAIN_KEYWORD = CFG["local_domain_keyword"]
UPSTREAM_DNS = CFG["upstream_dns"]
SOFTAP_XML = CFG["softap_xml"]
LOG_DIR = CFG["log_dir"]
HOTSPOT_GUARD_LOG = CFG["hotspot_guard_log"]
MIHOMO_LOG = CFG["mihomo_log"]
WATCHDOG_SCRIPT = CFG["watchdog_script"]
ANTI_CDRX_SCRIPT = CFG["anti_cdrx_script"]
TC_CAKE_BIN = CFG["tc_cake_bin"]
ROUTER_PROBE_URL = CFG["router_probe_url"]
WOL_MAC = CFG["wol_mac"]
WOL_SUBNETS = CFG["wol_subnets"]
WALLPAPER_URL = CFG["wallpaper_url"]
TRANSPORT = CFG["transport"]
ADB_SERIAL = CFG["adb_serial"]


def local_gateway_bytes():
    """把 local_gateway_ip 转成 4 字节，供内置 DNS 拼 A 记录应答。"""
    try:
        return bytes(int(x) for x in LOCAL_GATEWAY_IP.split("."))
    except Exception:
        return bytes([192, 168, 43, 1])
