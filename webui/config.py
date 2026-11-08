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

    # 设备接口名（不同手机差异最大的地方）
    "hotspot_iface": "wlan1",   # 软 AP 接口
    "wifi_sta_iface": "wlan0",  # Wi-Fi 客户端接口
    "eth_iface": "eth0",        # 有线/USB 网卡接口
    "cellular_iface": "rmnet_data3",  # 蜂窝数据主接口（部分逻辑用，多数已动态发现）

    # 内置 DNS 为本地域名解析回的网关 IP（k40s.com -> 本机）
    "local_gateway_ip": "192.168.43.1",
    "local_domain_keyword": "k40s",   # 匹配该关键词的查询走本地应答
    "upstream_dns": "223.5.5.5",      # 其余查询转发的上游 DNS

    # 路径（Android 上一般通用；自定义 ROM 可改）
    "softap_xml": "/data/misc/apexdata/com.android.wifi/WifiConfigStoreSoftAp.xml",

    # 可选的配套脚本/二进制（对应面板上的开关按钮；没有就留空，按钮会报错但不影响其他功能）
    "watchdog_script": "/data/adb/modules/cyber_gateway_network/bin/watchdog.sh",
    "anti_cdrx_script": "/data/adb/modules/cyber_anti_cdrx/service.sh",
    "tc_cake_bin": "/data/adb/modules/cyber_gateway_network/bin/tc_cake",

    # 运行模式：auto 自动判定；device 强制本机 su；adb 强制走 adb
    "transport": "auto",
    "adb_serial": "127.0.0.1:5555",   # transport=adb 时的目标序列号
}

_ENV_MAP = {
    "web_port": "CYBERGATE_WEB_PORT",
    "dns_port": "CYBERGATE_DNS_PORT",
    "controller_port": "CYBERGATE_CONTROLLER_PORT",
    "hotspot_iface": "CYBERGATE_HOTSPOT_IF",
    "wifi_sta_iface": "CYBERGATE_WIFI_STA_IF",
    "eth_iface": "CYBERGATE_ETH_IF",
    "cellular_iface": "CYBERGATE_CELLULAR_IF",
    "local_gateway_ip": "CYBERGATE_LOCAL_IP",
    "local_domain_keyword": "CYBERGATE_LOCAL_DOMAIN",
    "upstream_dns": "CYBERGATE_UPSTREAM_DNS",
    "softap_xml": "CYBERGATE_SOFTAP_XML",
    "transport": "CYBERGATE_TRANSPORT",
    "adb_serial": "CYBERGATE_ADB_SERIAL",
}


def _load():
    cfg = dict(_DEFAULTS)
    # 1) config.json 覆盖默认
    json_path = os.path.join(_HERE, "config.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                user = json.load(f)
            for k, v in user.items():
                if k in cfg:
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
            else:
                cfg[k] = val
    return cfg


CFG = _load()

# 便捷顶层常量，供主程序 import
WEB_PORT = CFG["web_port"]
DNS_PORT = CFG["dns_port"]
CONTROLLER_PORT = CFG["controller_port"]
HOTSPOT_IF = CFG["hotspot_iface"]
WIFI_STA_IF = CFG["wifi_sta_iface"]
ETH_IF = CFG["eth_iface"]
CELLULAR_IF = CFG["cellular_iface"]
LOCAL_GATEWAY_IP = CFG["local_gateway_ip"]
LOCAL_DOMAIN_KEYWORD = CFG["local_domain_keyword"]
UPSTREAM_DNS = CFG["upstream_dns"]
SOFTAP_XML = CFG["softap_xml"]
WATCHDOG_SCRIPT = CFG["watchdog_script"]
ANTI_CDRX_SCRIPT = CFG["anti_cdrx_script"]
TC_CAKE_BIN = CFG["tc_cake_bin"]
TRANSPORT = CFG["transport"]
ADB_SERIAL = CFG["adb_serial"]


def local_gateway_bytes():
    """把 local_gateway_ip 转成 4 字节，供内置 DNS 拼 A 记录应答。"""
    try:
        return bytes(int(x) for x in LOCAL_GATEWAY_IP.split("."))
    except Exception:
        return bytes([192, 168, 43, 1])
