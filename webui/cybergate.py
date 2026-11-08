"""
K40S CyberGateway WebUI Backend Engine (CyberGate LuCI v2.0)
Lightweight, Threaded HTTP & REST API Service
Listening on configurable port (see config.py)
"""

import os
import sys
import time
import json
import socket
import base64
import subprocess
import urllib.parse
import threading
import struct
import io
import re
import sqlite3
from datetime import datetime, date, timedelta
import xml.etree.ElementTree as ET
try:
    from PIL import Image
except ImportError:
    Image = None
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

# 设备差异全部集中在 config.py（或环境变量 / config.json），主程序只引用它。
import config as C

PORT = C.WEB_PORT
# WebUI 可原生运行在设备上（root，走本地 su），也可在 PC 上经 adb 远程管理。
# transport=auto 时自动判定；也可在 config 里强制 device / adb。
if C.TRANSPORT == "device":
    ON_DEVICE = True
elif C.TRANSPORT == "adb":
    ON_DEVICE = False
else:  # auto
    ON_DEVICE = os.path.exists("/system/bin/sh") and not os.path.exists("/usr/bin/adb")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
HTML_FILE = os.path.join(STATIC_DIR, "index.html")
DOCS_FILE = os.path.join(STATIC_DIR, "docs.html")
TARGET_ADB = C.ADB_SERIAL
SOFTAP_XML = C.SOFTAP_XML
SCHEDULE_JSON = "/workspace/mcp-shell/hotspot_schedule.json"
if not os.path.exists(os.path.dirname(SCHEDULE_JSON)):
    SCHEDULE_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hotspot_schedule.json")

BLOCKED_MACS_FILE = "/workspace/mcp-shell/blocked_macs.json"
if not os.path.exists(os.path.dirname(BLOCKED_MACS_FILE)):
    BLOCKED_MACS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocked_macs.json")

TRAFFIC_DB_PATH = "/workspace/mcp-shell/traffic_stats.db"
if not os.path.exists(os.path.dirname(TRAFFIC_DB_PATH)):
    TRAFFIC_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_stats.db")

# Screen streaming state
_screen_lock = threading.Lock()
_last_frame_time = 0
_last_frame_bytes = None
_screen_width = 800
# 2026-10-16: 路由器探测节流时间戳（clients 列表 60s 缓存）
_router_probe_skip = 0
_screen_height = 2400
_screen_file = "/data/local/tmp/screen.raw"

# Traffic snapshot
_last_traffic_time = 0
_last_traffic_data = {}


def _ensure_adb() -> bool:
    try:
        res = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=3)
        if f"{TARGET_ADB}\tdevice" in res.stdout:
            return True
        subprocess.run(["adb", "connect", TARGET_ADB], capture_output=True, text=True, timeout=3)
        time.sleep(0.3)
        res2 = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=3)
        return f"{TARGET_ADB}\tdevice" in res2.stdout
    except Exception:
        return False


def _run_host_shell(cmd: str, timeout: int = 15) -> str:
    """Run command on Android host natively (WebUI now runs on-device as root).
    Fallback to ADB transport when running off-device (legacy mode)."""
    if ON_DEVICE:
        b64 = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
        wrapped = f"echo '{b64}' | base64 -d | su"
        try:
            # 2026-10-16: 净化环境——python 进程的 PYTHONHOME/LD_LIBRARY_PATH(termux)
            # 会毒化子进程（screencap 等系统动态链接程序崩溃 CANNOT LINK EXECUTABLE）
            _clean_env = {k: v for k, v in os.environ.items()
                          if k not in ("PYTHONHOME", "LD_LIBRARY_PATH", "PYTHONPATH")}
            p = subprocess.run(
                ["/system/bin/sh", "-c", wrapped],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_clean_env
            )
            return p.stdout.strip()
        except Exception as e:
            return f"Error: {e}"
    if not _ensure_adb():
        return "Error: ADB connection unavailable"
    b64 = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    wrapped = f"echo '{b64}' | base64 -d | su"
    try:
        p = subprocess.run(
            ["adb", "-s", TARGET_ADB, "shell", wrapped],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        out = p.stdout.replace("* daemon not running; starting now at tcp:5037 *\n", "").replace("* daemon started successfully *\n", "")
        return out.strip()
    except Exception as e:
        return f"Error: {e}"


def _get_traffic_stats():
    """Calculate real-time download and upload speeds from /proc/net/dev."""
    global _last_traffic_time, _last_traffic_data
    now = time.time()
    current_data = {}

    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]
        for line in lines:
            parts = line.strip().split()
            if not parts:
                continue
            dev = parts[0].rstrip(":")
            rx_bytes = int(parts[1])
            tx_bytes = int(parts[9])
            current_data[dev] = (rx_bytes, tx_bytes)
    except Exception:
        return {}

    delta = now - _last_traffic_time
    speeds = {}

    if _last_traffic_data and delta > 0.3:
        for dev, (rx, tx) in current_data.items():
            if dev in _last_traffic_data:
                old_rx, old_tx = _last_traffic_data[dev]
                rx_speed = max(0, (rx - old_rx) / delta / 1024)
                tx_speed = max(0, (tx - old_tx) / delta / 1024)
                speeds[dev] = {
                    "rx_speed_kb": round(rx_speed, 1),
                    "tx_speed_kb": round(tx_speed, 1),
                    "rx_speed_mbps": round((rx_speed * 8) / 1024, 2),
                    "tx_speed_mbps": round((tx_speed * 8) / 1024, 2),
                    "rx_total_mb": round(rx / (1024 * 1024), 1),
                    "tx_total_mb": round(tx / (1024 * 1024), 1),
                }

    _last_traffic_time = now
    _last_traffic_data = current_data
    return speeds


# ==========================================
# 📊 Ultra-Lightweight SQLite Traffic Accounting Engine
# ==========================================
_traffic_lock = threading.Lock()
_pending_rx = 0
_pending_tx = 0
_last_flush_time = time.time()
_last_dev_bytes = {}

def _init_traffic_db():
    """Ensure SQLite database and tables exist with optimal WAL performance."""
    try:
        os.makedirs(os.path.dirname(TRAFFIC_DB_PATH), exist_ok=True)
        conn = sqlite3.connect(TRAFFIC_DB_PATH, timeout=10)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS daily_traffic (
                date TEXT PRIMARY KEY,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hourly_traffic (
                hour_key TEXT PRIMARY KEY,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Error initializing traffic db: {e}")

def _flush_traffic_db(force: bool = False):
    """Safely flush in-memory accumulated traffic bytes to SQLite.
    Prevents flash wear by batching writes every 60s."""
    global _pending_rx, _pending_tx, _last_flush_time
    now = time.time()
    with _traffic_lock:
        if not force and (now - _last_flush_time < 60) and (_pending_rx + _pending_tx < 10 * 1024 * 1024):
            return
        rx = _pending_rx
        tx = _pending_tx
        _pending_rx = 0
        _pending_tx = 0
        _last_flush_time = now

    if rx == 0 and tx == 0:
        return

    try:
        now_dt = datetime.now()
        date_str = now_dt.strftime("%Y-%m-%d")
        hour_str = now_dt.strftime("%Y-%m-%d %H:00")
        ts = int(now)

        conn = sqlite3.connect(TRAFFIC_DB_PATH, timeout=5)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO daily_traffic (date, rx_bytes, tx_bytes, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(date) DO UPDATE SET
                rx_bytes = rx_bytes + excluded.rx_bytes,
                tx_bytes = tx_bytes + excluded.tx_bytes,
                updated_at = excluded.updated_at
        """, (date_str, rx, tx, ts))

        cur.execute("""
            INSERT INTO hourly_traffic (hour_key, rx_bytes, tx_bytes)
            VALUES (?, ?, ?)
            ON CONFLICT(hour_key) DO UPDATE SET
                rx_bytes = rx_bytes + excluded.rx_bytes,
                tx_bytes = tx_bytes + excluded.tx_bytes
        """, (hour_str, rx, tx))

        # Auto-prune older than 365 days (daily) and 7 days (hourly)
        cur.execute("DELETE FROM daily_traffic WHERE date < date('now', 'localtime', '-365 day')")
        cur.execute("DELETE FROM hourly_traffic WHERE hour_key < strftime('%Y-%m-%d %H:00', 'now', 'localtime', '-7 day')")

        conn.commit()
        conn.close()
    except Exception as e:
        with _traffic_lock:
            _pending_rx += rx
            _pending_tx += tx
        print(f"[!] _flush_traffic_db error: {e}")

def _update_traffic_accounting():
    """Sample /proc/net/dev for cellular WAN interfaces (rmnet_data*),
    calculate deltas, accumulate in memory, and periodically flush."""
    global _last_dev_bytes, _pending_rx, _pending_tx
    curr_bytes = {}
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]
        for line in lines:
            parts = line.strip().split()
            if not parts:
                continue
            dev = parts[0].rstrip(":")
            # Target cellular WAN: rmnet_data* or rmnet* (excluding mhi/ipa)
            if dev.startswith("rmnet_data") or (dev.startswith("rmnet") and not dev.startswith("rmnet_mhi") and not dev.startswith("rmnet_ipa")):
                rx = int(parts[1])
                tx = int(parts[9])
                curr_bytes[dev] = (rx, tx)
    except Exception:
        return

    delta_rx_total = 0
    delta_tx_total = 0

    if _last_dev_bytes:
        for dev, (rx, tx) in curr_bytes.items():
            if dev in _last_dev_bytes:
                old_rx, old_tx = _last_dev_bytes[dev]
                d_rx = (rx - old_rx) if rx >= old_rx else 0
                d_tx = (tx - old_tx) if tx >= old_tx else 0
                if d_rx < 500 * 1024 * 1024:
                    delta_rx_total += d_rx
                if d_tx < 500 * 1024 * 1024:
                    delta_tx_total += d_tx

    _last_dev_bytes = curr_bytes

    if delta_rx_total > 0 or delta_tx_total > 0:
        with _traffic_lock:
            _pending_rx += delta_rx_total
            _pending_tx += delta_tx_total

    _flush_traffic_db(force=False)

def _traffic_collector_worker():
    """Continuous background daemon: samples traffic every 2s with minimal CPU impact (<0.01%)."""
    time.sleep(1)
    while True:
        try:
            _update_traffic_accounting()
        except Exception:
            pass
        time.sleep(2)

def _format_bytes(b: int) -> str:
    """Format bytes into human readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    elif b < 1024 * 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"
    else:
        return f"{b / (1024 * 1024 * 1024 * 1024):.2f} TB"

def _get_traffic_history() -> dict:
    """Generate comprehensive Day / Week / Month / Year traffic report from SQLite."""
    now_dt = datetime.now()
    today_str = now_dt.strftime("%Y-%m-%d")
    yesterday_str = (now_dt - timedelta(days=1)).strftime("%Y-%m-%d")
    monday_str = (now_dt - timedelta(days=now_dt.weekday())).strftime("%Y-%m-%d")
    month_prefix = now_dt.strftime("%Y-%m")

    first_this_month = now_dt.replace(day=1)
    last_day_last_month = first_this_month - timedelta(days=1)
    last_month_prefix = last_day_last_month.strftime("%Y-%m")

    with _traffic_lock:
        pen_rx = _pending_rx
        pen_tx = _pending_tx

    res = {
        "today": {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0, "rx_human": "0 B", "tx_human": "0 B", "total_human": "0 B"},
        "yesterday": {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0, "rx_human": "0 B", "tx_human": "0 B", "total_human": "0 B"},
        "this_week": {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0, "rx_human": "0 B", "tx_human": "0 B", "total_human": "0 B"},
        "this_month": {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0, "rx_human": "0 B", "tx_human": "0 B", "total_human": "0 B"},
        "last_month": {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0, "rx_human": "0 B", "tx_human": "0 B", "total_human": "0 B"},
        "year_total": {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0, "rx_human": "0 B", "tx_human": "0 B", "total_human": "0 B"},
        "hourly_today": [],
        "daily_30d": [],
        "monthly_12m": []
    }

    try:
        conn = sqlite3.connect(TRAFFIC_DB_PATH, timeout=5)
        cur = conn.cursor()

        # 1. Today
        cur.execute("SELECT rx_bytes, tx_bytes FROM daily_traffic WHERE date = ?", (today_str,))
        row = cur.fetchone()
        t_rx = (row[0] if row else 0) + pen_rx
        t_tx = (row[1] if row else 0) + pen_tx
        t_tot = t_rx + t_tx
        res["today"] = {
            "rx_bytes": t_rx, "tx_bytes": t_tx, "total_bytes": t_tot,
            "rx_human": _format_bytes(t_rx), "tx_human": _format_bytes(t_tx), "total_human": _format_bytes(t_tot)
        }

        # 2. Yesterday
        cur.execute("SELECT rx_bytes, tx_bytes FROM daily_traffic WHERE date = ?", (yesterday_str,))
        row = cur.fetchone()
        y_rx = row[0] if row else 0
        y_tx = row[1] if row else 0
        y_tot = y_rx + y_tx
        res["yesterday"] = {
            "rx_bytes": y_rx, "tx_bytes": y_tx, "total_bytes": y_tot,
            "rx_human": _format_bytes(y_rx), "tx_human": _format_bytes(y_tx), "total_human": _format_bytes(y_tot)
        }

        # 3. This Week (from Monday)
        cur.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM daily_traffic WHERE date >= ?", (monday_str,))
        row = cur.fetchone()
        w_rx = (row[0] if row and row[0] else 0) + pen_rx
        w_tx = (row[1] if row and row[1] else 0) + pen_tx
        w_tot = w_rx + w_tx
        res["this_week"] = {
            "rx_bytes": w_rx, "tx_bytes": w_tx, "total_bytes": w_tot,
            "rx_human": _format_bytes(w_rx), "tx_human": _format_bytes(w_tx), "total_human": _format_bytes(w_tot)
        }

        # 4. This Month
        cur.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM daily_traffic WHERE date LIKE ?", (f"{month_prefix}%",))
        row = cur.fetchone()
        m_rx = (row[0] if row and row[0] else 0) + pen_rx
        m_tx = (row[1] if row and row[1] else 0) + pen_tx
        m_tot = m_rx + m_tx
        res["this_month"] = {
            "rx_bytes": m_rx, "tx_bytes": m_tx, "total_bytes": m_tot,
            "rx_human": _format_bytes(m_rx), "tx_human": _format_bytes(m_tx), "total_human": _format_bytes(m_tot)
        }

        # 5. Last Month
        cur.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM daily_traffic WHERE date LIKE ?", (f"{last_month_prefix}%",))
        row = cur.fetchone()
        lm_rx = row[0] if row and row[0] else 0
        lm_tx = row[1] if row and row[1] else 0
        lm_tot = lm_rx + lm_tx
        res["last_month"] = {
            "rx_bytes": lm_rx, "tx_bytes": lm_tx, "total_bytes": lm_tot,
            "rx_human": _format_bytes(lm_rx), "tx_human": _format_bytes(lm_tx), "total_human": _format_bytes(lm_tot)
        }

        # 6. Year Total (up to 365 days rolling)
        cur.execute("SELECT SUM(rx_bytes), SUM(tx_bytes) FROM daily_traffic")
        row = cur.fetchone()
        yr_rx = (row[0] if row and row[0] else 0) + pen_rx
        yr_tx = (row[1] if row and row[1] else 0) + pen_tx
        yr_tot = yr_rx + yr_tx
        res["year_total"] = {
            "rx_bytes": yr_rx, "tx_bytes": yr_tx, "total_bytes": yr_tot,
            "rx_human": _format_bytes(yr_rx), "tx_human": _format_bytes(yr_tx), "total_human": _format_bytes(yr_tot)
        }

        # 7. Hourly Today (00:00 - 23:00)
        cur.execute("SELECT hour_key, rx_bytes, tx_bytes FROM hourly_traffic WHERE hour_key LIKE ? ORDER BY hour_key ASC", (f"{today_str}%",))
        hourly_map = {}
        for h_key, rx, tx in cur.fetchall():
            hh = h_key.split(" ")[1].split(":")[0]
            hourly_map[hh] = (rx, tx)

        current_hour_str = f"{now_dt.hour:02d}"
        hourly_list = []
        for h in range(24):
            hh = f"{h:02d}"
            rx, tx = hourly_map.get(hh, (0, 0))
            if hh == current_hour_str:
                rx += pen_rx
                tx += pen_tx
            hourly_list.append({
                "label": f"{hh}:00",
                "rx_mb": round(rx / (1024 * 1024), 2),
                "tx_mb": round(tx / (1024 * 1024), 2),
                "total_mb": round((rx + tx) / (1024 * 1024), 2)
            })
        res["hourly_today"] = hourly_list

        # 8. Daily 30 Days
        cur.execute("""
            SELECT date, rx_bytes, tx_bytes 
            FROM daily_traffic 
            WHERE date >= date('now', 'localtime', '-30 day') 
            ORDER BY date ASC
        """)
        daily_rows = cur.fetchall()
        daily_map = {r[0]: (r[1], r[2]) for r in daily_rows}
        daily_list = []
        for i in range(29, -1, -1):
            d_str = (now_dt - timedelta(days=i)).strftime("%Y-%m-%d")
            rx, tx = daily_map.get(d_str, (0, 0))
            if d_str == today_str:
                rx += pen_rx
                tx += pen_tx
            daily_list.append({
                "label": d_str[5:],
                "full_date": d_str,
                "rx_mb": round(rx / (1024 * 1024), 1),
                "tx_mb": round(tx / (1024 * 1024), 1),
                "total_mb": round((rx + tx) / (1024 * 1024), 1)
            })
        res["daily_30d"] = daily_list

        # 9. Monthly 12 Months
        cur.execute("""
            SELECT substr(date, 1, 7) as ym, SUM(rx_bytes), SUM(tx_bytes)
            FROM daily_traffic
            GROUP BY ym
            ORDER BY ym ASC
            LIMIT 12
        """)
        monthly_rows = cur.fetchall()
        monthly_map = {r[0]: (r[1], r[2]) for r in monthly_rows}
        monthly_list = []
        for i in range(11, -1, -1):
            y = now_dt.year
            m = now_dt.month - i
            while m <= 0:
                m += 12
                y -= 1
            ym_str = f"{y:04d}-{m:02d}"
            rx, tx = monthly_map.get(ym_str, (0, 0))
            if ym_str == month_prefix:
                rx += pen_rx
                tx += pen_tx
            monthly_list.append({
                "label": ym_str,
                "rx_gb": round(rx / (1024 * 1024 * 1024), 2),
                "tx_gb": round(tx / (1024 * 1024 * 1024), 2),
                "total_gb": round((rx + tx) / (1024 * 1024 * 1024), 2)
            })
        res["monthly_12m"] = monthly_list

        conn.close()
    except Exception as e:
        print(f"[!] _get_traffic_history query error: {e}")

    return res



def _parse_tag_output(raw: str) -> dict:
    """Accurately parse tag-based shell output: === TAG === ..."""
    parsed = {}
    curr_tag = None
    curr_lines = []
    for line in raw.splitlines():
        line_s = line.strip()
        if line_s.startswith("===") and line_s.endswith("==="):
            if curr_tag:
                parsed[curr_tag] = "\n".join(curr_lines).strip()
            curr_tag = line_s.replace("===", "").strip()
            curr_lines = []
        else:
            curr_lines.append(line)
    if curr_tag:
        parsed[curr_tag] = "\n".join(curr_lines).strip()
    return parsed


def _get_system_status():
    """Collect comprehensive K40S hardware, thermal, and network status."""
    status = {}

    # 1. Battery & Power Thermals
    try:
        def read_file(p):
            try:
                with open(p, "r") as f:
                    return f.read().strip()
            except Exception:
                return ""

        cap = read_file("/sys/class/power_supply/battery/capacity")
        temp = read_file("/sys/class/power_supply/battery/temp")
        current = read_file("/sys/class/power_supply/battery/current_now")
        voltage = read_file("/sys/class/power_supply/battery/voltage_now")
        batt_status = read_file("/sys/class/power_supply/battery/status")
        health = read_file("/sys/class/power_supply/battery/health") or "Good"
        charger_temp = read_file("/sys/class/power_supply/battery/charger_temp")
        cycle_count = read_file("/sys/class/power_supply/battery/cycle_count")
        charge_full = read_file("/sys/class/power_supply/battery/charge_full")
        charge_full_design = read_file("/sys/class/power_supply/battery/charge_full_design")

        usb_present = read_file("/sys/class/power_supply/usb/present") == "1"
        usb_type = read_file("/sys/class/power_supply/usb/type") or "USB"
        pd_active = read_file("/sys/class/power_supply/usb/pd_active") == "1"
        bypass_mode = read_file("/sys/class/power_supply/usb/enable_bypass_mode") == "1"
        input_suspend = read_file("/sys/class/power_supply/battery/input_suspend") == "1"

        temp_c = round(float(temp) / 10.0, 1) if temp else 0.0
        charger_temp_c = round(float(charger_temp) / 10.0, 1) if charger_temp else 0.0
        current_ma = round(float(current) / 1000.0, 1) if current else 0.0
        volt_v = round(float(voltage) / 1000000.0, 2) if voltage else 0.0
        power_w = round(abs(current_ma * volt_v) / 1000.0, 2)

        # Determine human-readable status
        if bypass_mode or (usb_present and (input_suspend or batt_status == "Discharging")):
            status_text = "旁路供电"
            status_desc = "旁路供电保护中 (插电不伤电池)"
            status_icon = "🛡️"
            status_badge = "bypass"
        elif batt_status == "Charging":
            status_text = "极速快充" if pd_active else "正在充电"
            status_desc = f"USB-PD 9V 快速充电中 (+{current_ma} mA)"
            status_icon = "⚡"
            status_badge = "charging"
        elif batt_status == "Full":
            status_text = "已充满"
            status_desc = "电池已达 100% 满电保护状态"
            status_icon = "🟢"
            status_badge = "full"
        elif batt_status == "Not charging":
            status_text = "停止充电"
            status_desc = "达到充电上限，保护性停充"
            status_icon = "⏸️"
            status_badge = "not_charging"
        else:
            status_text = "电池放电"
            status_desc = f"纯电池供电中 (-{current_ma} mA)"
            status_icon = "🔋"
            status_badge = "discharging"

        full_mah = round(int(charge_full) / 1000) if (charge_full and charge_full.isdigit()) else 3937
        design_mah = round(int(charge_full_design) / 1000) if (charge_full_design and charge_full_design.isdigit()) else 4500
        health_pct = round((full_mah / design_mah) * 100, 1) if (full_mah and design_mah) else 87.5

        status["battery"] = {
            "capacity": int(cap) if cap and cap.isdigit() else 0,
            "temp": temp_c,
            "charger_temp": charger_temp_c,
            "current_ma": current_ma,
            "voltage_v": volt_v,
            "power_w": power_w,
            "status": batt_status or "Unknown",
            "status_text": status_text,
            "status_desc": status_desc,
            "status_icon": status_icon,
            "status_badge": status_badge,
            "health": health,
            "health_pct": health_pct,
            "cycle_count": int(cycle_count) if (cycle_count and cycle_count.isdigit()) else 0,
            "charge_full_mah": full_mah,
            "design_mah": design_mah,
            "usb_present": usb_present,
            "usb_type": "USB-PD (9V)" if pd_active else usb_type,
            "bypass_active": bypass_mode or input_suspend
        }
    except Exception as e:
        status["battery"] = {"error": str(e)}

    # 2. CPU Load & RAM
    try:
        with open("/proc/loadavg", "r") as f:
            loads = f.read().strip().split()[:3]
        status["loadavg"] = " ".join(loads)

        with open("/proc/meminfo", "r") as f:
            mem_lines = f.readlines()
        mem = {}
        for line in mem_lines:
            parts = line.split(":")
            if len(parts) == 2:
                k = parts[0].strip()
                v = parts[1].strip().split()[0]
                mem[k] = int(v) if v.isdigit() else 0

        total_ram = mem.get("MemTotal", 0) // 1024
        avail_ram = mem.get("MemAvailable", 0) // 1024
        used_ram = total_ram - avail_ram
        total_swap = mem.get("SwapTotal", 0) // 1024
        free_swap = mem.get("SwapFree", 0) // 1024
        used_swap = total_swap - free_swap

        zram_total_mb = 0
        zram_used_mb = 0
        zram_prio = 0
        swapfile_total_mb = 0
        swapfile_used_mb = 0
        swapfile_prio = 0
        try:
            with open("/proc/swaps", "r") as sf:
                for line in sf.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        dev_name = parts[0]
                        size_mb = int(parts[2]) // 1024
                        u_mb = int(parts[3]) // 1024
                        pri = int(parts[4])
                        if "zram" in dev_name:
                            zram_total_mb += size_mb
                            zram_used_mb += u_mb
                            zram_prio = pri
                        else:
                            swapfile_total_mb += size_mb
                            swapfile_used_mb += u_mb
                            swapfile_prio = pri
        except Exception:
            pass

        swappiness = 100
        try:
            with open("/proc/sys/vm/swappiness", "r") as f:
                swappiness = int(f.read().strip())
        except Exception:
            pass

        status["memory"] = {
            "total_ram_mb": total_ram,
            "used_ram_mb": used_ram,
            "ram_percent": round((used_ram / total_ram * 100), 1) if total_ram else 0,
            "total_swap_mb": total_swap,
            "used_swap_mb": used_swap,
            "swap_percent": round((used_swap / total_swap * 100), 1) if total_swap else 0,
            "zram_total_mb": zram_total_mb,
            "zram_used_mb": zram_used_mb,
            "zram_prio": zram_prio,
            "swapfile_total_mb": swapfile_total_mb,
            "swapfile_used_mb": swapfile_used_mb,
            "swapfile_prio": swapfile_prio,
            "swappiness": swappiness
        }
    except Exception as e:
        status["memory"] = {"error": str(e)}

    # 3. Uptime
    try:
        with open("/proc/uptime", "r") as f:
            up_secs = float(f.read().split()[0])
        h = int(up_secs // 3600)
        m = int((up_secs % 3600) // 60)
        s = int(up_secs % 60)
        status["uptime"] = f"{h}h {m}m {s}s"
    except Exception:
        status["uptime"] = "N/A"

    # 4. Network Interfaces
    try:
        res = _run_host_shell("ip -o -4 addr show | awk '{print $2, $4}'")
        ips = {}
        for line in res.splitlines():
            parts = line.strip().split()
            if len(parts) == 2:
                ips[parts[0]] = parts[1]
        status["interfaces"] = ips
    except Exception:
        status["interfaces"] = {}


    # 4.5. Internal Storage (/sdcard)
    try:
        import shutil
        total_s, used_s, free_s = shutil.disk_usage("/sdcard")
        status["storage"] = {
            "total_gb": round(total_s / (1024**3), 1),
            "used_gb": round(used_s / (1024**3), 1),
            "free_gb": round(free_s / (1024**3), 1),
            "percent": round(used_s / total_s * 100, 1)
        }
    except Exception:
        status["storage"] = {"total_gb": 106.0, "used_gb": 36.0, "free_gb": 70.0, "percent": 34.0}

    # 5. Core Toggles & Services Status (Fixed Robust Parser!)
    try:
        check_script = """
echo "=== WATCHDOG ==="
ps -ef | grep -E "watchdog.sh" | grep -v grep | awk '{print $2}'
echo "=== ANTI_CDRX ==="
ps -ef | grep -E "ping -i 0.2" | grep -v grep | awk '{print $2}'
echo "=== ETH_TETHER ==="
dumpsys tethering 2>/dev/null | grep -i "__ETH__ - TetheredState"
echo "=== ETH_CARRIER ==="
cat /sys/class/net/__ETH__/carrier 2>/dev/null || echo 0
echo "=== WIFI_POWERSAVE ==="
iw dev __STA__ get power_save 2>/dev/null
echo "=== QOS_500B ==="
iptables -t mangle -C POSTROUTING -p udp -m length --length 0:500 -j DSCP --set-dscp-class EF 2>/dev/null && echo "1" || echo "0"
echo "=== QOS_CS2 ==="
iptables -t mangle -C PREROUTING -p udp --dport 27000:27065 -j DSCP --set-dscp-class EF 2>/dev/null && echo "1" || echo "0"
echo "=== PRIV_DNS ==="
settings get global private_dns_mode 2>/dev/null
echo "=== TCP_ALGO ==="
sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null
echo "=== RPS_WLAN ==="
cat /sys/class/net/__STA__/queues/rx-0/rps_cpus 2>/dev/null || echo "0"
echo "=== CAKE_QDISC ==="
tc qdisc show dev __CELL__ 2>/dev/null | head -n 1
echo "=== HOTSPOT_ACT ==="
ip -4 addr show __HOTSPOT__ 2>/dev/null | grep "inet "
echo "=== WEBDAV_ACT ==="
ps -ef | grep -E "webdav_server.py" | grep -v grep | awk '{print $2}'
echo "=== WIFI_ON ==="
settings get global wifi_on 2>/dev/null || echo 0
"""
        check_script = (check_script
                        .replace("__ETH__", C.ETH_IF)
                        .replace("__STA__", C.WIFI_STA_IF)
                        .replace("__CELL__", C.CELLULAR_IF)
                        .replace("__HOTSPOT__", C.HOTSPOT_IF))
        raw = _run_host_shell(check_script)
        parsed = _parse_tag_output(raw)

        status["toggles"] = {
            "watchdog": bool(parsed.get("WATCHDOG")),
            "anti_cdrx": bool(parsed.get("ANTI_CDRX")),
            "eth_tethered": f"{C.ETH_IF} - TetheredState" in parsed.get("ETH_TETHER", ""),
            "eth_carrier": parsed.get("ETH_CARRIER", "0").strip() == "1",
            "wifi_master": parsed.get("WIFI_ON", "0").strip() == "1",
            "wifi_power_save": "on" in parsed.get("WIFI_POWERSAVE", "").lower(),
            "qos_500b": parsed.get("QOS_500B", "0").strip() == "1",
            "qos_cs2": parsed.get("QOS_CS2", "0").strip() == "1",
            "private_dns": parsed.get("PRIV_DNS", "off").strip(),
            "tcp_congestion": parsed.get("TCP_ALGO", "bbr3").strip(),
            "rps_enabled": parsed.get("RPS_WLAN", "0").strip() == "70",
            "cake_qdisc": parsed.get("CAKE_QDISC", "cake"),
            "hotspot_active": bool(parsed.get("HOTSPOT_ACT")),
            "webdav_active": bool(parsed.get("WEBDAV_ACT"))
        }
    except Exception as e:
        status["toggles"] = {"error": str(e)}

    return status


_client_speed_cache = {}

def _format_size(bytes_val):
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024*1024):.1f} MB"
    else:
        return f"{bytes_val / (1024*1024*1024):.2f} GB"

def _get_mac_vendor(mac):
    prefix = mac.replace(":", "")[:6].upper()
    oui_table = {
        "08B4D2": "Intel Wi-Fi (PC主机)",
        "BAB5D6": "Xiaomi / Redmi (移动终端)",
        "E0DCFF": "Xiaomi / Redmi (移动终端)",
        "701124": "Apple (iPhone/iPad)",
        "34F64B": "Apple (Mac/iPhone)",
        "F44D30": "Google Pixel",
        "B42E99": "Huawei",
        "94F827": "TP-Link",
        "001132": "Synology NAS",
        "18C04E": "Espressif IoT (智能家居)",
        "D83ADD": "Realtek 网卡",
    }
    return oui_table.get(prefix, "")

def _get_conntrack_traffic_map():
    traffic_map = {}
    try:
        raw = _run_host_shell("cat /proc/net/nf_conntrack 2>/dev/null || cat /proc/net/ip_conntrack 2>/dev/null")
        for line in raw.splitlines():
            parts = line.split()
            ip = None
            tx = 0
            rx = 0
            for p in parts:
                if p.startswith("src=") and ip is None:
                    c = p[4:]
                    if c.startswith("192.168."):
                        ip = c
                elif p.startswith("bytes="):
                    v = int(p[6:]) if p[6:].isdigit() else 0
                    if tx == 0:
                        tx = v
                    else:
                        rx = v
            if ip:
                if ip not in traffic_map:
                    traffic_map[ip] = {"rx": 0, "tx": 0}
                traffic_map[ip]["tx"] += tx
                traffic_map[ip]["rx"] += rx
    except Exception:
        pass
    return traffic_map

def _calc_ip_speed(ip, cur_bytes, direction):
    global _client_speed_cache
    key = f"{ip}_{direction}"
    now = time.time()
    if key in _client_speed_cache:
        prev_bytes, prev_time = _client_speed_cache[key]
        dt = max(0.2, now - prev_time)
        diff = max(0, cur_bytes - prev_bytes)
        kbps = (diff / dt) / 1024
        _client_speed_cache[key] = (cur_bytes, now)
        if kbps >= 1024:
            return f"{kbps / 1024:.1f} MB/s"
        return f"{kbps:.1f} KB/s"
    else:
        _client_speed_cache[key] = (cur_bytes, now)
        return "0.0 KB/s"

def _get_clients_list():
    """Parse local Hotspot & USB clients, traffic stats, and query Router clients if online."""
    # 2026-10-16: 路由器探测节流——60s 内直接复用上次结果文件（断电时 3s 轮询不再卡 1s）
    global _router_probe_skip
    try:
        if time.time() - _router_probe_skip < 60:
            _skip_router = True
        else:
            _router_probe_skip = time.time()
            _skip_router = False
    except Exception:
        _skip_router = False
    clients = []
    blocked_macs = set()
    try:
        if os.path.exists(BLOCKED_MACS_FILE):
            with open(BLOCKED_MACS_FILE, "r") as f:
                blocked_macs = set(json.load(f))
    except Exception:
        pass

    traffic_map = _get_conntrack_traffic_map()
    local_ips = set()

    # 2026-10-16: 预读 udhcpd 租约建立 MAC->主机名 映射（终版：正向扫描）
    # 真实结构（od 实证）：MAC 6B 紧邻 hostname 16B（前面是 expire/IP），记录 30B 步进但可变。
    # 正向扫：找 ARP 表中每个 MAC 的字节序列，取其后 16B 内的最长可打印串为主机名。
    _lease_names = {}
    try:
        with open("/data/local/tmp/udhcpd.leases", "rb") as _lf:
            _raw = _lf.read()
        for _line in open("/proc/net/arp").readlines()[1:]:
            _p = _line.split()
            if len(_p) < 4 or _p[3] == "00:00:00:00:00:00":
                continue
            _amac = _p[3].lower()
            try:
                _amacb = bytes(int(x, 16) for x in _amac.split(":"))
            except ValueError:
                continue
            _pos = _raw.find(_amacb)
            while _pos != -1:
                _tail = _raw[_pos+6:_pos+22]
                _m2 = re.match(rb"[\x20-\x7e]{3,}", _tail.lstrip(b"\x00"))
                if _m2:
                    _hn = _m2.group().decode("ascii", errors="replace").strip()
                    if len(_hn) >= 3:
                        _lease_names[_amac] = _hn
                        break
                _pos = _raw.find(_amacb, _pos+1)
    except Exception:
        pass

    # 1. Local Hotspot & USB clients from ARP
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 6:
                ip = parts[0]
                mac = parts[3].lower()
                dev = parts[5]
                # 2026-10-16: 只算真正在线的设备——Flags 0x2=ATF_COM(已解析完成)，
                # 0x0 是 STALE/过期残留；同此修掉"已连设备数量异常"
                if parts[2] != "0x2":
                    continue
                if mac != "00:00:00:00:00:00" and not ip.startswith("127."):
                    local_ips.add(ip)
                    if dev == C.ETH_IF:
                        source = "🔌 USB直连路由"
                    elif "wlan" in dev:
                        source = "🔥 5G 热点"
                    else:
                        source = f"📱 {dev}"

                    # 设备名优先级：DHCP租约主机名 > MAC厂商 > IP尾缀（不再做 DNS 反解，消除卡顿）
                    name = _lease_names.get(mac) or _get_mac_vendor(mac) or f"终端 ({ip.split('.')[-1]})"

                    t_info = traffic_map.get(ip, {"rx": 0, "tx": 0})
                    speed_rx = _calc_ip_speed(ip, t_info["rx"], "rx")
                    speed_tx = _calc_ip_speed(ip, t_info["tx"], "tx")
                    total_bytes = t_info["rx"] + t_info["tx"]

                    clients.append({
                        "name": name,
                        "ip": ip,
                        "mac": mac,
                        "interface": dev,
                        "source": source,
                        "speed_rx": speed_rx,
                        "speed_tx": speed_tx,
                        "total_traffic": _format_size(total_bytes) if total_bytes > 0 else "< 1 MB",
                        "status": "已阻断" if mac in blocked_macs else "在线",
                        "blocked": mac in blocked_macs
                    })
    except Exception:
        pass

    # 2. Query Router clients if router is reachable
    router_online = False
    router_msg = "上游路由器当前离线 (断电或未连接)"
    try:
        if _skip_router:
            # 60s 节流窗口内：跳过阻塞探测（缓存超时后再探）
            raise RuntimeError("router probe throttled")
        import http.client as _hc
        _conn = _hc.HTTPConnection("192.168.1.1", 80, timeout=1.0)
        _conn.request("GET", "/cgi-bin/5g_clients", headers={"User-Agent": "CyberGate"})
        resp = _conn.getresponse()
        if resp.status == 200:
            r_data = json.loads(resp.read().decode("utf-8"))
            router_online = True
            router_msg = "OpenWrt 路由器在线运转中"
            for rc in r_data.get("clients", []):
                r_ip = rc.get("ip", "")
                if r_ip and r_ip not in local_ips:
                    clients.append({
                            "name": rc.get("hostname") or rc.get("name") or f"路由终端 ({r_ip.split('.')[-1]})",
                            "ip": r_ip,
                            "mac": rc.get("mac", "--").lower(),
                            "interface": rc.get("interface", "br-lan"),
                            "source": "🌐 路由器 Wi-Fi/LAN",
                            "speed_rx": rc.get("speed_rx", "--"),
                            "speed_tx": rc.get("speed_tx", "--"),
                            "total_traffic": rc.get("total_traffic", "--"),
                            "status": "在线",
                            "blocked": False
                        })
    except Exception:
        pass

    return {
        "clients": clients,
        "router_online": router_online,
        "router_message": router_msg,
        "total_count": len(clients)
    }

def _get_system_processes():
    """Extract CPU, RAM, GPU utilization and top process breakdown for performance monitor."""
    data = {
        "cpu": {"usage": 0, "load_1": "--", "load_5": "--", "load_15": "--", "cores": 8},
        "memory": {"total_mb": 7613, "used_mb": 0, "free_mb": 0, "available_mb": 0, "swap_total_mb": 0, "swap_used_mb": 0},
        "gpu": {"usage": 0, "freq_mhz": 0},
        "processes": []
    }

    # 1. GPU metrics (Adreno 650)
    try:
        raw_busy = _run_host_shell("cat /sys/class/kgsl/kgsl-3d0/gpu_busy_percentage 2>/dev/null").strip()
        data["gpu"]["usage"] = int(raw_busy.split()[0]) if raw_busy and raw_busy.split()[0].isdigit() else 0
        raw_freq = _run_host_shell("cat /sys/class/kgsl/kgsl-3d0/devfreq/cur_freq 2>/dev/null || cat /sys/class/kgsl/kgsl-3d0/gpuclk 2>/dev/null").strip()
        data["gpu"]["freq_mhz"] = int(raw_freq) // 1000000 if raw_freq.isdigit() else 0
    except Exception:
        pass

    # 2. CPU load average
    try:
        with open("/proc/loadavg", "r") as f:
            lparts = f.read().strip().split()
            if len(lparts) >= 3:
                data["cpu"]["load_1"] = lparts[0]
                data["cpu"]["load_5"] = lparts[1]
                data["cpu"]["load_15"] = lparts[2]
    except Exception:
        pass

    # 3. RAM metrics
    try:
        mem = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    k = parts[0].strip()
                    v = parts[1].strip().split()[0]
                    if v.isdigit():
                        mem[k] = int(v) // 1024
        total = mem.get("MemTotal", 7613)
        free = mem.get("MemFree", 0)
        avail = mem.get("MemAvailable", free)
        used = max(0, total - avail)
        swap_total = mem.get("SwapTotal", 0)
        swap_free = mem.get("SwapFree", 0)
        swap_used = max(0, swap_total - swap_free)

        data["memory"]["total_mb"] = total
        data["memory"]["used_mb"] = used
        data["memory"]["free_mb"] = free
        data["memory"]["available_mb"] = avail
        data["memory"]["swap_total_mb"] = swap_total
        data["memory"]["swap_used_mb"] = swap_used
    except Exception:
        pass

    # 4. Top Process Breakdown
    app_map = {
        "com.android.systemui": "系统界面 (SystemUI)",
        "system_server": "Android 核心框架 (system_server)",
        "surfaceflinger": "图形渲染合成 (SurfaceFlinger)",
        "com.coolapk.market": "酷安 (CoolApk)",
        "com.tencent.mm": "微信 (WeChat)",
        "com.tencent.mobileqq": "QQ",
        "com.topjohnwu.magisk": "Magisk 管理器",
        "cpe_webui.py": "CyberGate WebUI 后台服务",
        "hotspot_guardian.py": "5G 热点自愈守护",
        "watchdog.sh": "网络硬件防崩溃看门狗",
        "tailscaled": "Tailscale 穿透节点",
        "dnsmasq": "DNS / DHCP 路由解析",
        "adbd": "ADB 调试服务",
        "netd": "网络核心守护 (netd)",
        "vold": "存储管理服务 (vold)",
        "audioserver": "音频服务 (audioserver)",
        "cameraserver": "相机服务 (cameraserver)",
        "lmkd": "低内存杀手守护 (lmkd)"
    }

    try:
        raw_top = _run_host_shell("top -b -n 1 -m 35")
        lines = raw_top.splitlines()
        for line in lines[:8]:
            if "%cpu" in line:
                m_idle = re.search(r"(\d+)%idle", line)
                if m_idle:
                    idle = int(m_idle.group(1))
                    total_cpu = 800 if "800%" in line else 100
                    usage = max(0, min(100, int((total_cpu - idle) * 100 / total_cpu)))
                    data["cpu"]["usage"] = usage

        start_procs = False
        procs = []
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            if "PID" in line_str and "USER" in line_str and ("%CPU" in line_str or "ARGS" in line_str):
                start_procs = True
                continue
            if start_procs:
                parts = line_str.split(None, 11)
                if len(parts) >= 11:
                    pid = parts[0]
                    user = parts[1]
                    res = parts[5]
                    status = parts[7]
                    cpu_pct = parts[8]
                    mem_pct = parts[9]
                    args = parts[11] if len(parts) >= 12 else parts[10]

                    cmd_base = args.split()[0].split("/")[-1]
                    pkg = None
                    if "app_process" in args:
                        m_pkg = re.search(r"([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)", args)
                        if m_pkg:
                            pkg = m_pkg.group(1)
                    elif "." in cmd_base and not cmd_base.endswith(".sh") and not cmd_base.endswith(".py"):
                        pkg = cmd_base

                    friendly_name = app_map.get(pkg or cmd_base, "")
                    if not friendly_name:
                        for k, v in app_map.items():
                            if k in args:
                                friendly_name = v
                                break

                    display_name = friendly_name or pkg or cmd_base

                    procs.append({
                        "pid": int(pid) if pid.isdigit() else pid,
                        "name": display_name,
                        "raw_cmd": args[:100],
                        "package": pkg or "",
                        "user": user,
                        "cpu": float(cpu_pct) if cpu_pct.replace(".", "", 1).isdigit() else 0.0,
                        "mem": mem_pct,
                        "res": res,
                        "status": "运行中" if status == "R" else ("休眠" if status == "S" else ("空闲" if status == "I" else status)),
                        "can_kill": pid not in ("1", "0") and "cpe_webui" not in args
                    })
        data["processes"] = procs
    except Exception:
        pass

    return data

def _kill_process(pid, pkg=None):
    try:
        pid = int(pid)
        if pid in (1, 0, os.getpid()):
            return {"success": False, "message": "无法结束关键系统进程或自身服务"}
        _run_host_shell(f"kill -9 {pid}")
        if pkg and "." in pkg and "/" not in pkg:
            _run_host_shell(f"am force-stop {pkg} 2>/dev/null || true")
        return {"success": True, "message": f"进程 PID {pid} 已强制终止"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _get_cellular_deep_info():
    """Extract deep 5G carrier, band, ARFCN, PCI, TAC, RSRP, SINR from telephony registry."""
    sim_state = _run_host_shell("getprop gsm.sim.state").strip()
    raw = _run_host_shell("dumpsys telephony.registry")

    # Check if SIM card is absent
    has_sim = bool(sim_state and ("READY" in sim_state or "LOADED" in sim_state))
    if not has_sim and ("ABSENT" in sim_state or not sim_state) and "mCellIdentity=CellIdentity" not in raw:
        return {
            "sim_present": False,
            "sim_state": "未插卡 (ABSENT)",
            "operator": "未检测到 SIM 流量卡",
            "rat": "基带脱网待机",
            "mcc_mnc": "--",
            "band": "--",
            "arfcn": "--",
            "pci": "--",
            "tac": "--",
            "nci": "--",
            "rsrp": "--",
            "rsrq": "--",
            "sinr": "--",
            "level": 0,
            "apn": "--",
            "ip": "--",
            "iface": "--",
            "message": "当前未插入 SIM 流量卡。插入 5G/4G 卡后将自动建立蜂窝射频连接。"
        }

    # Default empty cellular info (no fake data)
    info = {
        "sim_present": True,
        "rat": "5G/4G 搜网中...",
        "operator": "正在驻留网络...",
        "mcc_mnc": "--",
        "band": "--",
        "arfcn": "--",
        "pci": "--",
        "tac": "--",
        "nci": "--",
        "rsrp": "--",
        "rsrq": "--",
        "sinr": "--",
        "level": 0,
        "apn": "--",
        "ip": "--",
        "iface": "--"
    }

    try:
        op_alpha = _run_host_shell("getprop gsm.operator.alpha").strip()
        op_numeric = _run_host_shell("getprop gsm.operator.numeric").strip()
        net_type = _run_host_shell("getprop gsm.network.type").strip()

        if op_alpha:
            info["operator"] = op_alpha
        if op_numeric:
            info["mcc_mnc"] = op_numeric
        if net_type:
            info["rat"] = "5G NR (SA/NSA)" if "NR" in net_type.upper() else f"4G ({net_type})"

        # 1. Try finding mRegistered=YES cell info (5G NR first, then 4G LTE)
        # 2026-10-16 修复：registry 含多个 CellInfoNr 块（空SIM槽填 MAX_INT），且嵌套 {}
        # 令原非贪婪正则在 mAdditionalPlmns = {} 提前截断——解析恒失败。
        # 新策略：遍历所有已注册 NR 块，取含有效 ssRsrp（-140..-30）的那个。
        reg_nr = None
        for _blk in re.finditer(r"CellInfoNr:\{ mRegistered=YES(.*?)CellSignalStrengthNr:\{(.*?)\} \}", raw, re.DOTALL):
            _sig = _blk.group(2)
            _chk = re.search(r"ssRsrp\s*=\s*(-?\d+)", _sig)
            if _chk and -140 <= int(_chk.group(1)) <= -30:
                reg_nr = _blk
                break
        reg_lte = re.search(r"CellInfoLte:\{\s*mRegistered=YES(.*?)\}", raw, re.DOTALL)

        if reg_nr:
            info["rat"] = "5G NR (SA 独立组网)"
            target_block = reg_nr.group(1) + " " + reg_nr.group(2)
            pci_m = re.search(r"mPci\s*=\s*(\d+)", target_block)
            if pci_m and int(pci_m.group(1)) < 10000:
                info["pci"] = int(pci_m.group(1))
            tac_m = re.search(r"mTac\s*=\s*(\d+)", target_block)
            if tac_m and int(tac_m.group(1)) < 20000000:
                info["tac"] = int(tac_m.group(1))
            arfcn_m = re.search(r"mNrArfcn\s*=\s*(\d+)", target_block)
            if arfcn_m and int(arfcn_m.group(1)) < 20000000:
                info["arfcn"] = int(arfcn_m.group(1))
            bands_m = re.search(r"mBands\s*=\s*\[(.*?)\]", target_block)
            if bands_m and bands_m.group(1).strip():
                info["band"] = f"n{bands_m.group(1).strip()}"
            rsrp_m = re.search(r"ssRsrp\s*=\s*(-?\d+)", target_block)
            if rsrp_m and -140 <= int(rsrp_m.group(1)) <= -30:
                info["rsrp"] = int(rsrp_m.group(1))
            rsrq_m = re.search(r"ssRsrq\s*=\s*(-?\d+)", target_block)
            if rsrq_m and -30 <= int(rsrq_m.group(1)) <= 10:
                info["rsrq"] = int(rsrq_m.group(1))
            sinr_m = re.search(r"ssSinr\s*=\s*(-?\d+)", target_block)
            if sinr_m and -20 <= int(sinr_m.group(1)) <= 50:
                info["sinr"] = int(sinr_m.group(1))
            level_m = re.search(r"level\s*=\s*(\d+)", target_block)
            if level_m:
                info["level"] = min(4, int(level_m.group(1)))
        elif reg_lte:
            info["rat"] = "4G LTE"
            target_block = reg_lte.group(1)
            pci_m = re.search(r"mCi\s*=\s*(\d+)", target_block)
            if pci_m:
                info["nci"] = int(pci_m.group(1))
            pci_val = re.search(r"mPci\s*=\s*(\d+)", target_block)
            if pci_val:
                info["pci"] = int(pci_val.group(1))
            earfcn_m = re.search(r"mEarfcn\s*=\s*(\d+)", target_block)
            if earfcn_m:
                info["arfcn"] = int(earfcn_m.group(1))
            rsrp_m = re.search(r"rsrp\s*=\s*(-?\d+)", target_block)
            if rsrp_m and -140 <= int(rsrp_m.group(1)) <= -30:
                info["rsrp"] = int(rsrp_m.group(1))
            rssnr_m = re.search(r"rssnr\s*=\s*(-?\d+)", target_block)
            if rssnr_m:
                info["sinr"] = int(rssnr_m.group(1))
        else:
            # Fallback to Phone Id=0 section
            top_chunk = raw.split("notifyServiceStateForSubscriber")[0] if "notifyServiceStateForSubscriber" in raw else raw[:5000]
            cid_m = re.search(r"mCellIdentity=CellIdentity(Nr|Lte):\{([^}]+)\}", top_chunk)
            if cid_m:
                ctype = "5G NR" if cid_m.group(1) == "Nr" else "4G LTE"
                info["rat"] = ctype
                c_body = cid_m.group(2)
                pci_m = re.search(r"mPci\s*=\s*(\d+)", c_body)
                if pci_m and int(pci_m.group(1)) not in (0, 2147483647):
                    info["pci"] = int(pci_m.group(1))
                arfcn_m = re.search(r"m(?:NrArfcn|Earfcn)\s*=\s*(\d+)", c_body)
                if arfcn_m and int(arfcn_m.group(1)) not in (0, 2147483647):
                    info["arfcn"] = int(arfcn_m.group(1))
                tac_m = re.search(r"mTac\s*=\s*(\d+)", c_body)
                if tac_m and int(tac_m.group(1)) not in (0, 2147483647):
                    info["tac"] = int(tac_m.group(1))
                band_m = re.search(r"mBands\s*=\s*\[(.*?)\]", c_body)
                if band_m and band_m.group(1).strip():
                    info["band"] = f"n{band_m.group(1).strip()}" if ctype == "5G NR" else f"B{band_m.group(1).strip()}"

        # Carrier branding fallback from raw dump if prop missing
        if info["operator"] in ("正在驻留网络...", ""):
            if "CHN-CT" in raw or "China Telecom" in raw or "46011" in raw:
                info["operator"] = "中国电信 (China Telecom)"
                info["mcc_mnc"] = "460-11"
            elif "CMCC" in raw or "China Mobile" in raw or "46000" in raw:
                info["operator"] = "中国移动 (China Mobile)"
                info["mcc_mnc"] = "460-00"
            elif "CUCC" in raw or "China Unicom" in raw or "46001" in raw:
                info["operator"] = "中国联通 (China Unicom)"
                info["mcc_mnc"] = "460-01"

    except Exception:
        pass
    return info


def _scan_nearby_cells(mode="all"):
    """Parse active and neighboring 4G/5G cells from telephony registry without duplicate historical dumps."""
    sim_state = _run_host_shell("getprop gsm.sim.state").strip()
    raw = _run_host_shell("dumpsys telephony.registry")

    # Check if SIM card is absent
    has_sim = bool(sim_state and ("READY" in sim_state or "LOADED" in sim_state))
    if not has_sim and ("ABSENT" in sim_state or not sim_state) and "mCellIdentity=CellIdentity" not in raw:
        return {
            "sim_present": False,
            "cells": [],
            "message": "当前未插入 SIM 流量卡，5G/4G 射频基带处于脱网休眠状态。插入 SIM 流量卡后即可实时扫描当前主基站与周边邻区基站。"
        }

    cells = []
    seen = set()

    # 1. Parse Primary Serving Cell from top Phone Id=0 section
    top_chunk = raw.split("notifyServiceStateForSubscriber")[0] if "notifyServiceStateForSubscriber" in raw else raw[:5000]

    cell_id_match = re.search(r"mCellIdentity=CellIdentity(Nr|Lte):\{([^}]+)\}", top_chunk)
    sig_match = re.search(r"mSignalStrength=SignalStrength:\{([\s\S]*?primary=CellSignalStrength[A-Za-z]+)\}", top_chunk)

    if cell_id_match:
        ctype = "5G NR" if cell_id_match.group(1) == "Nr" else "4G LTE"
        content = cell_id_match.group(2)
        pci_m = re.search(r"mPci\s*=\s*(\d+)", content)
        arfcn_m = re.search(r"m(?:NrArfcn|Earfcn)\s*=\s*(\d+)", content)
        tac_m = re.search(r"mTac\s*=\s*(\d+)", content)
        band_m = re.search(r"mBands\s*=\s*\[(.*?)\]", content)
        nci_m = re.search(r"m(?:Nci|Ci)\s*=\s*(\d+)", content)
        alpha_m = re.search(r"mAlphaLong\s*=\s*([^\s,}]+)", content)

        pci = int(pci_m.group(1)) if pci_m else 0
        arfcn = int(arfcn_m.group(1)) if arfcn_m else 0

        rsrp_str = "--"
        sinr_str = "--"
        if sig_match:
            sig_content = sig_match.group(1)
            rsrp_m = re.search(r"(?:ssRsrp|rsrp)\s*=\s*(-?\d+)", sig_content)
            sinr_m = re.search(r"(?:ssSinr|rssnr)\s*=\s*(-?\d+)", sig_content)
            if rsrp_m and rsrp_m.group(1) not in ("2147483647", "-140", "0"):
                rsrp_str = f"{rsrp_m.group(1)} dBm"
            if sinr_m and sinr_m.group(1) not in ("2147483647", "-20"):
                sinr_str = f"{sinr_m.group(1)} dB"

        band_str = f"n{band_m.group(1)}" if (band_m and ctype == "5G NR") else (f"B{band_m.group(1)}" if band_m else "n78")
        op_name = "中国电信 (CT)"
        if "46000" in content or "CMCC" in content:
            op_name = "中国移动 (CM)"
        elif "46001" in content or "CUCC" in content or "UNICOM" in content:
            op_name = "中国联通 (CU)"
        elif alpha_m and alpha_m.group(1) != "null":
            op_name = alpha_m.group(1)

        if pci > 0 and (mode == "all" or (mode == "nr" and ctype == "5G NR") or (mode == "lte" and ctype == "4G LTE")):
            cells.append({
                "type": ctype,
                "registered": True,
                "pci": pci,
                "arfcn": arfcn,
                "tac": int(tac_m.group(1)) if tac_m else "--",
                "nci": int(nci_m.group(1)) if nci_m else "--",
                "band": band_str,
                "rsrp": rsrp_str,
                "sinr": sinr_str,
                "operator": op_name,
                "status": "已连接主小区 (Primary Serving)"
            })
            seen.add((ctype, pci, arfcn))

    # 2. Parse measured cells from active mCellInfo=[ ... ]
    for block in re.finditer(r"CellInfo(Nr|Lte):\{([\s\S]*?CellSignalStrength(?:Nr|Lte):\{[\s\S]*?\})\s*\}", top_chunk):
        ctype = "5G NR" if block.group(1) == "Nr" else "4G LTE"
        body = block.group(2)
        pci_m = re.search(r"mPci\s*=\s*(\d+)", body)
        arfcn_m = re.search(r"m(?:NrArfcn|Earfcn)\s*=\s*(\d+)", body)
        tac_m = re.search(r"mTac\s*=\s*(\d+)", body)
        band_m = re.search(r"mBands\s*=\s*\[(.*?)\]", body)
        nci_m = re.search(r"m(?:Nci|Ci)\s*=\s*(\d+)", body)
        rsrp_m = re.search(r"(?:ssRsrp|rsrp)\s*=\s*(-?\d+)", body)
        sinr_m = re.search(r"(?:ssSinr|rssnr)\s*=\s*(-?\d+)", body)
        alpha_m = re.search(r"mAlphaLong\s*=\s*([^\s,}]+)", body)

        pci = int(pci_m.group(1)) if pci_m else 0
        arfcn = int(arfcn_m.group(1)) if arfcn_m else 0
        if pci <= 0 or pci >= 1024 or (ctype, pci, arfcn) in seen:
            continue
        seen.add((ctype, pci, arfcn))

        rsrp_str = f"{rsrp_m.group(1)} dBm" if rsrp_m and rsrp_m.group(1) not in ("2147483647", "-140", "0") else "--"
        sinr_str = f"{sinr_m.group(1)} dB" if sinr_m and sinr_m.group(1) not in ("2147483647", "-20") else "--"
        band_str = f"n{band_m.group(1)}" if (band_m and ctype == "5G NR") else (f"B{band_m.group(1)}" if band_m else "n78")

        op_name = "中国电信 (CT)"
        if "46000" in body or "CMCC" in body:
            op_name = "中国移动 (CM)"
        elif "46001" in body or "CUCC" in body or "UNICOM" in body:
            op_name = "中国联通 (CU)"
        elif alpha_m and alpha_m.group(1) != "null":
            op_name = alpha_m.group(1)

        if mode == "all" or (mode == "nr" and ctype == "5G NR") or (mode == "lte" and ctype == "4G LTE"):
            cells.append({
                "type": ctype,
                "registered": False,
                "pci": pci,
                "arfcn": arfcn,
                "tac": int(tac_m.group(1)) if tac_m else "--",
                "nci": int(nci_m.group(1)) if nci_m else "--",
                "band": band_str,
                "rsrp": rsrp_str,
                "sinr": sinr_str,
                "operator": op_name,
                "status": "实测临近小区 (Active Neighbor)"
            })

    return {
        "sim_present": True,
        "cells": cells,
        "count": len(cells)
    }



def _get_wifi_list():
    """Scan and list surrounding Wi-Fi APs like Android Settings."""
    wifi_on = _run_host_shell("settings get global wifi_on").strip() == "1"
    if not wifi_on:
        return []
    _run_host_shell("cmd wifi start-scan 2>/dev/null")
    time.sleep(1)
    raw = _run_host_shell("cmd wifi list-scan-results")
    networks = []
    lines = raw.splitlines()
    for line in lines[1:]:
        line_str = line.strip()
        if not line_str:
            continue
        # Pattern: BSSID FREQ RSSI FLAGS SSID
        # Match BSSID (17 chars)
        m = re.match(r"^([0-9a-fA-F:]{17})\s+(\d+)\s+([-\d]+(?:\([^\)]+\))?)\s+([\d\.]+)\s+(.*?)\s+((?:\[[^\]]+\])+)$", line_str)
        if m:
            bssid = m.group(1)
            freq = m.group(2)
            rssi_str = m.group(3)
            ssid = m.group(5).strip()
            flags = m.group(6)
        else:
            parts = line_str.split()
            if len(parts) >= 6:
                bssid, freq, rssi_str = parts[0], parts[1], parts[2]
                flags = parts[-1]
                ssid = " ".join(parts[4:-1])
            else:
                continue

        # Extract numeric RSSI
        num_rssi_m = re.search(r"(-\d+)", rssi_str)
        rssi_num = int(num_rssi_m.group(1)) if num_rssi_m else -75
        quality = min(100, max(0, int(2 * (rssi_num + 100))))

        sec = "Open"
        if "WPA3" in flags:
            sec = "WPA3"
        elif "WPA2" in flags:
            sec = "WPA2"
        elif "WPA" in flags:
            sec = "WPA"

        is_5g = int(freq) > 4000 if freq.isdigit() else False

        if ssid:
            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "frequency": freq,
                "is_5g": is_5g,
                "rssi": rssi_num,
                "quality": quality,
                "security": sec
            })
    networks.sort(key=lambda x: x["quality"], reverse=True)
    return networks


def _get_hotspot_details():
    """Read SoftAP configuration from XML and schedule settings."""
    details = {
        "ssid": "CyberGate",
        "passphrase": "",
        "security_type": 2,
        "band": 2,  # 1=2.4GHz, 2=5GHz
        "ax_enabled": True,
        "auto_shutdown": True,
        "active": False,
        "ip": "",
        "schedule": {
            "enabled": True,
            "always_on": False,
            "auto_heal": True,
            "start_time": "23:00",
            "end_time": "07:00",
            "days": [7, 1, 2, 3, 4]  # 周日~周四 23:00~次日07:00开启，周五周六不断电保持关闭
        }
    }

    try:
        xml_raw = _run_host_shell(f"cat {SOFTAP_XML}")
        root = ET.fromstring(xml_raw)
        softap = root.find("SoftAp")
        if softap is not None:
            for el in softap:
                name = el.attrib.get("name")
                if name == "WifiSsid":
                    details["ssid"] = el.text.strip('"') if el.text else "CyberGate"
                elif name == "Passphrase":
                    details["passphrase"] = el.text or ""
                elif name == "SecurityType":
                    details["security_type"] = int(el.attrib.get("value", 2))
                elif name == "80211axEnabled":
                    details["ax_enabled"] = el.attrib.get("value", "true") == "true"
                elif name == "AutoShutdownEnabled":
                    details["auto_shutdown"] = el.attrib.get("value", "true") == "true"
                elif el.tag == "BandChannelMap" or name == "BandChannelMap":
                    # 2026-10-16 修复：<BandChannelMap> 标签本身无 name 属性（此前按
                    # name 匹配永不命中，band/channel 一直是默认值假象）。改按 tag 匹配。
                    bc = el.find("BandChannel")
                    if bc is not None:
                        band_el = bc.find("int[@name='Band']")
                        if band_el is not None:
                            details["band"] = int(band_el.attrib.get("value", 2))
                        # 回读锁定信道（0=ACS 自动），形成 save/get 闭环
                        chan_el = bc.find("int[@name='Channel']")
                        if chan_el is not None:
                            details["channel"] = int(chan_el.attrib.get("value", 0))
    except Exception:
        pass

    # Check active state
    ip_raw = _run_host_shell("ip -4 addr show " + C.HOTSPOT_IF + " 2>/dev/null | grep 'inet ' | awk '{print $2}'")
    if ip_raw:
        details["active"] = True
        details["ip"] = ip_raw.strip()

    # Read schedule
    try:
        if os.path.exists(SCHEDULE_JSON):
            with open(SCHEDULE_JSON, "r") as f:
                details["schedule"] = json.load(f)
    except Exception:
        pass

    return details


def _save_hotspot_details(data: dict):
    """Update SoftAp XML and restart SoftAp if needed."""
    ssid = data.get("ssid", "")
    passphrase = data.get("passphrase", "")
    band = int(data.get("band", 3))
    # 支持锁定具体信道（0=ACS 自动）。按环境扫描结果选干净信道，5GHz+80MHz 吞吐延迟均衡
    channel = int(data.get("channel", 0))
    ax = "true" if data.get("ax_enabled", True) else "false"
    auto_shut = "true" if data.get("auto_shutdown", True) else "false"

    xml_content = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<WifiConfigStoreData>
<int name="Version" value="3" />
<SoftAp>
<string name="WifiSsid">&quot;{ssid}&quot;</string>
<boolean name="HiddenSSID" value="false" />
<int name="SecurityType" value="2" />
<string name="Passphrase">{passphrase}</string>
<int name="MaxNumberOfClients" value="0" />
<boolean name="ClientControlByUser" value="false" />
<boolean name="AutoShutdownEnabled" value="{auto_shut}" />
<long name="ShutdownTimeoutMillis" value="-1" />
<BlockedClientList />
<AllowedClientList />
<boolean name="BridgedModeOpportunisticShutdownEnabled" value="true" />
<int name="MacRandomizationSetting" value="2" />
<BandChannelMap>
<BandChannel>
<int name="Band" value="{band}" />
<int name="Channel" value="{channel}" />
</BandChannel>
</BandChannelMap>
<boolean name="80211axEnabled" value="{ax}" />
<boolean name="UserConfiguration" value="true" />
<long name="BridgedModeOpportunisticShutdownTimeoutMillis" value="-1" />
<VendorElements />
<boolean name="80211beEnabled" value="true" />
<string name="PersistentRandomizedMacAddress">12:4a:35:4b:f4:59</string>
</SoftAp>
</WifiConfigStoreData>"""

    b64 = base64.b64encode(xml_content.encode("utf-8")).decode("ascii")
    _run_host_shell(f"echo '{b64}' | base64 -d > {SOFTAP_XML} && chmod 600 {SOFTAP_XML}")

    # Schedule update
    if "schedule" in data:
        try:
            with open(SCHEDULE_JSON, "w") as f:
                json.dump(data["schedule"], f, indent=2)
        except Exception:
            pass

    return {"success": True, "message": "Hotspot configuration updated successfully"}


def _execute_action(action: str, params: dict = None) -> dict:
    """Execute control toggles and actions on the K40S host."""
    params = params or {}
    act = action.strip().lower()

    if act == "toggle_eth_tether":
        enable = params.get("enable", True)
        if enable:
            cmd = f"service call ethernet 13 i32 1 ; service call tethering 1 s16 {C.ETH_IF} s16 com.android.shell ; sysctl -w net.ipv4.ip_forward=1"
        else:
            cmd = f"service call tethering 2 s16 {C.ETH_IF} s16 com.android.shell ; service call ethernet 13 i32 0"
        res = _run_host_shell(cmd)
        return {"success": True, "message": f"Ethernet tether set to {enable}", "output": res}

    elif act == "toggle_watchdog":
        enable = params.get("enable", True)
        if enable:
            res = _run_host_shell(f"nohup {C.WATCHDOG_SCRIPT} >/dev/null 2>&1 &")
        else:
            res = _run_host_shell("pkill -f 'watchdog.sh'")
        return {"success": True, "message": f"Watchdog set to {enable}", "output": res}

    elif act == "toggle_anti_cdrx":
        enable = params.get("enable", True)
        if enable:
            res = _run_host_shell(f"nohup {C.ANTI_CDRX_SCRIPT} >/dev/null 2>&1 &")
        else:
            res = _run_host_shell("pkill -f 'ping -i 0.2'")
        return {"success": True, "message": f"Anti-C-DRX set to {enable}", "output": res}

    elif act == "toggle_wifi_master":
        enable = params.get("enable", True)
        arg = "enabled" if enable else "disabled"
        res = _run_host_shell(f"cmd wifi set-wifi-enabled {arg}")
        return {"success": True, "message": f"Wi-Fi master set to {arg}", "output": res}

    elif act == "toggle_wifi_power_save":
        enable = params.get("enable", True)
        arg = "on" if enable else "off"
        res = _run_host_shell(f"iw dev {C.WIFI_STA_IF} set power_save {arg}")
        return {"success": True, "message": f"Wi-Fi 6 Power Save set to {arg}", "output": res}

    elif act == "toggle_qos_500b":
        enable = params.get("enable", True)
        if enable:
            cmd = "iptables -t mangle -C POSTROUTING -p udp -m length --length 0:500 -j DSCP --set-dscp-class EF 2>/dev/null || iptables -t mangle -I POSTROUTING -p udp -m length --length 0:500 -j DSCP --set-dscp-class EF"
        else:
            cmd = "iptables -t mangle -D POSTROUTING -p udp -m length --length 0:500 -j DSCP --set-dscp-class EF 2>/dev/null || true"
        res = _run_host_shell(cmd)
        return {"success": True, "message": f"500B EF QoS set to {enable}", "output": res}

    elif act == "toggle_qos_cs2":
        enable = params.get("enable", True)
        if enable:
            cmd = "iptables -t mangle -C PREROUTING -p udp --dport 27000:27065 -j DSCP --set-dscp-class EF 2>/dev/null || iptables -t mangle -I PREROUTING -p udp --dport 27000:27065 -j DSCP --set-dscp-class EF"
        else:
            cmd = "iptables -t mangle -D PREROUTING -p udp --dport 27000:27065 -j DSCP --set-dscp-class EF 2>/dev/null || true"
        res = _run_host_shell(cmd)
        return {"success": True, "message": f"CS2 SDR QoS set to {enable}", "output": res}

    elif act == "toggle_hotspot":
        enable = params.get("enable", True)
        if enable:
            res = _run_host_shell("service call wifi 65 i32 0 s16 com.android.shell")
        else:
            res = _run_host_shell("service call wifi 67")
        return {"success": True, "message": f"Hotspot set to {enable}", "output": res}

    elif act == "wifi_connect":
        ssid = params.get("ssid", "")
        pwd = params.get("password", "")
        sec = params.get("security", "wpa2").lower()
        if not pwd or sec == "open":
            cmd = f"cmd wifi connect-network '{ssid}' open"
        else:
            cmd = f"cmd wifi connect-network '{ssid}' {sec} '{pwd}'"
        res = _run_host_shell(cmd)
        return {"success": True, "message": f"Connecting to {ssid}...", "output": res}

    elif act == "wifi_forget":
        net_id = params.get("network_id", "")
        res = _run_host_shell(f"cmd wifi forget-network {net_id}")
        return {"success": True, "message": "Network forgotten", "output": res}

    elif act == "toggle_client_block":
        mac = params.get("mac", "").lower()
        block = params.get("block", True)
        blocked_macs = set()
        try:
            if os.path.exists(BLOCKED_MACS_FILE):
                with open(BLOCKED_MACS_FILE, "r") as f:
                    blocked_macs = set(json.load(f))
        except Exception:
            pass

        if block:
            blocked_macs.add(mac)
            _run_host_shell(f"iptables -I FORWARD -m mac --mac-source {mac} -j DROP")
        else:
            blocked_macs.discard(mac)
            _run_host_shell(f"iptables -D FORWARD -m mac --mac-source {mac} -j DROP 2>/dev/null || true")

        try:
            with open(BLOCKED_MACS_FILE, "w") as f:
                json.dump(list(blocked_macs), f)
        except Exception:
            pass
        return {"success": True, "message": f"Client {mac} block state set to {block}"}

    elif act == "kick_client":
        ip = params.get("ip", "")
        mac = params.get("mac", "")
        _run_host_shell(f"iptables -I FORWARD -s {ip} -j DROP ; sleep 1 ; iptables -D FORWARD -s {ip} -j DROP 2>/dev/null || true")
        return {"success": True, "message": f"Client {ip} connection dropped"}

    elif act == "set_cake_mode":
        mode = params.get("mode", "full")
        tc_cake = C.TC_CAKE_BIN
        val = 0
        if mode == "300m": val = 300
        elif mode == "500m": val = 500
        elif mode == "custom": val = int(params.get("bandwidth", 0))

        bw_arg = "unlimited" if val <= 0 else f"bandwidth {val}mbit"
        cmd = f"""
for dev in $(ls /sys/class/net | grep -E '^(rmnet_data|wlan|eth)[0-9]*$'); do
    {tc_cake} qdisc replace dev "$dev" root cake {bw_arg} diffserv3 triple-isolate no-ack-filter split-gso nat 2>/dev/null || true
done
"""
        _run_host_shell(cmd)
        return {"success": True, "message": f"CAKE qdisc set to mode {mode}"}

    elif act == "set_tcp_congestion":
        algo = params.get("algo", "bbr3")
        _run_host_shell(f"sysctl -w net.ipv4.tcp_congestion_control={algo}")
        return {"success": True, "message": f"TCP congestion control set to {algo}"}

    elif act == "toggle_rps_rfs":
        enable = params.get("enable", True)
        if enable:
            cmd = """
sysctl -w net.core.rps_sock_flow_entries=32768
for dev in __CELL__ __STA__ __ETH__; do
    if [ -d "/sys/class/net/$dev/queues/rx-0" ]; then
        echo 70 > /sys/class/net/$dev/queues/rx-0/rps_cpus 2>/dev/null || true
        echo 4096 > /sys/class/net/$dev/queues/rx-0/rps_flow_cnt 2>/dev/null || true
    fi
done
""".replace("__CELL__", C.CELLULAR_IF).replace("__STA__", C.WIFI_STA_IF).replace("__ETH__", C.ETH_IF)
        else:
            cmd = """
for dev in __CELL__ __STA__ __ETH__; do
    if [ -d "/sys/class/net/$dev/queues/rx-0" ]; then
        echo 00 > /sys/class/net/$dev/queues/rx-0/rps_cpus 2>/dev/null || true
        echo 0 > /sys/class/net/$dev/queues/rx-0/rps_flow_cnt 2>/dev/null || true
    fi
done
""".replace("__CELL__", C.CELLULAR_IF).replace("__STA__", C.WIFI_STA_IF).replace("__ETH__", C.ETH_IF)
        _run_host_shell(cmd)
        return {"success": True, "message": f"RPS/RFS set to {enable}"}

    elif act == "wake_pc":
        mac = params.get("mac", "cc:28:aa:4f:bd:26")
        clean_mac = mac.replace(":", "").replace("-", "").strip()
        hw_bytes = bytes.fromhex(clean_mac)
        magic_packet = b"\xff" * 6 + hw_bytes * 16

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for bcast in ["255.255.255.255", "192.168.1.255", "192.168.203.255"]:
            try:
                sock.sendto(magic_packet, (bcast, 9))
            except Exception:
                pass
        sock.close()
        _run_host_shell(f"/data/adb/magisk/busybox ether-wake {mac} 2>/dev/null || true")
        return {"success": True, "message": f"Wake-on-LAN Magic Packet sent to {mac}"}

    elif act == "send_notification":
        title = params.get("title", "⚡ CyberGate WebUI")
        content = params.get("content", "Web 控制台测试通知发送成功！")
        _run_host_shell(f"cmd notification post -S bigtext -t '{title}' cybergate_ui '{content}'")
        return {"success": True, "message": "Notification dispatched to status bar."}

    elif act == "remount_swap":
        cmd = """
if ! grep -q "/dev/block/zram0" /proc/swaps; then
    swapoff /dev/block/zram0 2>/dev/null || true
    echo 1 > /sys/block/zram0/reset 2>/dev/null || true
    echo zstd > /sys/block/zram0/comp_algorithm 2>/dev/null || echo lz4 > /sys/block/zram0/comp_algorithm
    echo 8589934592 > /sys/block/zram0/disksize
    /system/bin/mkswap /dev/block/zram0
    /system/bin/swapon -p 32767 /dev/block/zram0
fi
if [ -f /data/swapfile ] && ! grep -q "/data/swapfile" /proc/swaps; then
    chmod 600 /data/swapfile
    /system/bin/swapon -p -2 /data/swapfile 2>/dev/null || /system/bin/swapon /data/swapfile 2>/dev/null || true
fi
sysctl -w vm.swappiness=100
sysctl -w vm.vfs_cache_pressure=50
"""
        _run_host_shell(cmd)
        return {"success": True, "message": "8G ZRAM (ZSTD) 与 16G UFS 物理 Swap 双层交换区已挂载就绪！"}


    elif act == "set_speed_limit":
        dev = params.get("interface", "all")
        rate = int(params.get("rate_mbps", 0))
        tc_cake = C.TC_CAKE_BIN
        bw_arg = "unlimited" if rate <= 0 else f"bandwidth {rate}mbit"
        if dev == "all":
            cmd = f'''
for d in $(ls /sys/class/net | grep -E '^(rmnet_data|wlan|eth)[0-9]*$'); do
    {tc_cake} qdisc replace dev "$d" root cake {bw_arg} diffserv3 triple-isolate no-ack-filter split-gso nat 2>/dev/null || true
done
'''
        else:
            cmd = f'{tc_cake} qdisc replace dev "{dev}" root cake {bw_arg} diffserv3 triple-isolate no-ack-filter split-gso nat 2>/dev/null || true'
        res = _run_host_shell(cmd)
        msg = f"接口 {dev} 带宽限制已设定为: {'无限制 (全速直通)' if rate <= 0 else str(rate) + ' Mbps'}"
        return {"success": True, "message": msg, "output": res}

    elif act == "limit_client_speed":
        ip = params.get("ip", "").strip()
        rate = int(params.get("rate_kbps", 0))
        if not ip:
            return {"success": False, "message": "目标设备 IP 不能为空"}
        chain_name = f"cl_{ip.replace('.', '_')}"
        _run_host_shell(f"iptables -D FORWARD -s {ip} -m hashlimit --hashlimit-above {rate}kb/s --hashlimit-burst 100kb --hashlimit-mode srcip --hashlimit-name {chain_name} -j DROP 2>/dev/null || true")
        if rate > 0:
            _run_host_shell(f"iptables -I FORWARD -s {ip} -m hashlimit --hashlimit-above {rate}kb/s --hashlimit-burst 100kb --hashlimit-mode srcip --hashlimit-name {chain_name} -j DROP")
            return {"success": True, "message": f"设备 {ip} 上行已限速至 {rate} KB/s ({round(rate*8/1024, 1)} Mbps)"}
        else:
            return {"success": True, "message": f"设备 {ip} 限速已解除"}

    elif act == "refresh_cellular":
        _run_host_shell("cmd connectivity airplane-mode enable; sleep 1; cmd connectivity airplane-mode disable")
        return {"success": True, "message": "5G 蜂窝基带重搜网完成"}

    elif act == "set_network_mode":
        mode = params.get("mode", "auto")
        if mode == "sa_only":
            cmd = "service call phone 83 i32 1 i32 33 ; settings put global preferred_network_mode 33"
        elif mode == "lte_only":
            cmd = "service call phone 83 i32 1 i32 11 ; settings put global preferred_network_mode 11"
        else:
            cmd = "service call phone 83 i32 1 i32 22 ; settings put global preferred_network_mode 22"
        _run_host_shell(cmd)
        return {"success": True, "message": f"网络偏好模式已切换为: {mode}"}

    elif act == "exec_cmd":
        cmd = params.get("command", "uptime")
        res = _run_host_shell(cmd, timeout=20)
        return {"success": True, "output": res}

    elif act == "reboot":
        _run_host_shell("reboot")
        return {"success": True, "message": "System reboot initiated."}

    return {"success": False, "message": f"Unknown action '{action}'"}


def _get_log_content(log_type: str = "dmesg", lines: int = 80) -> str:
    if log_type == "dmesg":
        return _run_host_shell(f"dmesg | tail -n {lines}")
    elif log_type == "logcat":
        return _run_host_shell(f"logcat -d -t {lines} -v time")
    elif log_type == "webui":
        return _run_host_shell(f"cat /data/local/tmp/cpe_webui.log 2>/dev/null | tail -n {lines}")
    elif log_type == "webdav":
        return _run_host_shell(f"cat /data/local/tmp/webdav.log 2>/dev/null | tail -n {lines}")
    elif log_type == "keeper":
        # 2026-10-16: 新架构——网关底座看护器日志（替代退役的 watchdog）
        return _run_host_shell(f"tail -n {lines} /data/local/tmp/net_keeper.log 2>/dev/null")
    elif log_type == "boxguard":
        # 2026-10-16: 新架构——透明代理守护日志
        return _run_host_shell(f"tail -n {lines} /data/local/tmp/box_guard.log 2>/dev/null")
    elif log_type == "mihomo":
        # 2026-10-16: 新架构——代理核心日志
        return _run_host_shell(f"tail -n {lines} /data/adb/box/run/clash.log 2>/dev/null")
    return "Unknown log type"


def _capture_screen_frame(quality: int = 55, target_width: int = 400):
    global _last_frame_time, _last_frame_bytes, _screen_width, _screen_height
    now = time.time()
    with _screen_lock:
        if _last_frame_bytes and (now - _last_frame_time) < 0.12:
            return _last_frame_bytes, _screen_width, _screen_height

        # 2026-10-16 无 PIL 兜底：screencap -p 直接产出 PNG（自带压缩），
        # 跳过 RGBA 解码/缩放（无 Pillow 依赖，功能等价——前端 img 标签原生吃 PNG）
        _png_file = "/data/local/tmp/screen.png"
        _run_host_shell(f"screencap -p {_png_file}", timeout=5)

        if not os.path.exists(_png_file):
            return _last_frame_bytes or b"", _screen_width, _screen_height

        try:
            with open(_png_file, "rb") as f:
                raw = f.read()

            if len(raw) > 100 and raw[:8] == b"\x89PNG\r\n\x1a\n":
                _last_frame_bytes = raw
                _last_frame_time = now
                return _last_frame_bytes, _screen_width, _screen_height
        except Exception:
            pass

        return _last_frame_bytes or b"", _screen_width, _screen_height


def _control_screen(action: str, params: dict = None) -> dict:
    global _screen_width, _screen_height
    params = params or {}
    act = action.strip().lower()

    if act == "tap":
        x = params.get("x", 0.5)
        y = params.get("y", 0.5)
        rx = int(x * _screen_width) if isinstance(x, float) and 0 <= x <= 1 else int(x)
        ry = int(y * _screen_height) if isinstance(y, float) and 0 <= y <= 1 else int(y)
        res = _run_host_shell(f"input tap {rx} {ry}", timeout=5)
        return {"success": True, "action": "tap", "x": rx, "y": ry, "output": res}

    elif act == "swipe":
        x1 = params.get("x1", 0.5)
        y1 = params.get("y1", 0.5)
        x2 = params.get("x2", 0.5)
        y2 = params.get("y2", 0.5)
        duration = int(params.get("duration", 250))
        rx1 = int(x1 * _screen_width) if isinstance(x1, float) and 0 <= x1 <= 1 else int(x1)
        ry1 = int(y1 * _screen_height) if isinstance(y1, float) and 0 <= y1 <= 1 else int(y1)
        rx2 = int(x2 * _screen_width) if isinstance(x2, float) and 0 <= x2 <= 1 else int(x2)
        ry2 = int(y2 * _screen_height) if isinstance(y2, float) and 0 <= y2 <= 1 else int(y2)
        res = _run_host_shell(f"input swipe {rx1} {ry1} {rx2} {ry2} {duration}", timeout=5)
        return {"success": True, "action": "swipe", "from": [rx1, ry1], "to": [rx2, ry2], "output": res}

    elif act == "key":
        code = int(params.get("code", 4))
        res = _run_host_shell(f"input keyevent {code}", timeout=5)
        return {"success": True, "action": "key", "code": code, "output": res}

    elif act == "text":
        txt = str(params.get("text", "")).replace("'", "").replace('"', "")
        escaped = txt.replace(" ", "%s")
        res = _run_host_shell(f"input text '{escaped}'", timeout=5)
        return {"success": True, "action": "text", "text": txt, "output": res}

    elif act == "wake":
        res = _run_host_shell("input keyevent 26 ; sleep 0.2 ; input swipe 400 1800 400 400 200", timeout=5)
        return {"success": True, "action": "wake", "output": res}

    return {"success": False, "error": f"Unknown screen action '{action}'"}


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class CyberGateHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 2026-10-16: Windows NCSI 探测应答（k40s.com 经 hosts 指向网关后由本机应答，
        # 让 Win 地球图标正确显示"有 Internet"——Akamai 边缘 404 问题的根治）
        host = (self.headers.get("Host") or "").split(":")[0]
        if path == "/connecttest.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Microsoft Connect Test")
            return
        if path == "/ncsi.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Microsoft NCSI")
            return

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if os.path.exists(HTML_FILE):
                with open(HTML_FILE, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>CyberGate UI Frontend loading...</h1>")

        elif path == "/docs" or path == "/docs.html" or path == "/manual":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if os.path.exists(DOCS_FILE):
                with open(DOCS_FILE, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>CyberGate Documentation Loading...</h1>")

        elif path == "/api/status":
            data = _get_system_status()
            self._send_json(data)

        elif path == "/api/traffic":
            data = _get_traffic_stats()
            self._send_json(data)

        elif path == "/api/traffic/history":
            data = _get_traffic_history()
            self._send_json(data)

        elif path == "/api/clients":
            data = _get_clients_list()
            self._send_json(data)

        elif path == "/api/cellular/deep":
            data = _get_cellular_deep_info()
            self._send_json(data)

        elif path == "/api/cellular/cells" or path == "/api/cellular/scan":
            q_str = urllib.parse.parse_qs(parsed.query)
            mode = q_str.get("mode", ["all"])[0]
            trigger = q_str.get("trigger", ["0"])[0]
            if trigger == "1":
                _run_host_shell("cmd connectivity airplane-mode enable; sleep 1; cmd connectivity airplane-mode disable")
                time.sleep(2)
            data = _scan_nearby_cells(mode)
            self._send_json(data)

        elif path == "/api/wifi/status":
            enabled = _run_host_shell("settings get global wifi_on").strip() == "1"
            self._send_json({"enabled": enabled})

        elif path == "/api/wifi/list":
            data = _get_wifi_list()
            self._send_json(data)

        elif path == "/api/hotspot/info":
            data = _get_hotspot_details()
            self._send_json(data)

        elif path == "/api/system/processes":
            data = _get_system_processes()
            self._send_json(data)

        elif path == "/api/logs":
            q_str = urllib.parse.parse_qs(parsed.query)
            log_type = q_str.get("type", ["dmesg"])[0]
            lines = int(q_str.get("lines", [80])[0])
            content = _get_log_content(log_type, lines)
            self._send_json({"type": log_type, "content": content})

        elif path == "/api/screen/frame":
            q_str = urllib.parse.parse_qs(parsed.query)
            quality = int(q_str.get("quality", [55])[0])
            width = int(q_str.get("width", [400])[0])
            frame_bytes, sw, sh = _capture_screen_frame(quality=quality, target_width=width)
            if frame_bytes:
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("X-Screen-Width", str(sw))
                self.send_header("X-Screen-Height", str(sh))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(frame_bytes)
            else:
                self.send_response(503)
                self.end_headers()

        elif path == "/api/screen/stream.mjpg":
            q_str = urllib.parse.parse_qs(parsed.query)
            quality = int(q_str.get("quality", [50])[0])
            width = int(q_str.get("width", [360])[0])
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                while True:
                    frame_bytes, _, _ = _capture_screen_frame(quality=quality, target_width=width)
                    if frame_bytes:
                        self.wfile.write(b"--frame\r\nContent-Type: image/png\r\nContent-Length: " + str(len(frame_bytes)).encode() + b"\r\n\r\n" + frame_bytes + b"\r\n")
                    time.sleep(0.05)
            except Exception:
                pass

        elif path.startswith("/proxypanel"):
            # 2026-10-15: 反向代理 mihomo 控制面板（9090），实现单页全管理
            sub = path[len("/proxypanel"):] or "/"
            if sub == "/" or sub == "":
                sub = "/ui/"
            self._proxy_to_mihomo(sub)

        else:
            self.send_response(404)
            self.end_headers()

    def _proxy_to_mihomo(self, subpath: str):
        """Proxy GET requests to the mihomo external-controller (127.0.0.1:CONTROLLER_PORT)."""
        import http.client
        try:
            conn = http.client.HTTPConnection("127.0.0.1", C.CONTROLLER_PORT, timeout=10)
            headers = {}
            for key in ("Accept", "Authorization", "Content-Type"):
                v = self.headers.get(key)
                if v:
                    headers[key] = v
            conn.request("GET", subpath, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            self.send_response(resp.status)
            ct = resp.getheader("Content-Type", "application/octet-stream")
            self.send_header("Content-Type", ct)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
            conn.close()
        except Exception as e:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"proxy error: {e}".encode("utf-8"))

    def do_POST(self):
        self._handle_write("POST")

    def do_PUT(self):
        self._handle_write("PUT")

    def do_PATCH(self):
        self._handle_write("PATCH")

    def do_DELETE(self):
        self._handle_write("DELETE")

    def _handle_write(self, method: str):
        """2026-10-16: 统一写方法入口——API 走 POST，proxypanel 透传全部写方法（切节点用 PUT/PATCH）。"""
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body_str = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
        try:
            body = json.loads(body_str) if body_str else {}
        except Exception:
            body = {}

        if parsed.path.startswith("/proxypanel"):
            sub = parsed.path[len("/proxypanel"):] or "/"
            import http.client as _phc
            try:
                _pconn = _phc.HTTPConnection("127.0.0.1", C.CONTROLLER_PORT, timeout=15)
                _phdrs = {k: v for k, v in self.headers.items()
                          if k.lower() not in ("host", "content-length", "connection", "accept-encoding")}
                _pconn.request(method, sub, body=body_str.encode("utf-8") if body_str else None, headers=_phdrs)
                _presp = _pconn.getresponse()
                _pdata = _presp.read()
                self.send_response(_presp.status)
                self.send_header("Content-Type", _presp.getheader("Content-Type", "application/json"))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(_pdata)
                _pconn.close()
            except Exception as e:
                self.send_response(502)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"proxy error: {e}".encode("utf-8"))
            return

        if method != "POST":
            self.send_response(405)
            self.end_headers()
            return

        if parsed.path == "/api/action":
            action = body.get("action", "")
            params = body.get("params", {})
            res = _execute_action(action, params)
            self._send_json(res)

        elif parsed.path == "/api/system/process/kill":
            pid = body.get("pid")
            pkg = body.get("package")
            res = _kill_process(pid, pkg)
            self._send_json(res)

        elif parsed.path == "/api/hotspot/save":
            res = _save_hotspot_details(body)
            self._send_json(res)

        elif parsed.path == "/api/terminal/exec":
            cmd = body.get("command", "uptime")
            res = _run_host_shell(cmd, timeout=25)
            self._send_json({"command": cmd, "output": res, "success": True})

        elif parsed.path == "/api/screen/control":
            action = body.get("action", "")
            params = body.get("params", {})
            res = _control_screen(action, params)
            self._send_json(res)

        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def _dns_server_worker():
    """Built-in DNS resolver: answers local-domain queries (e.g. k40s.com -> gateway IP)
    and forwards everything else upstream. Requires a port-53 redirect rule pointing
    at this port (see scripts/ and docs/ADAPTING.md)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", C.DNS_PORT))
        print(f"🌐 Built-in DNS resolver daemon listening on UDP {C.DNS_PORT}.")
    except Exception as e:
        print(f"[-] DNS server bind failed on {C.DNS_PORT}: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            if len(data) < 12:
                continue

            # Parse domain
            idx = 12
            labels = []
            while idx < len(data) and data[idx] != 0:
                l_len = data[idx]
                idx += 1
                labels.append(data[idx:idx+l_len].decode("ascii", errors="ignore"))
                idx += l_len
            idx += 1  # null terminator
            if idx + 4 > len(data):
                continue
            qtype = int.from_bytes(data[idx:idx+2], "big")
            qname = ".".join(labels).lower()

            if C.LOCAL_DOMAIN_KEYWORD in qname or qname.endswith(".lan") or qname.endswith(".cpe"):
                res = bytearray(data[:2])
                if qtype == 28:  # AAAA (IPv6)
                    # Return empty response with NOERROR so clients fall back to IPv4 immediately
                    res.extend(b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00")
                    res.extend(data[12:idx+4])
                else:  # A record (IPv4)
                    res.extend(b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00")
                    res.extend(data[12:idx+4])
                    # Answer: Pointer 0xc00c, Type A (1), Class IN (1), TTL 30s, Length 4, <local_gateway_ip>
                    res.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04")
                    res.extend(C.local_gateway_bytes())
                sock.sendto(res, addr)
            else:
                # Forward query to public upstream DNS asynchronously
                def _forward_dns(req_data, client_addr):
                    try:
                        fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        fwd.settimeout(2.0)
                        fwd.sendto(req_data, (C.UPSTREAM_DNS, 53))
                        resp, _ = fwd.recvfrom(2048)
                        sock.sendto(resp, client_addr)
                        fwd.close()
                    except Exception:
                        pass
                threading.Thread(target=_forward_dns, args=(data, addr), daemon=True).start()
        except Exception:
            time.sleep(0.05)


if __name__ == "__main__":
    print(f"🚀 CyberGate WebUI v2.0 starting on http://0.0.0.0:{PORT}")
    _init_traffic_db()
    collector_thread = threading.Thread(target=_traffic_collector_worker, daemon=True)
    collector_thread.start()
    print("📊 Background SQLite Traffic Accounting daemon started.")

    dns_thread = threading.Thread(target=_dns_server_worker, daemon=True)
    dns_thread.start()

    server = ThreadedHTTPServer(("0.0.0.0", PORT), CyberGateHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _flush_traffic_db(force=True)
        server.shutdown()
