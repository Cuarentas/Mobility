import customtkinter as ctk
import subprocess
import sys
import json
import base64
import urllib.parse
import time
import socket
import winreg
import ctypes
import shutil
import requests
from pathlib import Path
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except Exception:
    TRAY_AVAILABLE = False

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# 并行测速默认值
TEST_WORKERS_DEFAULT = 32
TEST_TIMEOUT = 5.0
TEST_WORKERS_OPTIONS = ["8", "16", "32", "64", "128", "256"]
PROXY_MODES = ["规则模式", "全局模式", "直连模式"]
PROXY_MODE_DEFAULT = "规则模式"
REFRESH_OPTIONS = ["不自动更新", "1小时", "6小时", "12小时", "24小时"]
REFRESH_HOURS = {"不自动更新": 0, "1小时": 1, "6小时": 6, "12小时": 12, "24小时": 24}
THEME_OPTIONS = ["跟随系统", "浅色", "深色"]
THEME_MAP = {"跟随系统": "System", "浅色": "Light", "深色": "Dark"}
DNS_OPTIONS = ["系统默认", "国内 DNS", "国外 DNS", "自定义"]
DNS_PRESETS = {
    "系统默认": None,
    "国内 DNS": ["223.5.5.5", "119.29.29.29"],
    "国外 DNS": ["8.8.8.8", "1.1.1.1"],
}
LOG_LEVELS = ["警告", "信息", "调试"]
LOG_LEVEL_MAP = {"警告": "warning", "信息": "info", "调试": "debug"}
LOG_LEVEL_REV = {"warning": "警告", "info": "信息", "debug": "调试"}


def get_base_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def get_resource_path(relative: str) -> Path:
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            return Path(sys._MEIPASS) / relative
        return Path(sys.executable).parent / relative
    return Path(__file__).parent / relative



def get_icons_dir() -> Path:
    candidates = [
        get_base_dir() / "icons",
        Path(sys.executable).parent / "icons",
        Path(sys.executable).parent / "_internal" / "icons",
    ]
    try:
        candidates.append(get_resource_path("icons"))
    except Exception:
        pass
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        candidates.append(Path(sys._MEIPASS) / "icons")
    for d in candidates:
        try:
            if d and Path(d).exists():
                return Path(d)
        except Exception:
            pass
    return get_base_dir() / "icons"


def b64_decode(s: str) -> str:
    s = s.strip().replace('-', '+').replace('_', '/')
    pad = 4 - len(s) % 4
    if pad != 4:
        s += '=' * pad
    return base64.b64decode(s).decode('utf-8', errors='ignore')


def parse_vmess(link: str) -> dict | None:
    try:
        raw = link[8:]
        data = json.loads(b64_decode(raw))
        return {
            "protocol": "vmess",
            "name": data.get("ps") or data.get("remark") or "vmess",
            "address": data.get("add") or data.get("address"),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "security": data.get("scy") or data.get("security") or "auto",
            "network": data.get("net") or "tcp",
            "type": data.get("type") or "none",
            "host": data.get("host") or "",
            "path": data.get("path") or "",
            "tls": data.get("tls") or "",
            "sni": data.get("sni") or data.get("host") or "",
            "raw": link,
            "latency": None,
        }
    except Exception:
        return None


def parse_vless(link: str) -> dict | None:
    try:
        parsed = urllib.parse.urlparse(link)
        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port or 443
        name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "vless"
        params = urllib.parse.parse_qs(parsed.query)

        def get_param(key, default=""):
            return params.get(key, [default])[0]

        return {
            "protocol": "vless",
            "name": name,
            "address": address,
            "port": int(port),
            "uuid": uuid,
            "encryption": get_param("encryption", "none"),
            "flow": get_param("flow", ""),
            "network": get_param("type", "tcp"),
            "security": get_param("security", "none"),
            "sni": get_param("sni") or get_param("host") or "",
            "fp": get_param("fp", ""),
            "pbk": get_param("pbk", ""),
            "sid": get_param("sid", ""),
            "spx": get_param("spx", ""),
            "path": get_param("path", ""),
            "host": get_param("host", ""),
            "serviceName": get_param("serviceName", ""),
            "raw": link,
            "latency": None,
        }
    except Exception:
        return None


def parse_trojan(link: str) -> dict | None:
    try:
        parsed = urllib.parse.urlparse(link)
        password = urllib.parse.unquote(parsed.username or "")
        address = parsed.hostname
        port = parsed.port or 443
        name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "trojan"
        params = urllib.parse.parse_qs(parsed.query)

        def get_param(key, default=""):
            return params.get(key, [default])[0]

        return {
            "protocol": "trojan",
            "name": name,
            "address": address,
            "port": int(port),
            "password": password,
            "network": get_param("type", "tcp"),
            "security": get_param("security", "tls"),
            "sni": get_param("sni") or get_param("peer") or "",
            "path": get_param("path", ""),
            "host": get_param("host", ""),
            "fp": get_param("fp", ""),
            "raw": link,
            "latency": None,
        }
    except Exception:
        return None


def parse_ss(link: str) -> dict | None:
    """解析 ss:// 链接（支持标准与 SIP002）"""
    try:
        raw = link[5:]  # 去掉 ss://
        name = "ss"
        if "#" in raw:
            raw, frag = raw.split("#", 1)
            name = urllib.parse.unquote(frag) or "ss"

        method = password = address = None
        port = 443

        # SIP002: ss://base64(method:password)@host:port
        if "@" in raw and not raw.startswith("@"):
            userinfo, hostinfo = raw.rsplit("@", 1)
            # userinfo 可能是 base64
            try:
                decoded = b64_decode(urllib.parse.unquote(userinfo))
                if ":" in decoded:
                    userinfo = decoded
            except Exception:
                userinfo = urllib.parse.unquote(userinfo)
            if ":" not in userinfo:
                return None
            method, password = userinfo.split(":", 1)
            hostinfo = hostinfo.split("?")[0]
            if ":" in hostinfo:
                address, port_s = hostinfo.rsplit(":", 1)
                port = int(port_s)
            else:
                address = hostinfo
        else:
            # 旧格式: ss://base64(method:password@host:port)
            decoded = b64_decode(urllib.parse.unquote(raw.split("?")[0]))
            if "@" not in decoded or ":" not in decoded:
                return None
            userinfo, hostinfo = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            if ":" in hostinfo:
                address, port_s = hostinfo.rsplit(":", 1)
                port = int(port_s)
            else:
                address = hostinfo

        if not all([method, password, address]):
            return None
        return {
            "protocol": "shadowsocks",
            "name": name,
            "address": address,
            "port": int(port),
            "method": method,
            "password": password,
            "raw": link,
            "latency": None,
        }
    except Exception:
        return None


def parse_link(link: str) -> dict | None:
    link = link.strip()
    if not link:
        return None
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    if link.startswith("ss://"):
        return parse_ss(link)
    return None


def parse_subscription_content(content: str) -> list[dict]:
    content = content.strip()
    nodes = []
    try:
        decoded = b64_decode(content)
        if "://" in decoded:
            content = decoded
    except Exception:
        pass

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if not line.startswith(("vmess://", "vless://", "trojan://", "ss://")):
            try:
                inner = b64_decode(line).strip()
                if inner.startswith(("vmess://", "vless://", "trojan://", "ss://")):
                    line = inner
            except Exception:
                continue
        node = parse_link(line)
        if node and node.get("address"):
            nodes.append(node)
    return nodes


def tcp_ping(host: str, port: int, timeout: float = TEST_TIMEOUT) -> int | None:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not infos:
            return None
        family, socktype, proto, _, sockaddr = infos[0]
        s = socket.socket(family, socktype, proto)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.connect(sockaddr)
        ms = int((time.perf_counter() - t0) * 1000)
        s.close()
        return ms
    except Exception:
        return None


def build_outbound(node: dict) -> dict:
    protocol = node["protocol"]

    if protocol == "vmess":
        user = {
            "id": node["uuid"],
            "alterId": node.get("alterId", 0),
            "security": node.get("security", "auto"),
        }
        stream = {"network": node.get("network", "tcp")}
        if node.get("tls") in ("tls", "xtls"):
            stream["security"] = "tls"
            stream["tlsSettings"] = {
                "serverName": node.get("sni") or node.get("host") or node["address"],
            }
        if node.get("network") == "ws":
            stream["wsSettings"] = {
                "path": node.get("path") or "/",
                "headers": {"Host": node.get("host") or node["address"]},
            }
        if node.get("network") == "grpc":
            stream["grpcSettings"] = {"serviceName": node.get("path") or ""}

        return {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": node["address"],
                    "port": node["port"],
                    "users": [user],
                }]
            },
            "streamSettings": stream,
        }

    if protocol == "vless":
        user = {
            "id": node["uuid"],
            "encryption": node.get("encryption", "none"),
        }
        if node.get("flow"):
            user["flow"] = node["flow"]

        stream = {"network": node.get("network", "tcp")}
        security = node.get("security", "none")
        if security == "tls":
            stream["security"] = "tls"
            tls = {"serverName": node.get("sni") or node["address"]}
            if node.get("fp"):
                tls["fingerprint"] = node["fp"]
            stream["tlsSettings"] = tls
        elif security == "reality":
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": node.get("sni") or node["address"],
                "fingerprint": node.get("fp") or "chrome",
                "publicKey": node.get("pbk") or "",
                "shortId": node.get("sid") or "",
                "spiderX": node.get("spx") or "",
            }

        if node.get("network") == "ws":
            stream["wsSettings"] = {
                "path": node.get("path") or "/",
                "headers": {"Host": node.get("host") or node.get("sni") or node["address"]},
            }
        if node.get("network") == "grpc":
            stream["grpcSettings"] = {
                "serviceName": node.get("serviceName") or node.get("path") or "",
            }

        return {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": node["address"],
                    "port": node["port"],
                    "users": [user],
                }]
            },
            "streamSettings": stream,
        }

    if protocol == "trojan":
        stream = {
            "network": node.get("network", "tcp"),
            "security": node.get("security") or "tls",
            "tlsSettings": {
                "serverName": node.get("sni") or node["address"],
            },
        }
        if node.get("fp"):
            stream["tlsSettings"]["fingerprint"] = node["fp"]
        if node.get("network") == "ws":
            stream["wsSettings"] = {
                "path": node.get("path") or "/",
                "headers": {"Host": node.get("host") or node.get("sni") or node["address"]},
            }

        return {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": node["address"],
                    "port": node["port"],
                    "password": node["password"],
                }]
            },
            "streamSettings": stream,
        }

    if protocol == "shadowsocks":
        return {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": node["address"],
                    "port": node["port"],
                    "method": node.get("method") or "aes-256-gcm",
                    "password": node["password"],
                }]
            },
        }

    return None


def node_label(node: dict) -> str:
    lat = node.get("latency")
    if lat is None:
        lat_s = "未测"
    elif lat < 0:
        lat_s = "超时"
    else:
        lat_s = f"{lat}ms"
    name = str(node.get("name") or "node")
    if len(name) > 24:
        name = name[:24] + "…"
    proto = node.get("protocol") or "?"
    return f"[{proto}] {name} ({lat_s})"


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Mobility")
        self.geometry("780x640")
        self.resizable(True, True)
        self.minsize(720, 560)

        self.base_dir = get_base_dir()
        self.core_dir = self.base_dir / "core"
        self.core_dir.mkdir(exist_ok=True)
        self.log_file = self.core_dir / "xray.log"
        self.settings_path = self.base_dir / "Subscribe.json"

        self.xray_process = None
        self.is_running = False
        self.is_testing = False
        self.nodes: list[dict] = []
        self.current_node = None
        self.subscription_url = ""
        self.proxy_mode = PROXY_MODE_DEFAULT
        self.close_to_tray = True
        self.auto_start = False
        self.auto_connect = False
        self.socks_port = 10808
        self.http_port = 10809
        self.refresh_label = "不自动更新"
        self._refresh_after_id = None
        self.start_minimized = False
        self.theme_label = "跟随系统"
        self.allow_lan = False
        self.filter_text = ""
        self.direct_domains = ""
        self.proxy_domains = ""
        self.dns_mode = "系统默认"
        self.dns_custom = "8.8.8.8,1.1.1.1"
        self.log_level = "警告"
        self.tray_icon = None
        self._lock = Lock()
        self._run_started_at = None
        self._bytes_up = 0
        self._bytes_down = 0
        self._custom_refresh_hours = 0
        self.icons_dir = get_icons_dir()

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.after(200, self.startup)

    def create_widgets(self):
        self.geometry("420x720")
        self.minsize(400, 600)
        self.resizable(True, True)

        # 窗口图标
        try:
            ico = self.icons_dir / "mobility.ico"
            if ico.exists():
                self.iconbitmap(default=str(ico))
                self.iconbitmap(str(ico))
        except Exception:
            pass
        try:
            from PIL import ImageTk
            png = self.icons_dir / "logo-main.png"
            if png.exists():
                self._wm_icon = ImageTk.PhotoImage(Image.open(png).resize((32, 32)))
                self.iconphoto(True, self._wm_icon)
        except Exception:
            pass
        self.log(f"图标目录：{self.icons_dir}")

        # ===== 顶栏 =====
        top = ctk.CTkFrame(self, fg_color="transparent", height=48)
        top.pack(fill="x", padx=16, pady=(12, 4))
        ctk.CTkLabel(
            top, text="Mobility",
            font=("Microsoft YaHei UI", 20, "bold"),
            text_color=("#5B7CFF", "#8AB4FF")
        ).pack(side="left")

        # ===== 主内容区（四页）=====
        self.page_host = ctk.CTkFrame(self, fg_color="transparent")
        self.page_host.pack(fill="both", expand=True, padx=12, pady=4)

        self.pages = {}
        for name in ("home", "nodes", "route", "settings"):
            f = ctk.CTkFrame(self.page_host, fg_color="transparent")
            self.pages[name] = f

        self._build_page_home(self.pages["home"])
        self._build_page_nodes(self.pages["nodes"])
        self._build_page_route(self.pages["route"])
        self._build_page_settings(self.pages["settings"])

        # ===== 底栏导航 =====
        nav = ctk.CTkFrame(self, corner_radius=16, height=64)
        nav.pack(fill="x", padx=16, pady=(4, 12))
        nav.pack_propagate(False)

        self.nav_btns = {}
        nav_items = [
            ("home", "首页"),
            ("nodes", "节点"),
            ("route", "分流"),
            ("settings", "设置"),
        ]
        for key, label in nav_items:
            b = ctk.CTkButton(
                nav, text=label, width=80, height=40,
                font=("Microsoft YaHei UI", 13),
                fg_color="transparent",
                text_color=("gray20", "gray90"),
                hover_color=("gray85", "gray25"),
                command=lambda k=key: self.show_page(k)
            )
            b.pack(side="left", expand=True, padx=4, pady=8)
            self.nav_btns[key] = b

        self.show_page("home")
        self.log("界面已切换为设计版布局")
        self.log("底栏：首页 / 节点 / 分流 / 设置")

    def show_page(self, key: str):
        for k, f in self.pages.items():
            f.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        for k, b in self.nav_btns.items():
            if k == key:
                b.configure(fg_color=("#3B82F6", "#2563EB"), text_color="white")
            else:
                b.configure(fg_color="transparent", text_color=("gray20", "gray90"))

    def _card(self, parent, **kwargs):
        return ctk.CTkFrame(parent, corner_radius=14, **kwargs)

    def _build_page_home(self, root):
        scroll = ctk.CTkScrollableFrame(root, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # 连接开关卡片
        card = self._card(scroll)
        card.pack(fill="x", pady=6)
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=12)
        left = ctk.CTkFrame(row, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        self.home_status = ctk.CTkLabel(left, text="未连接", font=("Microsoft YaHei UI", 16, "bold"))
        self.home_status.pack(anchor="w")
        self.home_status_hint = ctk.CTkLabel(
            left, text="点击右侧开关启动引擎",
            font=("Microsoft YaHei UI", 11), text_color=("gray40", "gray60")
        )
        self.home_status_hint.pack(anchor="w")
        self.connect_switch = ctk.CTkSwitch(
            row, text="", width=48,
            command=self.on_connect_switch
        )
        self.connect_switch.pack(side="right", padx=8)

        # 速率
        speed = self._card(scroll)
        speed.pack(fill="x", pady=6)
        sr = ctk.CTkFrame(speed, fg_color="transparent")
        sr.pack(fill="x", padx=10, pady=10)
        up_box = self._card(sr)
        up_box.pack(side="left", fill="both", expand=True, padx=4)
        ctk.CTkLabel(up_box, text="上传 (Upload)", font=("Microsoft YaHei UI", 11), text_color=("gray40", "gray60")).pack(anchor="w", padx=10, pady=(8, 0))
        self.lbl_up = ctk.CTkLabel(up_box, text="0.0 KB/s", font=("Microsoft YaHei UI", 16, "bold"), text_color="#F59E0B")
        self.lbl_up.pack(anchor="w", padx=10, pady=(0, 8))
        down_box = self._card(sr)
        down_box.pack(side="left", fill="both", expand=True, padx=4)
        ctk.CTkLabel(down_box, text="下载 (Download)", font=("Microsoft YaHei UI", 11), text_color=("gray40", "gray60")).pack(anchor="w", padx=10, pady=(8, 0))
        self.lbl_down = ctk.CTkLabel(down_box, text="0.0 KB/s", font=("Microsoft YaHei UI", 16, "bold"), text_color="#3B82F6")
        self.lbl_down.pack(anchor="w", padx=10, pady=(0, 8))

        # 信息网格
        grid = self._card(scroll)
        grid.pack(fill="x", pady=6)
        g = ctk.CTkFrame(grid, fg_color="transparent")
        g.pack(fill="x", padx=8, pady=8)
        def cell(parent, title, attr, value):
            box = self._card(parent)
            box.pack(side="left", fill="both", expand=True, padx=4, pady=4)
            ctk.CTkLabel(box, text=title, font=("Microsoft YaHei UI", 11), text_color=("gray40", "gray60")).pack(anchor="w", padx=10, pady=(8, 0))
            lbl = ctk.CTkLabel(box, text=value, font=("Microsoft YaHei UI", 14, "bold"))
            lbl.pack(anchor="w", padx=10, pady=(0, 8))
            setattr(self, attr, lbl)
        row1 = ctk.CTkFrame(g, fg_color="transparent")
        row1.pack(fill="x")
        cell(row1, "规则模式", "lbl_mode", "规则模式")
        cell(row1, "已用流量", "lbl_traffic", "0 MB")
        row2 = ctk.CTkFrame(g, fg_color="transparent")
        row2.pack(fill="x")
        cell(row2, "运行时长", "lbl_uptime", "00:00:00")
        cell(row2, "内存占用", "lbl_mem", "- MB")

        # 快捷入口
        quick = self._card(scroll)
        quick.pack(fill="x", pady=6)
        qr = ctk.CTkFrame(quick, fg_color="transparent")
        qr.pack(fill="x", padx=8, pady=10)
        for text, cmd in [
            ("测速", lambda: (self.show_page("nodes"), self.test_all_thread())),
            ("日志", lambda: self.show_page("settings")),
            ("连通性", self.connectivity_test_thread),
            ("配置", lambda: self.show_page("settings")),
        ]:
            ctk.CTkButton(
                qr, text=text, width=70, height=56,
                font=("Microsoft YaHei UI", 12),
                corner_radius=12,
                command=cmd
            ).pack(side="left", expand=True, padx=4)

        # 当前节点
        node_card = self._card(scroll)
        node_card.pack(fill="x", pady=6)
        ctk.CTkLabel(node_card, text="当前节点", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w", padx=12, pady=(10, 4))
        self.home_node = ctk.CTkLabel(
            node_card, text="未选择节点",
            font=("Microsoft YaHei UI", 13), text_color=("gray30", "gray70")
        )
        self.home_node.pack(anchor="w", padx=12)
        self.home_latency = ctk.CTkLabel(node_card, text="", font=("Microsoft YaHei UI", 12), text_color="#10B981")
        self.home_latency.pack(anchor="w", padx=12, pady=(0, 4))
        nr = ctk.CTkFrame(node_card, fg_color="transparent")
        nr.pack(fill="x", padx=10, pady=(4, 12))
        ctk.CTkButton(nr, text="切换节点", height=34, command=lambda: self.show_page("nodes")).pack(side="left", fill="x", expand=True, padx=4)
        ctk.CTkButton(nr, text="更新订阅", height=34, fg_color="#6366F1", command=self.load_nodes_thread).pack(side="left", fill="x", expand=True, padx=4)

        # 网络设置
        net = self._card(scroll)
        net.pack(fill="x", pady=6)
        ctk.CTkLabel(net, text="网络设置", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w", padx=12, pady=(10, 6))
        tun_row = ctk.CTkFrame(net, fg_color="transparent")
        tun_row.pack(fill="x", padx=12, pady=4)
        tl = ctk.CTkFrame(tun_row, fg_color="transparent")
        tl.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(tl, text="启用 TUN 模式", font=("Microsoft YaHei UI", 13)).pack(anchor="w")
        ctk.CTkLabel(tl, text="接管系统流量（开发中）", font=("Microsoft YaHei UI", 10), text_color=("gray45", "gray55")).pack(anchor="w")
        self.tun_switch = ctk.CTkSwitch(tun_row, text="", command=self.on_tun_placeholder)
        self.tun_switch.pack(side="right")
        lan_row = ctk.CTkFrame(net, fg_color="transparent")
        lan_row.pack(fill="x", padx=12, pady=(4, 12))
        ll = ctk.CTkFrame(lan_row, fg_color="transparent")
        ll.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(ll, text="允许局域网连接", font=("Microsoft YaHei UI", 13)).pack(anchor="w")
        ctk.CTkLabel(ll, text="允许同一 Wi-Fi 设备使用代理", font=("Microsoft YaHei UI", 10), text_color=("gray45", "gray55")).pack(anchor="w")
        self.lan_check = ctk.CTkSwitch(lan_row, text="", command=self.on_lan_option)
        self.lan_check.pack(side="right")

        # 兼容旧代码引用的 status/current 标签（隐藏同步）
        self.status_label = self.home_status
        self.current_label = self.home_node

    def _build_page_nodes(self, root):
        scroll = ctk.CTkScrollableFrame(root, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        ctk.CTkLabel(scroll, text="订阅 / 节点", font=("Microsoft YaHei UI", 16, "bold")).pack(anchor="w", padx=4, pady=(4, 6))
        self.entry = ctk.CTkEntry(scroll, height=36, placeholder_text="订阅 URL 或节点链接")
        self.entry.pack(fill="x", padx=4, pady=4)

        row = ctk.CTkFrame(scroll, fg_color="transparent")
        row.pack(fill="x", pady=4)
        self.load_btn = ctk.CTkButton(row, text="加载", width=64, height=32, command=self.load_nodes_thread)
        self.load_btn.pack(side="left", padx=2)
        self.clip_btn = ctk.CTkButton(row, text="剪贴板", width=64, height=32, command=self.import_clipboard_thread)
        self.clip_btn.pack(side="left", padx=2)
        self.copy_btn = ctk.CTkButton(row, text="复制", width=56, height=32, command=self.copy_selected_node)
        self.copy_btn.pack(side="left", padx=2)
        self.test_btn = ctk.CTkButton(row, text="测速", width=56, height=32, fg_color="#8e44ad", command=self.test_all_thread)
        self.test_btn.pack(side="left", padx=2)
        self.test_filter_btn = ctk.CTkButton(row, text="测筛选", width=64, height=32, fg_color="#9b59b6", command=self.test_filtered_thread)
        self.test_filter_btn.pack(side="left", padx=2)
        self.best_btn = ctk.CTkButton(row, text="最快", width=56, height=32, fg_color="#16a085", command=self.select_best)
        self.best_btn.pack(side="left", padx=2)

        row2 = ctk.CTkFrame(scroll, fg_color="transparent")
        row2.pack(fill="x", pady=4)
        ctk.CTkLabel(row2, text="并发", font=("Microsoft YaHei UI", 12)).pack(side="left", padx=(2, 2))
        self.workers_combo = ctk.CTkComboBox(row2, width=70, values=TEST_WORKERS_OPTIONS, state="readonly")
        self.workers_combo.set(str(TEST_WORKERS_DEFAULT))
        self.workers_combo.pack(side="left", padx=2)
        self.ping_btn = ctk.CTkButton(row2, text="连通性测试", width=100, height=32, fg_color="#d35400", command=self.connectivity_test_thread)
        self.ping_btn.pack(side="left", padx=6)

        fr = ctk.CTkFrame(scroll, fg_color="transparent")
        fr.pack(fill="x", pady=4)
        self.filter_entry = ctk.CTkEntry(fr, height=32, placeholder_text="搜索节点")
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.filter_entry.bind("<KeyRelease>", lambda e: self.apply_node_filter())
        self.filter_clear_btn = ctk.CTkButton(fr, text="清除", width=60, height=32, command=self.clear_node_filter)
        self.filter_clear_btn.pack(side="left")

        self.node_combo = ctk.CTkComboBox(
            scroll, height=34,
            values=["（请先加载订阅或节点）"],
            state="readonly",
            command=self.on_node_picked
        )
        self.node_combo.set("（请先加载订阅或节点）")
        self.node_combo.pack(fill="x", padx=4, pady=8)

        # 启动/停止仅在首页开关，节点页不再重复
        self.start_btn = None
        self.stop_btn = None

    def _build_page_route(self, root):
        scroll = ctk.CTkScrollableFrame(root, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        ctk.CTkLabel(scroll, text="分流与 DNS", font=("Microsoft YaHei UI", 16, "bold")).pack(anchor="w", pady=(4, 8))

        mr = ctk.CTkFrame(scroll, fg_color="transparent")
        mr.pack(fill="x", pady=4)
        ctk.CTkLabel(mr, text="代理模式", font=("Microsoft YaHei UI", 13)).pack(side="left")
        self.mode_combo = ctk.CTkComboBox(mr, width=140, values=PROXY_MODES, state="readonly", command=self.on_mode_change)
        self.mode_combo.set(PROXY_MODE_DEFAULT)
        self.mode_combo.pack(side="left", padx=8)

        ctk.CTkLabel(scroll, text="直连域名", font=("Microsoft YaHei UI", 12)).pack(anchor="w", pady=(10, 2))
        self.direct_entry = ctk.CTkEntry(scroll, height=32, placeholder_text="baidu.com,*.qq.com")
        self.direct_entry.pack(fill="x", pady=2)

        ctk.CTkLabel(scroll, text="代理域名", font=("Microsoft YaHei UI", 12)).pack(anchor="w", pady=(10, 2))
        self.proxy_entry = ctk.CTkEntry(scroll, height=32, placeholder_text="google.com,youtube.com")
        self.proxy_entry.pack(fill="x", pady=2)
        self.domain_apply_btn = ctk.CTkButton(scroll, text="应用域名规则", height=34, command=self.apply_custom_domains)
        self.domain_apply_btn.pack(fill="x", pady=8)

        dns = ctk.CTkFrame(scroll, fg_color="transparent")
        dns.pack(fill="x", pady=8)
        ctk.CTkLabel(dns, text="DNS", font=("Microsoft YaHei UI", 13)).pack(side="left")
        self.dns_combo = ctk.CTkComboBox(dns, width=110, values=DNS_OPTIONS, state="readonly", command=self.on_dns_change)
        self.dns_combo.set("系统默认")
        self.dns_combo.pack(side="left", padx=6)
        self.dns_entry = ctk.CTkEntry(dns, width=160, placeholder_text="自定义 DNS")
        self.dns_entry.insert(0, "8.8.8.8,1.1.1.1")
        self.dns_entry.pack(side="left", padx=4)

        lv = ctk.CTkFrame(scroll, fg_color="transparent")
        lv.pack(fill="x", pady=8)
        ctk.CTkLabel(lv, text="日志级别", font=("Microsoft YaHei UI", 13)).pack(side="left")
        self.loglevel_combo = ctk.CTkComboBox(lv, width=100, values=LOG_LEVELS, state="readonly", command=self.on_loglevel_change)
        self.loglevel_combo.set("警告")
        self.loglevel_combo.pack(side="left", padx=8)

    def _build_page_settings(self, root):
        scroll = ctk.CTkScrollableFrame(root, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        ctk.CTkLabel(scroll, text="设置", font=("Microsoft YaHei UI", 16, "bold")).pack(anchor="w", pady=(4, 8))

        opt = ctk.CTkFrame(scroll, fg_color="transparent")
        opt.pack(fill="x", pady=4)
        self.tray_check = ctk.CTkCheckBox(opt, text="关闭到托盘", command=self.on_tray_option)
        self.tray_check.select()
        self.tray_check.pack(anchor="w", pady=3)
        self.autostart_check = ctk.CTkCheckBox(opt, text="开机自启", command=self.on_autostart_option)
        self.autostart_check.pack(anchor="w", pady=3)
        self.autoconnect_check = ctk.CTkCheckBox(opt, text="启动时自动连接", command=self.on_autoconnect_option)
        self.autoconnect_check.pack(anchor="w", pady=3)
        self.minimized_check = ctk.CTkCheckBox(opt, text="启动后最小化", command=self.on_minimized_option)
        self.minimized_check.pack(anchor="w", pady=3)

        tr = ctk.CTkFrame(scroll, fg_color="transparent")
        tr.pack(fill="x", pady=8)
        ctk.CTkLabel(tr, text="主题", font=("Microsoft YaHei UI", 13)).pack(side="left")
        self.theme_combo = ctk.CTkComboBox(tr, width=120, values=THEME_OPTIONS, state="readonly", command=self.on_theme_change)
        self.theme_combo.set("跟随系统")
        self.theme_combo.pack(side="left", padx=8)

        pr = ctk.CTkFrame(scroll, fg_color="transparent")
        pr.pack(fill="x", pady=8)
        ctk.CTkLabel(pr, text="SOCKS", font=("Microsoft YaHei UI", 12)).pack(side="left")
        self.socks_entry = ctk.CTkEntry(pr, width=80)
        self.socks_entry.insert(0, "10808")
        self.socks_entry.pack(side="left", padx=6)
        ctk.CTkLabel(pr, text="HTTP", font=("Microsoft YaHei UI", 12)).pack(side="left")
        self.http_entry = ctk.CTkEntry(pr, width=80)
        self.http_entry.insert(0, "10809")
        self.http_entry.pack(side="left", padx=6)
        self.apply_port_btn = ctk.CTkButton(pr, text="应用端口", width=80, command=self.apply_ports)
        self.apply_port_btn.pack(side="left", padx=6)

        rr = ctk.CTkFrame(scroll, fg_color="transparent")
        rr.pack(fill="x", pady=8)
        ctk.CTkLabel(rr, text="订阅定时更新", font=("Microsoft YaHei UI", 13)).pack(side="left")
        self.refresh_combo = ctk.CTkComboBox(rr, width=110, values=REFRESH_OPTIONS, state="readonly", command=self.on_refresh_change)
        self.refresh_combo.set("不自动更新")
        self.refresh_combo.pack(side="left", padx=6)
        self.refresh_custom_entry = ctk.CTkEntry(rr, width=60, placeholder_text="小时")
        self.refresh_custom_entry.pack(side="left", padx=4)
        ctk.CTkLabel(rr, text="小时", font=("Microsoft YaHei UI", 12)).pack(side="left")
        ctk.CTkButton(rr, text="应用", width=50, command=self.apply_custom_refresh).pack(side="left", padx=4)

        ur = ctk.CTkFrame(scroll, fg_color="transparent")
        ur.pack(fill="x", pady=10)
        self.clear_log_btn = ctk.CTkButton(ur, text="清空日志", width=100, command=self.clear_log)
        self.clear_log_btn.pack(side="left", padx=4)
        self.update_btn = ctk.CTkButton(ur, text="检查更新", width=100, command=self.check_update_thread)
        self.update_btn.pack(side="left", padx=4)

        ctk.CTkLabel(scroll, text="运行日志", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w", pady=(12, 4))
        self.log_box = ctk.CTkTextbox(scroll, height=220, font=("Consolas", 11))
        self.log_box.pack(fill="both", expand=True, pady=4)

    def on_node_picked(self, value=None):
        node = self.get_selected_node()
        if node:
            self.current_node = node
            try:
                self.home_node.configure(text=f"[{node.get('protocol')}] {node.get('name')}")
                lat = node.get("latency")
                if isinstance(lat, int) and lat >= 0:
                    self.home_latency.configure(text=f"{lat} ms")
                else:
                    self.home_latency.configure(text="")
            except Exception:
                pass

    def on_connect_switch(self):
        if self.connect_switch.get():
            if not self.is_running:
                self.start_proxy_thread()
        else:
            if self.is_running:
                self.stop_proxy()

    def on_tun_placeholder(self):
        self.tun_switch.deselect()
        self.log("TUN 模式开发中，当前版本暂不可用")

    def update_home_stats(self):
        """刷新首页状态显示"""
        try:
            if self.is_running:
                self.home_status.configure(text="已连接", text_color="#10B981")
                self.home_status_hint.configure(text="代理运行中")
                if not self.connect_switch.get():
                    self.connect_switch.select()
            else:
                self.home_status.configure(text="未连接", text_color=("gray20", "gray90"))
                self.home_status_hint.configure(text="点击右侧开关启动引擎")
                if self.connect_switch.get():
                    self.connect_switch.deselect()

            mode = self.mode_combo.get() if hasattr(self, "mode_combo") else self.proxy_mode
            self.lbl_mode.configure(text=mode or "规则模式")

            if self._run_started_at and self.is_running:
                sec = int(time.time() - self._run_started_at)
                h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
                self.lbl_uptime.configure(text=f"{h:02d}:{m:02d}:{s:02d}")
            else:
                self.lbl_uptime.configure(text="00:00:00")

            # 内存
            try:
                import os
                import psutil
                proc = psutil.Process(os.getpid())
                mem_mb = proc.memory_info().rss / (1024 * 1024)
                self.lbl_mem.configure(text=f"{mem_mb:.0f} MB")
            except Exception:
                self.lbl_mem.configure(text="- MB")

            node = self.current_node
            if node:
                self.home_node.configure(text=f"[{node.get('protocol')}] {node.get('name')}")
                lat = node.get("latency")
                if isinstance(lat, int) and lat >= 0:
                    self.home_latency.configure(text=f"{lat} ms")
                else:
                    self.home_latency.configure(text="")
            else:
                self.home_node.configure(text="未选择节点")
                self.home_latency.configure(text="")
        except Exception:
            pass
        self.after(1000, self.update_home_stats)

    def log(self, msg: str):
        def _do():
            self.log_box.insert("end", msg + "\n")
            self.log_box.see("end")
        self.after(0, _do)

    def clear_log(self):
        self.log_box.delete("1.0", "end")
        self.log("日志已清空")

    def check_update_thread(self):
        Thread(target=self.check_update, daemon=True).start()

    def check_update(self):
        self.log("正在检查更新...")
        try:
            # 读取当前仓库信息（从 git remote 不可用时用默认）
            api = "https://api.github.com/repos/Cuarentas/Mobility/releases/latest"
            r = requests.get(api, timeout=15, headers={"User-Agent": "Mobility-Client"})
            if r.status_code == 404:
                self.log("未找到 Release，请确认仓库已发布版本")
                return
            r.raise_for_status()
            data = r.json()
            tag = data.get("tag_name") or data.get("name") or "未知"
            url = data.get("html_url") or ""
            self.log(f"最新版本：{tag}")
            if url:
                self.log(f"发布页面：{url}")
            assets = data.get("assets") or []
            for a in assets:
                if a.get("name"):
                    self.log(f"  资源：{a['name']}")
            self.log("请到 GitHub Releases 下载更新")
        except Exception as e:
            self.log(f"检查更新失败：{e}")

    def startup(self):
        self.prepare_core()
        self.load_settings()
        if TRAY_AVAILABLE:
            self.setup_tray()
            self.log("系统托盘已启用（关闭窗口可最小化到托盘）")
        else:
            self.log("系统托盘不可用（缺少 pystray）")
        # 首页状态刷新
        self.after(500, self.update_home_stats)
        # 订阅定时更新
        self.schedule_subscription_refresh()
        # 启动后最小化到托盘
        if self.start_minimized and TRAY_AVAILABLE:
            self.after(300, self.withdraw)
            self.log("已按设置启动后最小化到托盘")
        # 启动时自动连接
        if self.auto_connect and self.nodes:
            self.log("已开启启动自动连接，正在启动代理...")
            self.after(800, self.start_proxy_thread)

    def prepare_core(self):
        xray_exe = self.core_dir / "xray.exe"
        if xray_exe.exists():
            self.log("已检测到 Xray-core")
            return
        try:
            bundled = get_resource_path("core/xray.exe")
            if bundled.exists():
                shutil.copy2(bundled, xray_exe)
                self.log("已从程序内部提取 Xray-core")
                return
        except Exception as e:
            self.log(f"提取内置核心失败: {e}")
        local_core = self.base_dir / "core" / "xray.exe"
        if local_core.exists() and local_core != xray_exe:
            shutil.copy2(local_core, xray_exe)
            self.log("已使用目录内 Xray-core")
            return
        self.log("未找到 Xray-core，请确保 core/xray.exe 存在")

    def on_mode_change(self, value=None):
        self.proxy_mode = self.mode_combo.get() or PROXY_MODE_DEFAULT
        self.log(f"代理模式已切换为：{self.proxy_mode}")
        self.save_settings()
        if self.is_running:
            self.log("模式已更改，请停止后重新启动代理以生效")

    def on_tray_option(self):
        self.close_to_tray = bool(self.tray_check.get())
        self.save_settings()
        self.log(f"关闭到托盘：{'开启' if self.close_to_tray else '关闭'}")

    def on_autostart_option(self):
        self.auto_start = bool(self.autostart_check.get())
        ok = self.set_auto_start(self.auto_start)
        if ok:
            self.log(f"开机自启：{'已开启' if self.auto_start else '已关闭'}")
        else:
            self.log("设置开机自启失败")
            # 回滚勾选
            if self.auto_start:
                self.autostart_check.deselect()
                self.auto_start = False
            else:
                self.autostart_check.select()
                self.auto_start = True
        self.save_settings()

    def on_autoconnect_option(self):
        self.auto_connect = bool(self.autoconnect_check.get())
        self.save_settings()
        self.log(f"启动时自动连接：{'开启' if self.auto_connect else '关闭'}")

    def on_minimized_option(self):
        self.start_minimized = bool(self.minimized_check.get())
        self.save_settings()
        self.log(f"启动后最小化：{'开启' if self.start_minimized else '关闭'}")

    def on_theme_change(self, value=None):
        self.theme_label = self.theme_combo.get() or "跟随系统"
        mode = THEME_MAP.get(self.theme_label, "System")
        ctk.set_appearance_mode(mode)
        self.save_settings()
        self.log(f"主题已切换：{self.theme_label}")

    def connectivity_test_thread(self):
        Thread(target=self.connectivity_test, daemon=True).start()

    def connectivity_test(self):
        if not self.is_running:
            self.log("请先启动代理再做连通性测试")
            return
        _, http_port = self.get_ports()
        proxies = {
            "http": f"http://127.0.0.1:{http_port}",
            "https": f"http://127.0.0.1:{http_port}",
        }
        targets = [
            ("https://www.google.com/generate_204", "Google"),
            ("https://www.youtube.com", "YouTube"),
            ("https://www.cloudflare.com", "Cloudflare"),
        ]
        self.log("---------- 连通性测试 ----------")
        ok_count = 0
        for url, name in targets:
            try:
                t0 = time.perf_counter()
                r = requests.get(url, proxies=proxies, timeout=8, allow_redirects=True)
                ms = int((time.perf_counter() - t0) * 1000)
                # 204 or 200 都算成功
                if r.status_code in (200, 204, 301, 302):
                    self.log(f"  {name}: 成功 {ms}ms (HTTP {r.status_code})")
                    ok_count += 1
                else:
                    self.log(f"  {name}: 异常 HTTP {r.status_code} ({ms}ms)")
            except Exception as e:
                self.log(f"  {name}: 失败 ({e})")
        self.log(f"连通性结果：{ok_count}/{len(targets)} 成功")
        if ok_count == 0:
            self.log("提示：代理可能未真正可用，请更换节点后重试")

    def on_refresh_change(self, value=None):
        self.refresh_label = self.refresh_combo.get() or "不自动更新"
        self.save_settings()
        self.schedule_subscription_refresh()
        self.log(f"订阅定时更新：{self.refresh_label}")

    def schedule_subscription_refresh(self):
        # 取消旧定时
        job = getattr(self, "_refresh_job", None)
        if job is not None:
            try:
                self.after_cancel(job)
            except Exception:
                pass
            self._refresh_job = None

        label = "不自动更新"
        try:
            label = self.refresh_combo.get()
        except Exception:
            pass
        hours = REFRESH_HOURS.get(label, 0)
        if hours == -1:
            hours = getattr(self, "_custom_refresh_hours", 0) or 0
        if not hours or hours <= 0:
            return
        ms = int(float(hours) * 3600 * 1000)

        def _tick():
            self.log("定时更新：开始拉取订阅...")
            self.load_nodes_thread()
            self.schedule_subscription_refresh()

        self._refresh_job = self.after(ms, _tick)
        self.log(f"订阅定时更新已启用：每 {hours} 小时")


    def _auto_refresh_sub(self):
        self.log(f"定时任务：开始更新订阅（{self.refresh_label}）...")
        if self.subscription_url:
            self.entry.delete(0, "end")
            self.entry.insert(0, self.subscription_url)
            self.load_nodes_thread()
        else:
            self.log("无订阅地址，跳过定时更新")
        # 继续下一轮
        self.schedule_subscription_refresh()

    def import_clipboard_thread(self):
        Thread(target=self.import_clipboard, daemon=True).start()

    def import_clipboard(self):
        try:
            text = self.clipboard_get()
        except Exception:
            text = ""
        text = (text or "").strip()
        if not text:
            self.log("剪贴板为空")
            return
        self.log("正在从剪贴板解析...")
        # 订阅 URL
        if text.startswith(("http://", "https://")):
            self.after(0, lambda: (self.entry.delete(0, "end"), self.entry.insert(0, text)))
            self.subscription_url = text
            self.load_nodes()
            return
        nodes = parse_subscription_content(text)
        if not nodes and "://" in text:
            node = parse_link(text)
            if node:
                nodes = [node]
        if not nodes:
            self.log("剪贴板中未识别到有效节点或订阅链接")
            return
        self.nodes = nodes
        self.refresh_combo(keep_selection=False)
        self.save_settings()
        self.log(f"剪贴板导入成功：{len(nodes)} 个节点")

    def copy_selected_node(self):
        node = self.get_selected_node()
        if not node:
            self.log("没有可复制的节点")
            return
        raw = node.get("raw") or ""
        if not raw:
            self.log("该节点没有原始分享链接")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(raw)
            self.log(f"已复制节点链接：{node.get('name', '')}")
        except Exception as e:
            self.log(f"复制失败：{e}")

    def apply_ports(self):
        try:
            sp = int(self.socks_entry.get().strip())
            hp = int(self.http_entry.get().strip())
            if not (1 <= sp <= 65535 and 1 <= hp <= 65535):
                raise ValueError("端口范围 1-65535")
            if sp == hp:
                raise ValueError("SOCKS 与 HTTP 端口不能相同")
            self.socks_port = sp
            self.http_port = hp
            self.save_settings()
            self.log(f"端口已应用：SOCKS={sp}  HTTP={hp}")
            if self.is_running:
                self.log("端口已更改，请停止后重新启动代理以生效")
        except Exception as e:
            self.log(f"端口设置无效：{e}")

    def get_ports(self):
        try:
            sp = int(self.socks_entry.get().strip())
            hp = int(self.http_entry.get().strip())
            if 1 <= sp <= 65535 and 1 <= hp <= 65535 and sp != hp:
                return sp, hp
        except Exception:
            pass
        return self.socks_port, self.http_port

    def set_auto_start(self, enable: bool) -> bool:
        """写入/删除当前用户开机启动项"""
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "Mobility"
            if getattr(sys, 'frozen', False):
                cmd = f'"{sys.executable}"'
            else:
                cmd = f'"{sys.executable}" "{Path(__file__).resolve()}"'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                if enable:
                    winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, cmd)
                else:
                    try:
                        winreg.DeleteValue(key, app_name)
                    except FileNotFoundError:
                        pass
            return True
        except Exception as e:
            self.log(f"开机自启注册表操作失败：{e}")
            return False

    def make_tray_image(self):
        # 简单生成一个托盘图标
        size = 64
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse((4, 4, size - 4, size - 4), fill=(41, 128, 185, 255))
        draw.ellipse((18, 18, size - 18, size - 18), fill=(236, 240, 241, 255))
        return image

    def load_tray_image(self, state: str = "disconnected"):
        """state: main/connected/pac/warning/disconnected"""
        name_map = {
            "main": ["logo-main-64.png", "logo-main.png"],
            "connected": ["logo-connected-64.png", "logo-connected.png"],
            "pac": ["logo-pac-64.png", "logo-pac.png"],
            "warning": ["logo-warning-64.png", "logo-warning.png"],
            "disconnected": ["logo-disconnected-64.png", "logo-disconnected.png"],
        }
        for name in name_map.get(state, name_map["disconnected"]):
            path = self.icons_dir / name
            try:
                if path.exists() and path.stat().st_size > 100:
                    img = Image.open(path).convert("RGBA")
                    img = img.resize((64, 64), Image.Resampling.LANCZOS)
                    return img
            except Exception:
                continue
        return self.make_tray_image()

    def set_tray_state(self, state: str):
        if not self.tray_icon:
            return
        try:
            self.tray_icon.icon = self.load_tray_image(state)
            labels = {
                "connected": "Mobility - 已连接",
                "pac": "Mobility - 规则模式",
                "warning": "Mobility - 警告",
                "disconnected": "Mobility - 未连接",
                "main": "Mobility",
            }
            self.tray_icon.title = labels.get(state, "Mobility")
        except Exception:
            pass

    def setup_tray(self):
        if not TRAY_AVAILABLE:
            self.log("未安装 pystray，托盘功能不可用")
            return
        if self.tray_icon is not None:
            return

        menu = pystray.Menu(
            pystray.MenuItem("显示主窗口", self.tray_show_window, default=True),
            pystray.MenuItem("启动代理", self.tray_start),
            pystray.MenuItem("停止代理", self.tray_stop),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", self.tray_quit),
        )
        img = self.load_tray_image("disconnected")
        self.tray_icon = pystray.Icon("Mobility", img, "Mobility - 未连接", menu)
        Thread(target=self.tray_icon.run, daemon=True).start()

    def tray_show_window(self, icon=None, item=None):
        def _do():
            self.deiconify()
            self.lift()
            self.focus_force()
        self.after(0, _do)

    def tray_start(self, icon=None, item=None):
        self.after(0, self.start_proxy_thread)

    def tray_stop(self, icon=None, item=None):
        self.after(0, self.stop_proxy)

    def tray_quit(self, icon=None, item=None):
        def _do():
            self.close_to_tray = False
            self.on_closing()
        self.after(0, _do)

    def save_settings(self):
        try:
            slim_nodes = []
            for n in self.nodes:
                item = {k: v for k, v in n.items() if not str(k).startswith("_")}
                slim_nodes.append(item)
            data = {
                "subscription_url": self.subscription_url or self.entry.get().strip(),
                "nodes": slim_nodes,
                "selected_label": self.node_combo.get() if self.nodes else "",
                "test_workers": self.workers_combo.get(),
                "proxy_mode": self.mode_combo.get() if hasattr(self, "mode_combo") else self.proxy_mode,
                "close_to_tray": bool(self.tray_check.get()) if hasattr(self, "tray_check") else self.close_to_tray,
                "auto_start": bool(self.autostart_check.get()) if hasattr(self, "autostart_check") else self.auto_start,
                "auto_connect": bool(self.autoconnect_check.get()) if hasattr(self, "autoconnect_check") else self.auto_connect,
                "socks_port": self.get_ports()[0],
                "http_port": self.get_ports()[1],
                "refresh_label": self.refresh_combo.get() if hasattr(self, "refresh_combo") else self.refresh_label,
                "start_minimized": bool(self.minimized_check.get()) if hasattr(self, "minimized_check") else self.start_minimized,
                "theme_label": self.theme_combo.get() if hasattr(self, "theme_combo") else self.theme_label,
                "allow_lan": bool(self.lan_check.get()) if hasattr(self, "lan_check") else self.allow_lan,
                "direct_domains": self.direct_entry.get().strip() if hasattr(self, "direct_entry") else self.direct_domains,
                "proxy_domains": self.proxy_entry.get().strip() if hasattr(self, "proxy_entry") else self.proxy_domains,
                "dns_mode": self.dns_combo.get() if hasattr(self, "dns_combo") else self.dns_mode,
                "dns_custom": self.dns_entry.get().strip() if hasattr(self, "dns_entry") else self.dns_custom,
                "log_level": self.loglevel_combo.get() if hasattr(self, "loglevel_combo") else self.log_level,
            }
            self.settings_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
        except Exception as e:
            self.log(f"保存设置失败：{e}")

    def load_settings(self):
        if not self.settings_path.exists():
            return
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
            url = data.get("subscription_url") or ""
            nodes = data.get("nodes") or []
            if url:
                self.subscription_url = url
                self.entry.delete(0, "end")
                self.entry.insert(0, url)
            tw = str(data.get("test_workers") or TEST_WORKERS_DEFAULT)
            if tw in TEST_WORKERS_OPTIONS:
                self.workers_combo.set(tw)
            pm = data.get("proxy_mode") or PROXY_MODE_DEFAULT
            if pm in PROXY_MODES:
                self.proxy_mode = pm
                self.mode_combo.set(pm)
            self.close_to_tray = bool(data.get("close_to_tray", True))
            if hasattr(self, "tray_check"):
                if self.close_to_tray:
                    self.tray_check.select()
                else:
                    self.tray_check.deselect()
            self.auto_start = bool(data.get("auto_start", False))
            if hasattr(self, "autostart_check"):
                if self.auto_start:
                    self.autostart_check.select()
                else:
                    self.autostart_check.deselect()
            self.auto_connect = bool(data.get("auto_connect", False))
            if hasattr(self, "autoconnect_check"):
                if self.auto_connect:
                    self.autoconnect_check.select()
                else:
                    self.autoconnect_check.deselect()
            try:
                self.socks_port = int(data.get("socks_port", 10808))
                self.http_port = int(data.get("http_port", 10809))
            except Exception:
                self.socks_port, self.http_port = 10808, 10809
            if hasattr(self, "socks_entry"):
                self.socks_entry.delete(0, "end")
                self.socks_entry.insert(0, str(self.socks_port))
                self.http_entry.delete(0, "end")
                self.http_entry.insert(0, str(self.http_port))
            rl = data.get("refresh_label") or "不自动更新"
            if rl in REFRESH_OPTIONS:
                self.refresh_label = rl
                if hasattr(self, "refresh_combo"):
                    self.refresh_combo.set(rl)
            self.start_minimized = bool(data.get("start_minimized", False))
            if hasattr(self, "minimized_check"):
                if self.start_minimized:
                    self.minimized_check.select()
                else:
                    self.minimized_check.deselect()
            tl = data.get("theme_label") or "跟随系统"
            if tl in THEME_OPTIONS:
                self.theme_label = tl
                if hasattr(self, "theme_combo"):
                    self.theme_combo.set(tl)
                ctk.set_appearance_mode(THEME_MAP.get(tl, "System"))
            self.allow_lan = bool(data.get("allow_lan", False))
            if hasattr(self, "lan_check"):
                try:
                    if self.allow_lan:
                        self.lan_check.select()
                    else:
                        self.lan_check.deselect()
                except Exception:
                    pass
            self.direct_domains = data.get("direct_domains") or ""
            self.proxy_domains = data.get("proxy_domains") or ""
            if hasattr(self, "direct_entry"):
                self.direct_entry.delete(0, "end")
                self.direct_entry.insert(0, self.direct_domains)
                self.proxy_entry.delete(0, "end")
                self.proxy_entry.insert(0, self.proxy_domains)
            self.dns_mode = data.get("dns_mode") or "系统默认"
            if self.dns_mode in DNS_OPTIONS and hasattr(self, "dns_combo"):
                self.dns_combo.set(self.dns_mode)
            self.dns_custom = data.get("dns_custom") or "8.8.8.8,1.1.1.1"
            if hasattr(self, "dns_entry"):
                self.dns_entry.delete(0, "end")
                self.dns_entry.insert(0, self.dns_custom)
            raw_lv = data.get("log_level") or "警告"
            # 兼容旧版英文配置
            if raw_lv in LOG_LEVEL_REV:
                raw_lv = LOG_LEVEL_REV[raw_lv]
            self.log_level = raw_lv if raw_lv in LOG_LEVELS else "警告"
            if hasattr(self, "loglevel_combo"):
                self.loglevel_combo.set(self.log_level)
            if nodes:
                self.nodes = nodes
                for n in self.nodes:
                    if "latency" not in n:
                        n["latency"] = None
                self.refresh_combo(keep_selection=False)
                sel = data.get("selected_label") or ""
                labels = [n.get("_label") for n in self.nodes]
                if sel and sel in labels:
                    self.node_combo.set(sel)
                self.log(f"已恢复上次数据：{len(self.nodes)} 个节点")
            elif url:
                self.log("已恢复订阅地址，请点击「加载订阅」")
        except Exception as e:
            self.log(f"读取本地设置失败：{e}")

    def filtered_nodes(self):
        kw = (self.filter_text or "").strip().lower()
        if not kw:
            return list(self.nodes)
        out = []
        for n in self.nodes:
            blob = f"{n.get('name','')} {n.get('address','')} {n.get('protocol','')}".lower()
            if kw in blob:
                out.append(n)
        return out

    def apply_node_filter(self):
        self.filter_text = self.filter_entry.get() if hasattr(self, "filter_entry") else ""
        self.refresh_combo(keep_selection=True)

    def clear_node_filter(self):
        if hasattr(self, "filter_entry"):
            self.filter_entry.delete(0, "end")
        self.filter_text = ""
        self.refresh_combo(keep_selection=False)
        self.log("已清除节点搜索过滤")

    def on_lan_option(self):
        self.allow_lan = bool(self.lan_check.get())
        self.save_settings()
        self.log(f"允许局域网连接：{'开启' if self.allow_lan else '关闭'}（需重启代理生效）")
        if self.allow_lan:
            self.log("局域网设备可使用本机 IP + 本地端口作为代理")

    def refresh_combo(self, keep_selection: bool = True):
        """在主线程刷新节点下拉列表。"""
        try:
            if not hasattr(self, "node_combo") or self.node_combo is None:
                self.log("刷新失败：node_combo 不存在")
                return
            nodes = list(self.nodes or [])
            if not nodes:
                self.node_combo.configure(values=["（无可用节点）"])
                self.node_combo.set("（无可用节点）")
                self.log("节点列表为空")
                return

            def sort_key(n):
                lat = n.get("latency")
                if lat is None:
                    return (2, 999999)
                if isinstance(lat, (int, float)) and lat < 0:
                    return (1, 999999)
                try:
                    return (0, int(lat))
                except Exception:
                    return (2, 999999)

            nodes.sort(key=sort_key)
            self.nodes = nodes
            labels = []
            for i, n in enumerate(self.nodes):
                try:
                    lb = node_label(n)
                except Exception:
                    lb = f"节点{i+1}"
                n["_label"] = lb
                n["_index"] = i

            kw = ""
            try:
                kw = (self.filter_entry.get() or "").strip().lower()
            except Exception:
                kw = ""
            view_labels = []
            view_nodes = []
            for n in self.nodes:
                if kw:
                    blob = f"{n.get('name','')} {n.get('address','')} {n.get('protocol','')}".lower()
                    if kw not in blob:
                        continue
                view_labels.append(n["_label"])
                view_nodes.append(n)

            if not view_labels:
                self.node_combo.configure(values=["（无匹配节点）"])
                self.node_combo.set("（无匹配节点）")
                self.log("筛选后无节点")
                return

            prev = None
            if keep_selection:
                try:
                    prev = self.node_combo.get()
                except Exception:
                    prev = None

            # CTk 对 list 偶发异常，改用 tuple
            self.node_combo.configure(values=tuple(view_labels))
            if prev and prev in view_labels:
                self.node_combo.set(prev)
            else:
                self.node_combo.set(view_labels[0])
                self.current_node = view_nodes[0]
            self.log(f"节点列表已更新：{len(view_labels)} 条")
        except Exception as e:
            self.log(f"刷新节点列表失败：{type(e).__name__}: {e}")


    def load_nodes_thread(self):
        Thread(target=self.load_nodes, daemon=True).start()

    def load_nodes(self):
        self.after(0, lambda: self.load_btn.configure(state="disabled"))
        text = self.entry.get().strip()
        if not text:
            self.log("错误：请输入订阅链接或节点链接")
            self.after(0, lambda: self.load_btn.configure(state="normal"))
            return

        self.nodes = []
        try:
            if text.startswith(("http://", "https://")):
                self.subscription_url = text
                self.log("正在拉取订阅...")
                resp = requests.get(
                    text,
                    timeout=20,
                    headers={"User-Agent": "Mozilla/5.0 Mobility/0.4"}
                )
                resp.raise_for_status()
                self.nodes = parse_subscription_content(resp.text)
                self.log(f"订阅解析完成，共 {len(self.nodes)} 个节点")
            else:
                self.subscription_url = ""
                if "://" in text and "\n" not in text:
                    node = parse_link(text)
                    if node:
                        self.nodes = [node]
                else:
                    self.nodes = parse_subscription_content(text)
                self.log(f"解析完成，共 {len(self.nodes)} 个节点")
        except Exception as e:
            self.log(f"加载失败：{e}")
            self.after(0, lambda: self.load_btn.configure(state="normal"))
            return

        if not self.nodes:
            self.log("未解析到有效节点")
            self.refresh_combo()
            self.after(0, lambda: self.load_btn.configure(state="normal"))
            return

        count = len(self.nodes)
        # 所有 UI 操作丢回主线程
        def _ui_ok():
            try:
                self.log(f"解析到 {count} 个节点，正在刷新列表...")
                self.refresh_combo(keep_selection=False)
                self.save_settings()
            finally:
                try:
                    self.load_btn.configure(state="normal")
                except Exception:
                    pass
        self.after(0, _ui_ok)

    def on_dns_change(self, value=None):
        self.dns_mode = self.dns_combo.get() or "系统默认"
        self.save_settings()
        self.log(f"DNS 模式：{self.dns_mode}（重启代理后生效）")

    def on_loglevel_change(self, value=None):
        self.log_level = self.loglevel_combo.get() or "警告"
        self.save_settings()
        self.log(f"日志级别：{self.log_level}（重启代理后生效）")

    def test_all_thread(self):
        if self.is_testing:
            self.log("正在测速中，请稍候...")
            return
        if not self.nodes:
            self.log("请先加载节点")
            return
        Thread(target=lambda: self.test_all(only_filtered=False), daemon=True).start()

    def test_filtered_thread(self):
        if self.is_testing:
            self.log("正在测速中，请稍候...")
            return
        if not self.nodes:
            self.log("请先加载节点")
            return
        view = self.filtered_nodes()
        if not view:
            self.log("当前筛选结果为空")
            return
        Thread(target=lambda: self.test_all(only_filtered=True), daemon=True).start()

    def test_all(self, only_filtered: bool = False):
        self.is_testing = True
        self.after(0, lambda: self.test_btn.configure(state="disabled"))
        self.after(0, lambda: self.load_btn.configure(state="disabled"))
        if hasattr(self, "test_filter_btn"):
            self.after(0, lambda: self.test_filter_btn.configure(state="disabled"))

        # 建立待测列表：(全局 index, node)
        if only_filtered:
            targets = []
            for i, n in enumerate(self.nodes):
                if n in self.filtered_nodes() or n.get("_label") in {x.get("_label") for x in self.filtered_nodes()}:
                    targets.append((i, n))
            # 更稳妥：按过滤关键词重新筛
            kw = (self.filter_text or "").strip().lower()
            targets = []
            for i, n in enumerate(self.nodes):
                if not kw:
                    targets.append((i, n))
                else:
                    blob = f"{n.get('name','')} {n.get('address','')} {n.get('protocol','')}".lower()
                    if kw in blob:
                        targets.append((i, n))
            self.log(f"仅测速筛选结果：{len(targets)} 个节点")
        else:
            targets = [(i, n) for i, n in enumerate(self.nodes)]

        total = len(targets)
        if total == 0:
            self.log("没有可测速的节点")
            self.is_testing = False
            self.after(0, lambda: self.test_btn.configure(state="normal"))
            self.after(0, lambda: self.load_btn.configure(state="normal"))
            if hasattr(self, "test_filter_btn"):
                self.after(0, lambda: self.test_filter_btn.configure(state="normal"))
            return

        try:
            chosen = int(self.workers_combo.get())
        except Exception:
            chosen = TEST_WORKERS_DEFAULT
        workers = min(chosen, max(1, total))
        self.log(f"开始并行测速：{total} 个节点，并发 {workers}，超时 {TEST_TIMEOUT}s")

        t_start = time.perf_counter()

        def _one(pair):
            i, node = pair
            ms = tcp_ping(node["address"], int(node["port"]), timeout=TEST_TIMEOUT)
            return i, ms

        ok = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_one, p) for p in targets]
            done = 0
            for fut in as_completed(futs):
                i, ms = fut.result()
                done += 1
                if ms is None:
                    self.nodes[i]["latency"] = -1
                else:
                    self.nodes[i]["latency"] = ms
                    ok += 1
                if done % max(1, total // 5) == 0 or done == total:
                    self.log(f"  进度 {done}/{total} ...")

        elapsed = time.perf_counter() - t_start
        self.log(f"测速完成：成功 {ok}/{total}，耗时 {elapsed:.1f}s")

        ranked = sorted(
            [n for n in self.nodes if isinstance(n.get("latency"), int) and n["latency"] >= 0],
            key=lambda x: x["latency"]
        )
        for n in ranked[:5]:
            self.log(f"  优: {n['name']} → {n['latency']}ms")

        self.refresh_combo(keep_selection=False)
        self.select_best()
        self.save_settings()

        self.is_testing = False
        self.after(0, lambda: self.test_btn.configure(state="normal"))
        self.after(0, lambda: self.load_btn.configure(state="normal"))
        if hasattr(self, "test_filter_btn"):
            self.after(0, lambda: self.test_filter_btn.configure(state="normal"))

    def select_best(self):
        if not self.nodes:
            self.log("没有节点可选")
            return
        best = None
        for n in self.nodes:
            lat = n.get("latency")
            if lat is not None and lat >= 0:
                if best is None or lat < best["latency"]:
                    best = n
        if best is None:
            self.log("没有测速成功的节点，请先点「测速全部」")
            return
        self.refresh_combo(keep_selection=False)

        def _set():
            self.node_combo.set(best["_label"])
        self.after(0, _set)
        self.log(f"已选择最低延迟：{best['name']} ({best['latency']}ms)")
        self.save_settings()

    def get_selected_node(self):
        try:
            label = self.node_combo.get()
        except Exception:
            return self.current_node
        if not label or label.startswith("（"):
            return None
        for n in self.nodes or []:
            if n.get("_label") == label:
                return n
        # 兜底：按名称模糊匹配
        for n in self.nodes or []:
            if n.get("name") and n.get("name") in label:
                return n
        return None


    def parse_domain_list(self, text: str) -> list:
        if not text:
            return []
        parts = []
        for chunk in text.replace("\n", ",").split(","):
            d = chunk.strip().lower()
            if not d:
                continue
            # 支持 *.example.com -> domain:example.com 或完整域名
            if d.startswith("*."):
                d = "domain:" + d[2:]
            elif d.startswith("domain:") or d.startswith("full:") or d.startswith("regexp:"):
                pass
            else:
                d = "domain:" + d
            parts.append(d)
        # 去重保序
        seen = set()
        out = []
        for p in parts:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    def apply_custom_domains(self):
        self.direct_domains = self.direct_entry.get().strip() if hasattr(self, "direct_entry") else ""
        self.proxy_domains = self.proxy_entry.get().strip() if hasattr(self, "proxy_entry") else ""
        self.save_settings()
        dd = self.parse_domain_list(self.direct_domains)
        pd = self.parse_domain_list(self.proxy_domains)
        self.log(f"自定义域名已保存：直连 {len(dd)} 条，代理 {len(pd)} 条")
        if self.is_running:
            self.log("域名规则已更改，请停止后重新启动代理以生效")

    def build_routing_rules(self) -> list:
        """根据代理模式生成路由规则"""
        mode = self.proxy_mode or PROXY_MODE_DEFAULT
        custom_direct = self.parse_domain_list(
            self.direct_entry.get() if hasattr(self, "direct_entry") else self.direct_domains
        )
        custom_proxy = self.parse_domain_list(
            self.proxy_entry.get() if hasattr(self, "proxy_entry") else self.proxy_domains
        )

        rules = []
        # 自定义域名优先
        if custom_direct:
            rules.append({"type": "field", "outboundTag": "direct", "domain": custom_direct})
        if custom_proxy:
            rules.append({"type": "field", "outboundTag": "proxy", "domain": custom_proxy})

        # 直连模式：全部直连
        if mode == "直连模式":
            rules.append({"type": "field", "outboundTag": "direct", "network": "tcp,udp"})
            return rules

        # 全局模式：仅私有地址直连，其余走代理
        if mode == "全局模式":
            rules.append({"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]})
            return rules

        # 规则模式：国内直连，国外代理
        rules.extend([
            {"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]},
            {"type": "field", "outboundTag": "direct", "domain": ["geosite:private"]},
            {"type": "field", "outboundTag": "direct", "ip": ["geoip:cn"]},
            {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]},
        ])
        return rules

    def create_config(self, node: dict) -> Path:
        outbound = build_outbound(node)
        if not outbound:
            raise ValueError("无法生成出站配置")

        mode = self.proxy_mode or PROXY_MODE_DEFAULT
        # 直连模式时默认出站改为 direct，更干净
        outbounds = [
            outbound,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ]
        if mode == "直连模式":
            # 把 direct 放第一位作为默认
            outbounds = [
                {"tag": "direct", "protocol": "freedom"},
                outbound,
                {"tag": "block", "protocol": "blackhole"},
            ]

        socks_port, http_port = self.get_ports()
        listen_ip = "0.0.0.0" if self.allow_lan else "127.0.0.1"

        # DNS
        dns_mode = self.dns_combo.get() if hasattr(self, "dns_combo") else self.dns_mode
        dns_servers = DNS_PRESETS.get(dns_mode)
        if dns_mode == "自定义":
            raw = self.dns_entry.get().strip() if hasattr(self, "dns_entry") else self.dns_custom
            dns_servers = [x.strip() for x in raw.split(",") if x.strip()]
        log_level_label = self.loglevel_combo.get() if hasattr(self, "loglevel_combo") else self.log_level
        log_level = LOG_LEVEL_MAP.get(log_level_label, "warning")

        config = {
            "log": {
                "loglevel": log_level,
                "access": str(self.core_dir / "access.log"),
                "error": str(self.core_dir / "error.log"),
            },
            "inbounds": [
                {
                    "tag": "socks",
                    "port": socks_port,
                    "listen": listen_ip,
                    "protocol": "socks",
                    "settings": {"udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
                {
                    "tag": "http",
                    "port": http_port,
                    "listen": listen_ip,
                    "protocol": "http",
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
            ],
            "outbounds": outbounds,
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": self.build_routing_rules(),
            },
        }
        if dns_servers:
            config["dns"] = {"servers": dns_servers}

        config_path = self.core_dir / "config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return config_path

    def set_system_proxy(self, enable: bool, port: int = 10809):
        try:
            internet_settings = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_WRITE
            )
            if enable:
                winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(internet_settings, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
            else:
                winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(internet_settings)

            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
            return True
        except Exception as e:
            self.log(f"设置系统代理失败：{e}")
            return False

    def read_xray_error(self) -> str:
        err_file = self.core_dir / "error.log"
        if not err_file.exists():
            return ""
        try:
            lines = err_file.read_text(encoding="utf-8", errors="ignore").strip().splitlines()
            return "\n".join(lines[-8:]) if lines else ""
        except Exception:
            return ""

    def start_proxy_thread(self):
        if self.is_running:
            self.log("代理已在运行中，请先停止")
            return
        Thread(target=self.start_proxy, daemon=True).start()

    def start_proxy(self):
        self.after(0, lambda: self.start_btn and self.start_btn.configure(state="disabled") if self.start_btn else None)
        self.log("---------- 开始启动 ----------")

        node = self.get_selected_node()
        if not node:
            text = self.entry.get().strip()
            if text and not text.startswith(("http://", "https://")):
                node = parse_link(text)
            if not node:
                self.log("错误：请先加载订阅并选择节点")
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return

        if not node.get("address") or not node.get("port"):
            self.log("错误：节点地址或端口无效")
            self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
            return

        self.current_node = node
        lat = node.get("latency")
        lat_s = f"{lat}ms" if isinstance(lat, int) and lat >= 0 else "未测速"
        self.log(f"使用节点：[{node['protocol']}] {node['name']} ({lat_s})")
        self.log(f"服务器：{node['address']}:{node['port']}")
        self.log(f"代理模式：{self.proxy_mode}")
        self.after(0, lambda: self.current_label.configure(
            text=f"当前节点：[{node['protocol']}] {node['name']} ({lat_s})"
        ))

        xray_exe = self.core_dir / "xray.exe"
        if not xray_exe.exists():
            self.prepare_core()
            if not xray_exe.exists():
                self.log("错误：找不到 Xray-core")
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return

        for f in ("error.log", "access.log"):
            p = self.core_dir / f
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

        try:
            config_path = self.create_config(node)
            self.log("配置文件已生成")
        except Exception as e:
            self.log(f"生成配置失败：{e}")
            self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
            return

        try:
            log_handle = open(self.log_file, "w", encoding="utf-8")
            self.xray_process = subprocess.Popen(
                [str(xray_exe), "run", "-c", str(config_path)],
                cwd=str(self.core_dir),
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=log_handle,
                stderr=log_handle,
            )

            time.sleep(1.2)
            ret = self.xray_process.poll()
            if ret is not None:
                self.log(f"Xray 启动失败，退出码：{ret}")
                err = self.read_xray_error()
                if err:
                    self.log("错误日志：")
                    for line in err.splitlines():
                        self.log("  " + line)
                else:
                    try:
                        log_handle.close()
                        txt = self.log_file.read_text(encoding="utf-8", errors="ignore").strip()
                        if txt:
                            self.log("Xray 输出：")
                            for line in txt.splitlines()[-10:]:
                                self.log("  " + line)
                    except Exception:
                        pass
                self.xray_process = None
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return

            _, http_port = self.get_ports()
            if self.set_system_proxy(True, http_port):
                self.is_running = True
                self.after(0, lambda: self.status_label.configure(
                    text="状态：运行中", text_color="#27ae60"
                ))
                self.log("Xray 已启动")
                self.log(f"系统代理已设置为 127.0.0.1:{http_port}")
                if self.allow_lan:
                    self.log(f"已允许局域网：其他设备可连 本机IP:{http_port} (HTTP) / {self.get_ports()[0]} (SOCKS)")
                self._run_started_at = time.time()
                mode = self.proxy_mode or ""
                if "规则" in mode:
                    self.set_tray_state("pac")
                else:
                    self.set_tray_state("connected")
                self.save_settings()
            else:
                self.xray_process.terminate()
                self.xray_process = None
                self.log("设置系统代理失败，已停止 Xray")

        except Exception as e:
            self.log(f"启动失败：{e}")
            self.xray_process = None

        self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)

    def stop_proxy(self):
        if self.xray_process:
            try:
                self.xray_process.terminate()
                self.xray_process.wait(timeout=3)
            except Exception:
                try:
                    self.xray_process.kill()
                except Exception:
                    pass
            self.xray_process = None

        self.set_system_proxy(False)
        self.is_running = False
        self._run_started_at = None
        try:
            self.status_label.configure(text="未连接")
            self.current_label.configure(text="未选择节点")
        except Exception:
            pass
        self.set_tray_state("disconnected")
        self.log("代理已停止，系统代理已关闭")

    def on_closing(self):
        # 关闭到托盘
        if self.close_to_tray and TRAY_AVAILABLE and self.tray_icon is not None:
            self.save_settings()
            self.withdraw()
            self.log("已最小化到系统托盘")
            return
        self.stop_proxy()
        self.save_settings()
        try:
            if self.tray_icon is not None:
                self.tray_icon.stop()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = App()
    app.mainloop()
