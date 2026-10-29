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
        if not line.startswith(("vmess://", "vless://", "trojan://")):
            try:
                inner = b64_decode(line).strip()
                if inner.startswith(("vmess://", "vless://", "trojan://")):
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

    return None


def node_label(node: dict) -> str:
    lat = node.get("latency")
    if lat is None:
        lat_s = "未测速"
    elif lat < 0:
        lat_s = "超时"
    else:
        lat_s = f"{lat}ms"
    return f"[{node['protocol']}] {node['name']}  ({lat_s})  {node['address']}:{node['port']}"


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Mobility")
        self.geometry("660x760")
        self.resizable(False, False)

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
        self.tray_icon = None
        self._lock = Lock()

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.after(200, self.startup)

    def create_widgets(self):
        title = ctk.CTkLabel(self, text="Mobility", font=("Microsoft YaHei UI", 22, "bold"))
        title.pack(pady=(14, 4))

        subtitle = ctk.CTkLabel(
            self, text="第八阶段：剪贴板导入 + 定时更新订阅",
            font=("Microsoft YaHei UI", 12)
        )
        subtitle.pack(pady=(0, 8))

        self.entry_label = ctk.CTkLabel(
            self, text="订阅链接 或 单条节点链接：",
            font=("Microsoft YaHei UI", 13)
        )
        self.entry_label.pack(anchor="w", padx=40)

        self.entry = ctk.CTkEntry(
            self, width=560, height=34,
            placeholder_text="https://... 订阅地址，或 vmess:// / vless:// / trojan://"
        )
        self.entry.pack(pady=6)

        mid_btn = ctk.CTkFrame(self, fg_color="transparent")
        mid_btn.pack(pady=6)

        self.load_btn = ctk.CTkButton(
            mid_btn, text="加载订阅", width=100, height=34,
            font=("Microsoft YaHei UI", 13),
            command=self.load_nodes_thread
        )
        self.load_btn.pack(side="left", padx=4)

        self.clip_btn = ctk.CTkButton(
            mid_btn, text="剪贴板导入", width=100, height=34,
            font=("Microsoft YaHei UI", 13),
            fg_color="#2980b9", hover_color="#1f6a9a",
            command=self.import_clipboard_thread
        )
        self.clip_btn.pack(side="left", padx=4)

        self.copy_btn = ctk.CTkButton(
            mid_btn, text="复制节点", width=90, height=34,
            font=("Microsoft YaHei UI", 13),
            fg_color="#7f8c8d", hover_color="#636e72",
            command=self.copy_selected_node
        )
        self.copy_btn.pack(side="left", padx=4)

        self.test_btn = ctk.CTkButton(
            mid_btn, text="测速全部", width=90, height=34,
            font=("Microsoft YaHei UI", 13),
            fg_color="#8e44ad", hover_color="#6c3483",
            command=self.test_all_thread
        )
        self.test_btn.pack(side="left", padx=6)

        self.best_btn = ctk.CTkButton(
            mid_btn, text="最低延迟", width=90, height=34,
            font=("Microsoft YaHei UI", 13),
            fg_color="#16a085", hover_color="#117a65",
            command=self.select_best
        )
        self.best_btn.pack(side="left", padx=6)

        self.workers_label = ctk.CTkLabel(mid_btn, text="并发:", font=("Microsoft YaHei UI", 12))
        self.workers_label.pack(side="left", padx=(12, 4))

        self.workers_combo = ctk.CTkComboBox(
            mid_btn, width=72, height=34,
            values=TEST_WORKERS_OPTIONS,
            state="readonly",
            font=("Microsoft YaHei UI", 12)
        )
        self.workers_combo.set(str(TEST_WORKERS_DEFAULT))
        self.workers_combo.pack(side="left", padx=2)

        mode_row = ctk.CTkFrame(self, fg_color="transparent")
        mode_row.pack(pady=(4, 0))

        ctk.CTkLabel(mode_row, text="代理模式：", font=("Microsoft YaHei UI", 13)).pack(side="left", padx=(0, 8))
        self.mode_combo = ctk.CTkComboBox(
            mode_row, width=140, height=32,
            values=PROXY_MODES,
            state="readonly",
            font=("Microsoft YaHei UI", 12),
            command=self.on_mode_change
        )
        self.mode_combo.set(PROXY_MODE_DEFAULT)
        self.mode_combo.pack(side="left")

        opt_row = ctk.CTkFrame(self, fg_color="transparent")
        opt_row.pack(pady=(6, 0))

        self.tray_check = ctk.CTkCheckBox(
            opt_row, text="关闭到托盘",
            font=("Microsoft YaHei UI", 12),
            command=self.on_tray_option
        )
        self.tray_check.select()
        self.tray_check.pack(side="left", padx=8)

        self.autostart_check = ctk.CTkCheckBox(
            opt_row, text="开机自启",
            font=("Microsoft YaHei UI", 12),
            command=self.on_autostart_option
        )
        self.autostart_check.pack(side="left", padx=8)

        self.autoconnect_check = ctk.CTkCheckBox(
            opt_row, text="启动时自动连接",
            font=("Microsoft YaHei UI", 12),
            command=self.on_autoconnect_option
        )
        self.autoconnect_check.pack(side="left", padx=8)

        port_row = ctk.CTkFrame(self, fg_color="transparent")
        port_row.pack(pady=(6, 0))

        ctk.CTkLabel(port_row, text="SOCKS:", font=("Microsoft YaHei UI", 12)).pack(side="left")
        self.socks_entry = ctk.CTkEntry(port_row, width=70, height=30)
        self.socks_entry.insert(0, "10808")
        self.socks_entry.pack(side="left", padx=(4, 12))

        ctk.CTkLabel(port_row, text="HTTP:", font=("Microsoft YaHei UI", 12)).pack(side="left")
        self.http_entry = ctk.CTkEntry(port_row, width=70, height=30)
        self.http_entry.insert(0, "10809")
        self.http_entry.pack(side="left", padx=(4, 12))

        self.apply_port_btn = ctk.CTkButton(
            port_row, text="应用端口", width=80, height=30,
            font=("Microsoft YaHei UI", 12),
            command=self.apply_ports
        )
        self.apply_port_btn.pack(side="left", padx=4)

        refresh_row = ctk.CTkFrame(self, fg_color="transparent")
        refresh_row.pack(pady=(6, 0))
        ctk.CTkLabel(refresh_row, text="订阅定时更新：", font=("Microsoft YaHei UI", 12)).pack(side="left")
        self.refresh_combo = ctk.CTkComboBox(
            refresh_row, width=120, height=30,
            values=REFRESH_OPTIONS,
            state="readonly",
            font=("Microsoft YaHei UI", 12),
            command=self.on_refresh_change
        )
        self.refresh_combo.set("不自动更新")
        self.refresh_combo.pack(side="left", padx=6)

        self.node_label = ctk.CTkLabel(self, text="选择节点：", font=("Microsoft YaHei UI", 13))
        self.node_label.pack(anchor="w", padx=40, pady=(8, 0))

        self.node_combo = ctk.CTkComboBox(
            self, width=560, height=34,
            values=["（请先加载订阅或节点）"],
            state="readonly",
            font=("Microsoft YaHei UI", 12)
        )
        self.node_combo.set("（请先加载订阅或节点）")
        self.node_combo.pack(pady=6)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=10)

        self.start_btn = ctk.CTkButton(
            btn_frame, text="启动代理", width=150, height=40,
            font=("Microsoft YaHei UI", 14),
            command=self.start_proxy_thread
        )
        self.start_btn.pack(side="left", padx=12)

        self.stop_btn = ctk.CTkButton(
            btn_frame, text="停止代理", width=150, height=40,
            font=("Microsoft YaHei UI", 14),
            fg_color="#c0392b", hover_color="#922b21",
            command=self.stop_proxy
        )
        self.stop_btn.pack(side="left", padx=12)

        self.status_label = ctk.CTkLabel(self, text="状态：未运行", font=("Microsoft YaHei UI", 14))
        self.status_label.pack(pady=4)

        self.current_label = ctk.CTkLabel(
            self, text="当前节点：无",
            font=("Microsoft YaHei UI", 12),
            text_color=("gray40", "gray60")
        )
        self.current_label.pack(pady=(0, 4))

        self.log_box = ctk.CTkTextbox(self, width=580, height=180, font=("Consolas", 12))
        self.log_box.pack(pady=6)
        self.log("欢迎使用 Mobility")
        self.log(f"默认并行测速并发数：{TEST_WORKERS_DEFAULT}（可在界面调整）")
        self.log("代理模式：规则(国内直连) / 全局 / 直连")
        self.log("支持关闭到系统托盘、开机自启、启动自动连接")
        self.log("可自定义本地 SOCKS / HTTP 端口")
        self.log("支持剪贴板导入、复制节点、订阅定时更新")
        self.log("数据保存到 Subscribe.json")

    def log(self, msg: str):
        def _do():
            self.log_box.insert("end", msg + "\n")
            self.log_box.see("end")
        self.after(0, _do)

    def startup(self):
        self.prepare_core()
        self.load_settings()
        if TRAY_AVAILABLE:
            self.setup_tray()
            self.log("系统托盘已启用（关闭窗口可最小化到托盘）")
        else:
            self.log("系统托盘不可用（缺少 pystray）")
        # 订阅定时更新
        self.schedule_subscription_refresh()
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

    def on_refresh_change(self, value=None):
        self.refresh_label = self.refresh_combo.get() or "不自动更新"
        self.save_settings()
        self.schedule_subscription_refresh()
        self.log(f"订阅定时更新：{self.refresh_label}")

    def schedule_subscription_refresh(self):
        # 取消旧定时器
        if self._refresh_after_id is not None:
            try:
                self.after_cancel(self._refresh_after_id)
            except Exception:
                pass
            self._refresh_after_id = None
        hours = REFRESH_HOURS.get(self.refresh_label, 0)
        if hours <= 0:
            return
        ms = int(hours * 3600 * 1000)
        self._refresh_after_id = self.after(ms, self._auto_refresh_sub)

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
        self.tray_icon = pystray.Icon("Mobility", self.make_tray_image(), "Mobility", menu)
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

    def refresh_combo(self, keep_selection: bool = True):
        def _do():
            if not self.nodes:
                self.node_combo.configure(values=["（无可用节点）"])
                self.node_combo.set("（无可用节点）")
                return

            def sort_key(n):
                lat = n.get("latency")
                if lat is None:
                    return (2, 999999)
                if lat < 0:
                    return (1, 999999)
                return (0, lat)

            self.nodes.sort(key=sort_key)
            labels = []
            for i, n in enumerate(self.nodes):
                label = node_label(n)
                n["_label"] = label
                n["_index"] = i
                labels.append(label)

            prev = self.node_combo.get() if keep_selection else None
            self.node_combo.configure(values=labels)
            if prev and prev in labels:
                self.node_combo.set(prev)
            else:
                self.node_combo.set(labels[0])

        self.after(0, _do)

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

        self.refresh_combo(keep_selection=False)
        self.save_settings()
        self.log("已载入并保存，可点击「测速全部」")
        self.after(0, lambda: self.load_btn.configure(state="normal"))

    def test_all_thread(self):
        if self.is_testing:
            self.log("正在测速中，请稍候...")
            return
        if not self.nodes:
            self.log("请先加载节点")
            return
        Thread(target=self.test_all, daemon=True).start()

    def test_all(self):
        self.is_testing = True
        self.after(0, lambda: self.test_btn.configure(state="disabled"))
        self.after(0, lambda: self.load_btn.configure(state="disabled"))

        total = len(self.nodes)
        try:
            chosen = int(self.workers_combo.get())
        except Exception:
            chosen = TEST_WORKERS_DEFAULT
        workers = min(chosen, max(1, total))
        self.log(f"开始并行测速：{total} 个节点，并发 {workers}，超时 {TEST_TIMEOUT}s")

        t_start = time.perf_counter()

        def _one(i: int, node: dict):
            ms = tcp_ping(node["address"], int(node["port"]), timeout=TEST_TIMEOUT)
            return i, ms

        ok = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_one, i, n) for i, n in enumerate(self.nodes)]
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

    def get_selected_node(self) -> dict | None:
        if not self.nodes:
            return None
        current = self.node_combo.get()
        for n in self.nodes:
            if n.get("_label") == current:
                return n
        return self.nodes[0]

    def build_routing_rules(self) -> list:
        """根据代理模式生成路由规则"""
        mode = self.proxy_mode or PROXY_MODE_DEFAULT

        # 直连模式：全部直连
        if mode == "直连模式":
            return [
                {"type": "field", "outboundTag": "direct", "network": "tcp,udp"}
            ]

        # 全局模式：仅私有地址直连，其余走代理
        if mode == "全局模式":
            return [
                {"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]},
            ]

        # 规则模式：国内直连，国外代理
        return [
            {"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]},
            {"type": "field", "outboundTag": "direct", "domain": ["geosite:private"]},
            {"type": "field", "outboundTag": "direct", "ip": ["geoip:cn"]},
            {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]},
        ]

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

        config = {
            "log": {
                "loglevel": "warning",
                "access": str(self.core_dir / "access.log"),
                "error": str(self.core_dir / "error.log"),
            },
            "inbounds": [
                {
                    "tag": "socks",
                    "port": socks_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
                {
                    "tag": "http",
                    "port": http_port,
                    "listen": "127.0.0.1",
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
        self.after(0, lambda: self.start_btn.configure(state="disabled"))
        self.log("---------- 开始启动 ----------")

        node = self.get_selected_node()
        if not node:
            text = self.entry.get().strip()
            if text and not text.startswith(("http://", "https://")):
                node = parse_link(text)
            if not node:
                self.log("错误：请先加载订阅并选择节点")
                self.after(0, lambda: self.start_btn.configure(state="normal"))
                return

        if not node.get("address") or not node.get("port"):
            self.log("错误：节点地址或端口无效")
            self.after(0, lambda: self.start_btn.configure(state="normal"))
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
                self.after(0, lambda: self.start_btn.configure(state="normal"))
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
            self.after(0, lambda: self.start_btn.configure(state="normal"))
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
                self.after(0, lambda: self.start_btn.configure(state="normal"))
                return

            _, http_port = self.get_ports()
            if self.set_system_proxy(True, http_port):
                self.is_running = True
                self.after(0, lambda: self.status_label.configure(
                    text="状态：运行中", text_color="#27ae60"
                ))
                self.log("Xray 已启动")
                self.log(f"系统代理已设置为 127.0.0.1:{http_port}")
                self.save_settings()
            else:
                self.xray_process.terminate()
                self.xray_process = None
                self.log("设置系统代理失败，已停止 Xray")

        except Exception as e:
            self.log(f"启动失败：{e}")
            self.xray_process = None

        self.after(0, lambda: self.start_btn.configure(state="normal"))

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
        self.status_label.configure(text="状态：已停止", text_color=("gray10", "gray90"))
        self.current_label.configure(text="当前节点：无")
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
