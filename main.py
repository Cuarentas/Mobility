import customtkinter as ctk
import subprocess
import sys
import json
import base64
import urllib.parse
import time
import winreg
import ctypes
import shutil
import requests
from pathlib import Path
from threading import Thread

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


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
    """解析订阅内容，返回节点列表"""
    content = content.strip()
    nodes = []

    # 常见：整段 base64
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
        # 单行也可能再套一层 base64
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


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Mobility")
        self.geometry("600x560")
        self.resizable(False, False)

        self.base_dir = get_base_dir()
        self.core_dir = self.base_dir / "core"
        self.core_dir.mkdir(exist_ok=True)
        self.log_file = self.core_dir / "xray.log"

        self.xray_process = None
        self.is_running = False
        self.nodes: list[dict] = []
        self.current_node = None

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.after(200, self.prepare_core)

    def create_widgets(self):
        title = ctk.CTkLabel(self, text="Mobility", font=("Microsoft YaHei UI", 22, "bold"))
        title.pack(pady=(16, 4))

        subtitle = ctk.CTkLabel(
            self, text="第三阶段：订阅解析 + 节点选择",
            font=("Microsoft YaHei UI", 12)
        )
        subtitle.pack(pady=(0, 10))

        self.entry_label = ctk.CTkLabel(
            self, text="订阅链接 或 单条节点链接：",
            font=("Microsoft YaHei UI", 13)
        )
        self.entry_label.pack(anchor="w", padx=40)

        self.entry = ctk.CTkEntry(
            self, width=520, height=34,
            placeholder_text="https://... 订阅地址，或 vmess:// / vless:// / trojan://"
        )
        self.entry.pack(pady=6)

        mid_btn = ctk.CTkFrame(self, fg_color="transparent")
        mid_btn.pack(pady=6)

        self.load_btn = ctk.CTkButton(
            mid_btn, text="加载订阅 / 解析节点", width=160, height=34,
            font=("Microsoft YaHei UI", 13),
            command=self.load_nodes_thread
        )
        self.load_btn.pack(side="left", padx=8)

        self.node_label = ctk.CTkLabel(self, text="选择节点：", font=("Microsoft YaHei UI", 13))
        self.node_label.pack(anchor="w", padx=40, pady=(8, 0))

        self.node_combo = ctk.CTkComboBox(
            self, width=520, height=34,
            values=["（请先加载订阅或节点）"],
            state="readonly",
            font=("Microsoft YaHei UI", 12)
        )
        self.node_combo.set("（请先加载订阅或节点）")
        self.node_combo.pack(pady=6)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=12)

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

        self.log_box = ctk.CTkTextbox(self, width=540, height=170, font=("Consolas", 12))
        self.log_box.pack(pady=6)
        self.log("欢迎使用 Mobility 第三阶段")
        self.log("支持：订阅链接 / 单条 vmess·vless·trojan 节点")
        self.log("先点击「加载订阅 / 解析节点」，再选择节点并启动")

    def log(self, msg: str):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

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

    def load_nodes_thread(self):
        Thread(target=self.load_nodes, daemon=True).start()

    def load_nodes(self):
        self.load_btn.configure(state="disabled")
        text = self.entry.get().strip()
        if not text:
            self.log("错误：请输入订阅链接或节点链接")
            self.load_btn.configure(state="normal")
            return

        self.nodes = []
        try:
            if text.startswith(("http://", "https://")):
                self.log("正在拉取订阅...")
                resp = requests.get(
                    text,
                    timeout=20,
                    headers={"User-Agent": "Mozilla/5.0 Mobility/0.3"}
                )
                resp.raise_for_status()
                content = resp.text
                self.nodes = parse_subscription_content(content)
                self.log(f"订阅解析完成，共 {len(self.nodes)} 个节点")
            else:
                # 单条或多条（换行分隔）节点
                if "://" in text and "\n" not in text:
                    node = parse_link(text)
                    if node:
                        self.nodes = [node]
                else:
                    self.nodes = parse_subscription_content(text)
                self.log(f"解析完成，共 {len(self.nodes)} 个节点")
        except Exception as e:
            self.log(f"加载失败：{e}")
            self.load_btn.configure(state="normal")
            return

        if not self.nodes:
            self.log("未解析到有效节点，请检查链接")
            self.node_combo.configure(values=["（无可用节点）"])
            self.node_combo.set("（无可用节点）")
            self.load_btn.configure(state="normal")
            return

        labels = []
        for i, n in enumerate(self.nodes):
            label = f"[{n['protocol']}] {n['name']}  ({n['address']}:{n['port']})"
            labels.append(label)
            # 避免重名显示问题，内部用索引
            n["_label"] = label
            n["_index"] = i

        self.node_combo.configure(values=labels)
        self.node_combo.set(labels[0])
        self.log(f"已载入，默认选择第 1 个节点")
        self.load_btn.configure(state="normal")

    def get_selected_node(self) -> dict | None:
        if not self.nodes:
            return None
        current = self.node_combo.get()
        for n in self.nodes:
            if n.get("_label") == current:
                return n
        return self.nodes[0]

    def create_config(self, node: dict) -> Path:
        outbound = build_outbound(node)
        if not outbound:
            raise ValueError("无法生成出站配置")

        config = {
            "log": {
                "loglevel": "warning",
                "access": str(self.core_dir / "access.log"),
                "error": str(self.core_dir / "error.log"),
            },
            "inbounds": [
                {
                    "tag": "socks",
                    "port": 10808,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
                {
                    "tag": "http",
                    "port": 10809,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
            ],
            "outbounds": [
                outbound,
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "outboundTag": "direct",
                        "ip": ["geoip:private"],
                    }
                ],
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
        self.start_btn.configure(state="disabled")
        self.log("---------- 开始启动 ----------")

        node = self.get_selected_node()
        if not node:
            # 兼容：输入框里直接是单节点且未点加载
            text = self.entry.get().strip()
            if text and not text.startswith(("http://", "https://")):
                node = parse_link(text)
            if not node:
                self.log("错误：请先加载订阅并选择节点")
                self.start_btn.configure(state="normal")
                return

        if not node.get("address") or not node.get("port"):
            self.log("错误：节点地址或端口无效")
            self.start_btn.configure(state="normal")
            return

        self.current_node = node
        self.log(f"使用节点：[{node['protocol']}] {node['name']}")
        self.log(f"服务器：{node['address']}:{node['port']}")
        self.current_label.configure(text=f"当前节点：[{node['protocol']}] {node['name']}")

        xray_exe = self.core_dir / "xray.exe"
        if not xray_exe.exists():
            self.prepare_core()
            if not xray_exe.exists():
                self.log("错误：找不到 Xray-core")
                self.start_btn.configure(state="normal")
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
            self.start_btn.configure(state="normal")
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
                self.start_btn.configure(state="normal")
                return

            if self.set_system_proxy(True, 10809):
                self.is_running = True
                self.status_label.configure(text="状态：运行中", text_color="#27ae60")
                self.log("Xray 已启动")
                self.log("系统代理已设置为 127.0.0.1:10809")
            else:
                self.xray_process.terminate()
                self.xray_process = None
                self.log("设置系统代理失败，已停止 Xray")

        except Exception as e:
            self.log(f"启动失败：{e}")
            self.xray_process = None

        self.start_btn.configure(state="normal")

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
        self.stop_proxy()
        self.destroy()


if __name__ == "__main__":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = App()
    app.mainloop()
