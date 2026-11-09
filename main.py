import customtkinter as ctk
import subprocess
import sys
import json
import re
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
CORE_OPTIONS = ["Xray", "sing-box", "Mihomo"]
CORE_PROTOCOLS = ["vmess", "vless", "trojan", "shadowsocks", "socks", "http"]
DEFAULT_CORE_MAP = {p: "Xray" for p in CORE_PROTOCOLS}
PROXY_MODE_DEFAULT = "规则模式"
REFRESH_OPTIONS = ["不自动更新", "1小时", "6小时", "12小时", "24小时", "自定义"]
REFRESH_HOURS = {"不自动更新": 0, "1小时": 1, "6小时": 6, "12小时": 12, "24小时": 24}
THEME_OPTIONS = ["跟随系统", "浅色", "深色"]
FONT_SIZE_OPTIONS = ["12", "13", "14", "15", "16", "18"]
FONT_SIZE_DEFAULT = "13"
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

APP_VERSION = "0.18.3"
GITHUB_REPO = "Cuarentas/Mobility"


def normalize_version(v: str) -> tuple:
    v = (v or "").strip().lstrip("vV")
    parts = []
    for x in v.split("."):
        try:
            parts.append(int(re.sub(r"[^0-9].*", "", x) or 0))
        except Exception:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def version_newer(remote: str, local: str) -> bool:
    return normalize_version(remote) > normalize_version(local)



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



def find_xray():
    """查找 xray.exe 路径"""
    candidates = [
        get_base_dir() / "core" / "xray.exe",
        get_base_dir() / "xray.exe",
    ]
    try:
        candidates.append(get_resource_path("core/xray.exe"))
    except Exception:
        pass
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        candidates.append(Path(sys._MEIPASS) / "core" / "xray.exe")
    for c in candidates:
        try:
            if c and Path(c).exists():
                return Path(c)
        except Exception:
            pass
    return None


def ensure_wintun(core_dir: Path, log_fn=None) -> bool:
    """确保 wintun.dll 与 xray.exe 同目录（Windows system 栈必需）。"""
    core_dir = Path(core_dir)
    core_dir.mkdir(parents=True, exist_ok=True)
    dest = core_dir / "wintun.dll"
    targets = [
        dest,
        get_base_dir() / "wintun.dll",
        get_base_dir() / "core" / "wintun.dll",
    ]
    for pth in targets:
        if pth.exists() and pth.stat().st_size > 1000:
            if pth.resolve() != dest.resolve():
                try:
                    import shutil
                    shutil.copy2(pth, dest)
                    if log_fn:
                        log_fn(f"已复制 wintun.dll → {dest}")
                except Exception:
                    pass
            return dest.exists()
    # 从官方包下载（含多架构）
    url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
    try:
        if log_fn:
            log_fn("正在下载 wintun.dll ...")
        import tempfile, zipfile
        r = requests.get(url, timeout=60, headers={"User-Agent": "Mobility"})
        r.raise_for_status()
        tmp = Path(tempfile.gettempdir()) / "wintun.zip"
        tmp.write_bytes(r.content)
        out = Path(core_dir) / "wintun.dll"
        Path(core_dir).mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmp, "r") as zf:
            # prefer amd64
            candidates = [n for n in zf.namelist() if n.lower().endswith("wintun.dll")]
            pick = None
            for n in candidates:
                if "amd64" in n.lower() or "x64" in n.lower():
                    pick = n
                    break
            if not pick and candidates:
                pick = candidates[0]
            if not pick:
                if log_fn:
                    log_fn("wintun 压缩包内未找到 dll")
                return False
            out.write_bytes(zf.read(pick))
        if log_fn:
            log_fn(f"wintun.dll 已保存到 {out}")
        return out.exists()
    except Exception as e:
        if log_fn:
            log_fn(f"下载 wintun 失败：{e}")
        return False



def find_singbox():
    candidates = [
        get_base_dir() / "core" / "sing-box.exe",
        get_base_dir() / "sing-box.exe",
    ]
    try:
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            candidates.append(Path(sys._MEIPASS) / "core" / "sing-box.exe")
    except Exception:
        pass
    for c in candidates:
        try:
            if c.exists():
                return c
        except Exception:
            pass
    return None


def ensure_singbox(core_dir: Path, log_fn=None):
    """确保 sing-box.exe 存在；缺失时尝试从 GitHub 下载。"""
    core_dir = Path(core_dir)
    core_dir.mkdir(parents=True, exist_ok=True)
    dest = core_dir / "sing-box.exe"
    if dest.exists() and dest.stat().st_size > 1000:
        return dest
    existing = find_singbox()
    if existing and existing.resolve() != dest.resolve():
        try:
            import shutil
            shutil.copy2(existing, dest)
            return dest
        except Exception:
            pass
    # 官方资源名含版本号，先走 API 再下载
    try:
        if log_fn:
            log_fn("正在下载 sing-box 核心 ...")
        import tempfile, zipfile
        api = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
        meta = requests.get(api, timeout=30, headers={"User-Agent": "Mobility"}).json()
        url = None
        for a in meta.get("assets") or []:
            name = a.get("name") or ""
            if name.endswith("windows-amd64.zip") and "cgo" not in name:
                url = a.get("browser_download_url")
                break
        if not url:
            for a in meta.get("assets") or []:
                name = (a.get("name") or "").lower()
                if "windows" in name and "amd64" in name and name.endswith(".zip"):
                    url = a.get("browser_download_url")
                    break
        if not url:
            if log_fn:
                log_fn("未找到 sing-box windows-amd64 资源")
            return None
        r = requests.get(url, timeout=120, headers={"User-Agent": "Mobility"})
        r.raise_for_status()
        tmp = Path(tempfile.gettempdir()) / "singbox.zip"
        tmp.write_bytes(r.content)
        with zipfile.ZipFile(tmp, "r") as zf:
            pick = None
            for n in zf.namelist():
                if n.lower().endswith("sing-box.exe"):
                    pick = n
                    break
            if not pick:
                if log_fn:
                    log_fn("sing-box 压缩包内未找到 exe")
                return None
            dest.write_bytes(zf.read(pick))
        if log_fn:
            log_fn(f"sing-box 已保存到 {dest}")
        return dest if dest.exists() else None
    except Exception as e:
        if log_fn:
            log_fn(f"下载 sing-box 失败：{e}")
        return None


def find_mihomo():
    candidates = [
        get_base_dir() / "core" / "mihomo.exe",
        get_base_dir() / "mihomo.exe",
    ]
    try:
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            candidates.append(Path(sys._MEIPASS) / "core" / "mihomo.exe")
    except Exception:
        pass
    for c in candidates:
        try:
            if c.exists():
                return c
        except Exception:
            pass
    return None


def ensure_mihomo(core_dir: Path, log_fn=None):
    """确保 mihomo.exe 存在；缺失时从 GitHub 下载。"""
    core_dir = Path(core_dir)
    core_dir.mkdir(parents=True, exist_ok=True)
    dest = core_dir / "mihomo.exe"
    if dest.exists() and dest.stat().st_size > 1000:
        return dest
    existing = find_mihomo()
    if existing and existing.resolve() != dest.resolve():
        try:
            import shutil
            shutil.copy2(existing, dest)
            return dest
        except Exception:
            pass
    try:
        if log_fn:
            log_fn("正在下载 Mihomo 核心 ...")
        import tempfile, zipfile
        api = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
        meta = requests.get(api, timeout=30, headers={"User-Agent": "Mobility"}).json()
        url = None
        # 优先：mihomo-windows-amd64-vX.Y.Z.zip（非 compatible / 非 go1xx）
        assets = meta.get("assets") or []
        for a in assets:
            name = a.get("name") or ""
            if re.match(r"mihomo-windows-amd64-v[\d.]+\.zip$", name):
                url = a.get("browser_download_url")
                break
        if not url:
            for a in assets:
                name = (a.get("name") or "").lower()
                if "windows-amd64" in name and name.endswith(".zip") and "compatible" not in name:
                    url = a.get("browser_download_url")
                    break
        if not url:
            if log_fn:
                log_fn("未找到 mihomo windows-amd64 资源")
            return None
        r = requests.get(url, timeout=120, headers={"User-Agent": "Mobility"})
        r.raise_for_status()
        tmp = Path(tempfile.gettempdir()) / "mihomo.zip"
        tmp.write_bytes(r.content)
        with zipfile.ZipFile(tmp, "r") as zf:
            pick = None
            for n in zf.namelist():
                low = n.lower()
                if low.endswith(".exe") and "mihomo" in low:
                    pick = n
                    break
            if not pick:
                for n in zf.namelist():
                    if n.lower().endswith(".exe"):
                        pick = n
                        break
            if not pick:
                if log_fn:
                    log_fn("mihomo 压缩包内未找到 exe")
                return None
            dest.write_bytes(zf.read(pick))
        if log_fn:
            log_fn(f"mihomo 已保存到 {dest}")
        return dest if dest.exists() else None
    except Exception as e:
        if log_fn:
            log_fn(f"下载 mihomo 失败：{e}")
        return None


def get_core_binary_version(exe_path, name_hint="") -> str:
    """尝试读取核心 exe 版本号。"""
    if not exe_path:
        return "未安装"
    try:
        path = Path(exe_path)
        if not path.exists():
            return "未安装"
    except Exception:
        return "未安装"
    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        # 常见：version / -version / -v
        for args in ([str(path), "version"], [str(path), "-version"], [str(path), "-v"]):
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=5, creationflags=flags)
                out = (r.stdout or "") + (r.stderr or "")
                out = out.strip()
                if not out:
                    continue
                # Xray: Xray 1.8.x / 26.x
                m = re.search(r"Xray\s+([0-9.]+)", out, re.I)
                if m:
                    return m.group(1)
                # sing-box: version x.y.z
                m = re.search(r"version\s+([0-9.]+)", out, re.I)
                if m:
                    return m.group(1)
                m = re.search(r"sing-box\s+.*?([0-9]+\.[0-9]+\.[0-9]+)", out, re.I)
                if m:
                    return m.group(1)
                # mihomo / clash meta
                m = re.search(r"(?:Mihomo|Clash)\s*(?:Meta)?\s*v?([0-9.]+)", out, re.I)
                if m:
                    return m.group(1)
                m = re.search(r"\bv?([0-9]+\.[0-9]+\.[0-9]+)\b", out)
                if m:
                    return m.group(1)
                # 取第一行截断
                line = out.splitlines()[0].strip()
                return line[:32] if line else "未知"
            except Exception:
                continue
    except Exception:
        pass
    return "未知"


def get_xray_version(xray_path) -> str:
    if not xray_path:
        xray_path = find_xray()
    if not xray_path or not Path(xray_path).exists():
        return "未找到"
    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(
            [str(xray_path), "version"],
            capture_output=True, text=True, timeout=8,
            creationflags=flags,
            cwd=str(Path(xray_path).parent),
        )
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"Xray\s+([0-9]+(?:\.[0-9]+)*)", out, re.I)
        if m:
            return m.group(1)
        m2 = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+)\b", out)
        if m2:
            return m2.group(1)
        line = out.strip().splitlines()[0] if out.strip() else ""
        return line[:48] if line else "未知"
    except Exception:
        return "未知"


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
        self.singbox_process = None
        self.mihomo_process = None
        self.is_running = False
        self.is_testing = False
        self.nodes: list[dict] = []
        self.current_node = None
        self.subscription_url = ""
        self.subscriptions = []
        self._xray_ver = "未知"
        self.tun_enabled = False
        self.proxy_core = "Xray"
        self.core_map = dict(DEFAULT_CORE_MAP)
        self.live_stats_enabled = False  # 实时网速/内存，默认关闭
        self.font_size = 13
        self.hotkey_toggle = "ctrl+shift+m"
        self.hotkey_proxy = "ctrl+shift+p"
        self.hotkey_clear_proxy = ""
        self.hotkey_set_proxy = ""
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
        self._last_up = 0
        self._last_down = 0
        self._last_stat_ts = 0.0
        self._speed_up = 0.0
        self._speed_down = 0.0
        self.api_port = 10085
        self._custom_refresh_hours = 0
        self.icons_dir = get_icons_dir()

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.after(200, self.startup)

    def create_widgets(self):
        # 窗口图标
        try:
            ico = self.icons_dir / "mobility.ico"
            if ico.exists():
                self.iconbitmap(str(ico))
        except Exception:
            pass

        # ===== 顶栏 =====
        top = ctk.CTkFrame(self, fg_color=("gray90", "gray17"), corner_radius=0, height=52)
        top.pack(fill="x")
        top.pack_propagate(False)
        # 右侧按钮先 pack，避免长节点名把按钮挤出窗口
        self.stop_btn = ctk.CTkButton(top, text="停止", width=72, height=32,
                                      fg_color="#DC2626", hover_color="#B91C1C", command=self.stop_proxy)
        self.stop_btn.pack(side="right", padx=(4, 12), pady=10)
        self.start_btn = ctk.CTkButton(top, text="启动", width=72, height=32, command=self.start_proxy_thread)
        self.start_btn.pack(side="right", padx=4, pady=10)

        self.title_label = ctk.CTkLabel(
            top, text="Mobility", font=("Microsoft YaHei UI", 18, "bold"),
            text_color=("#2563EB", "#60A5FA"))
        self.title_label.pack(side="left", padx=(16, 10))
        self.app_ver_label = ctk.CTkLabel(
            top, text=f"v{APP_VERSION}", font=("Microsoft YaHei UI", 12),
            text_color=("gray40", "gray60"))
        self.app_ver_label.pack(side="left", padx=(4, 10))
        self.status_label = ctk.CTkLabel(top, text="未运行", font=("Microsoft YaHei UI", 13))
        self.status_label.pack(side="left", padx=8)
        self.current_label = ctk.CTkLabel(top, text="当前节点：无", font=("Microsoft YaHei UI", 12),
                                          text_color=("gray40", "gray60"))
        self.current_label.pack(side="left", padx=8)
        self.version_label = ctk.CTkLabel(
            top, text=f"v{APP_VERSION}",
            font=("Microsoft YaHei UI", 11), text_color=("gray45", "gray55")
        )
        self.version_label.pack(side="left", padx=8)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=8)

        # ===== 订阅行（多订阅）=====
        sub = ctk.CTkFrame(body, fg_color="transparent")
        sub.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(sub, text="订阅", font=("Microsoft YaHei UI", 13)).pack(side="left")
        self.sub_select = ctk.CTkComboBox(
            sub, width=140, height=32, values=["（无订阅）"], state="readonly",
            command=self.on_sub_select
        )
        self.sub_select.set("（无订阅）")
        self.sub_select.pack(side="left", padx=(6, 4))
        self.entry = ctk.CTkEntry(sub, height=32, placeholder_text="订阅 URL 或节点链接")
        self.entry.pack(side="left", fill="x", expand=True, padx=4)
        self.load_btn = ctk.CTkButton(sub, text="加载", width=56, height=32, command=self.load_nodes_thread)
        self.load_btn.pack(side="left", padx=2)
        self.add_sub_btn = ctk.CTkButton(sub, text="添加", width=56, height=32, fg_color="#0D9488", command=self.add_subscription)
        self.add_sub_btn.pack(side="left", padx=2)
        self.del_sub_btn = ctk.CTkButton(sub, text="删除", width=56, height=32, fg_color="#DC2626", command=self.remove_subscription)
        self.del_sub_btn.pack(side="left", padx=2)
        self.rename_sub_btn = ctk.CTkButton(sub, text="改名", width=56, height=32, fg_color="#0EA5E9", command=self.rename_subscription)
        self.rename_sub_btn.pack(side="left", padx=2)
        self.refresh_all_btn = ctk.CTkButton(sub, text="更新全部", width=72, height=32, fg_color="#7C3AED", command=self.refresh_all_subs_thread)
        self.refresh_all_btn.pack(side="left", padx=2)
        self.clip_btn = ctk.CTkButton(sub, text="剪贴板", width=64, height=32, command=self.import_clipboard_thread)
        self.clip_btn.pack(side="left", padx=2)
        self.qr_btn = ctk.CTkButton(sub, text="扫码", width=56, height=32, fg_color="#7C3AED",
                                    command=self.scan_screen_qr_thread)
        self.qr_btn.pack(side="left", padx=2)
        self.show_qr_btn = ctk.CTkButton(sub, text="生成码", width=56, height=32, fg_color="#DB2777",
                                         command=self.show_node_qr)
        self.show_qr_btn.pack(side="left", padx=2)

        # ===== 工具行：左侧操作按钮，右侧核心/并发/模式（填满空白） =====
        tools = ctk.CTkFrame(body, fg_color="transparent")
        tools.pack(fill="x", pady=(0, 6))
        self.test_btn = ctk.CTkButton(tools, text="测速全部", width=80, height=30, fg_color="#7C3AED", command=self.test_all_thread)
        self.test_btn.pack(side="left", padx=2)
        self.test_filter_btn = ctk.CTkButton(tools, text="测速筛选", width=80, height=30, fg_color="#8B5CF6", command=self.test_filtered_thread)
        self.test_filter_btn.pack(side="left", padx=2)
        self.best_btn = ctk.CTkButton(tools, text="选最快", width=72, height=30, fg_color="#059669", command=self.select_best)
        self.best_btn.pack(side="left", padx=2)
        self.copy_btn = ctk.CTkButton(tools, text="复制节点", width=72, height=30, command=self.copy_selected_node)
        self.copy_btn.pack(side="left", padx=2)
        self.ping_btn = ctk.CTkButton(tools, text="连通性", width=64, height=30, fg_color="#EA580C", command=self.connectivity_test_thread)
        self.ping_btn.pack(side="left", padx=2)

        # 右侧选项区（核心由设置「按协议映射」决定，此处不再放核心下拉）
        right_opts = ctk.CTkFrame(tools, fg_color="transparent")
        right_opts.pack(side="right", padx=(8, 0))
        ctk.CTkLabel(right_opts, text="并发", font=("Microsoft YaHei UI", 12)).pack(side="left", padx=(10, 2))
        self.workers_combo = ctk.CTkComboBox(right_opts, width=72, height=30, values=TEST_WORKERS_OPTIONS, state="readonly")
        self.workers_combo.set(str(TEST_WORKERS_DEFAULT))
        self.workers_combo.pack(side="left", padx=2)
        ctk.CTkLabel(right_opts, text="模式", font=("Microsoft YaHei UI", 13)).pack(side="left", padx=(8, 2))
        self.mode_combo = ctk.CTkComboBox(
            right_opts, width=150, height=32, values=PROXY_MODES, state="readonly",
            command=self.on_mode_change, font=("Microsoft YaHei UI", 13),
        )
        self.mode_combo.set(PROXY_MODE_DEFAULT)
        self.mode_combo.pack(side="left", padx=2)

        # ===== 运行状态条 =====
        stats = ctk.CTkFrame(body, fg_color=("gray90", "gray20"), corner_radius=8, height=48)
        stats.pack(fill="x", pady=(6, 6))
        stats.pack_propagate(False)
        self.stat_up_label = ctk.CTkLabel(stats, text="↑ 0 B/s", font=("Microsoft YaHei UI", 12), text_color="#EA580C")
        self.stat_up_label.pack(side="left", padx=12)
        self.stat_down_label = ctk.CTkLabel(stats, text="↓ 0 B/s", font=("Microsoft YaHei UI", 12), text_color="#2563EB")
        self.stat_down_label.pack(side="left", padx=8)
        self.stat_total_label = ctk.CTkLabel(stats, text="流量 0 B", font=("Microsoft YaHei UI", 12))
        self.stat_total_label.pack(side="left", padx=12)
        self.stat_time_label = ctk.CTkLabel(stats, text="时长 00:00:00", font=("Microsoft YaHei UI", 12))
        self.stat_time_label.pack(side="left", padx=8)
        self.stat_mem_label = ctk.CTkLabel(stats, text="内存 --", font=("Microsoft YaHei UI", 12))
        self.stat_mem_label.pack(side="left", padx=8)
        # 实时统计开关：默认关闭，用户需要时再开（尤其 TUN 下更省资源）
        self.live_stats_var = ctk.BooleanVar(value=False)
        self.live_stats_sw = ctk.CTkSwitch(
            stats, text="实时统计", variable=self.live_stats_var, width=90,
            command=self.on_live_stats_toggle
        )
        self.live_stats_sw.pack(side="right", padx=10)

        # ===== 中部：节点列表 + 右侧设置 =====
        mid = ctk.CTkFrame(body, fg_color="transparent")
        mid.pack(fill="both", expand=True, pady=4)

        left = ctk.CTkFrame(mid)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))

        search_row = ctk.CTkFrame(left, fg_color="transparent")
        search_row.pack(fill="x", padx=8, pady=6)
        self.filter_entry = ctk.CTkEntry(search_row, height=28, placeholder_text="搜索节点名称/地址/协议")
        self.filter_entry.pack(side="left", fill="x", expand=True)
        self.filter_entry.bind("<KeyRelease>", lambda e: self.apply_node_filter())
        self.filter_clear_btn = ctk.CTkButton(search_row, text="清除", width=56, height=28, command=self.clear_node_filter)
        self.filter_clear_btn.pack(side="left", padx=(6, 0))

        self.node_count_label = ctk.CTkLabel(left, text="节点：0", font=("Microsoft YaHei UI", 12),
                                             text_color=("gray40", "gray60"))
        self.node_count_label.pack(anchor="w", padx=10)

        self.node_list = ctk.CTkScrollableFrame(left, height=220)
        self.node_list.pack(fill="both", expand=True, padx=6, pady=(0, 8))
        self._node_buttons = []
        self._selected_label = None

        # 兼容旧代码：隐藏 combo
        self.node_combo = None

        right_wrap = ctk.CTkFrame(mid, width=250)
        right_wrap.pack(side="right", fill="y")
        right_wrap.pack_propagate(False)
        right = ctk.CTkScrollableFrame(right_wrap, width=230)
        right.pack(fill="both", expand=True)
        ctk.CTkLabel(right, text="设置", font=("Microsoft YaHei UI", 14, "bold")).pack(anchor="w", padx=8, pady=(6, 6))

        self.tray_check = ctk.CTkCheckBox(right, text="关闭到托盘", command=self.on_tray_option)
        self.tray_check.select()
        self.tray_check.pack(anchor="w", padx=8, pady=3)
        self.autostart_check = ctk.CTkCheckBox(right, text="开机自启", command=self.on_autostart_option)
        self.autostart_check.pack(anchor="w", padx=8, pady=3)
        self.autoconnect_check = ctk.CTkCheckBox(right, text="启动自动连接", command=self.on_autoconnect_option)
        self.autoconnect_check.pack(anchor="w", padx=8, pady=3)
        self.minimized_check = ctk.CTkCheckBox(right, text="启动后最小化", command=self.on_minimized_option)
        self.minimized_check.pack(anchor="w", padx=8, pady=3)
        self.lan_check = ctk.CTkCheckBox(right, text="允许局域网", command=self.on_lan_option)
        self.lan_check.pack(anchor="w", padx=8, pady=3)
        self.tun_check = ctk.CTkCheckBox(right, text="TUN 模式", command=self.on_tun_toggle)
        self.tun_check.pack(anchor="w", padx=8, pady=3)

        # 端口：标签固定宽 + 输入框填满，避免启动时被裁切
        pr1 = ctk.CTkFrame(right, fg_color="transparent")
        pr1.pack(fill="x", padx=8, pady=(10, 2))
        pr1.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(pr1, text="SOCKS", width=56, anchor="w",
                     font=("Microsoft YaHei UI", 12)).grid(row=0, column=0, sticky="w")
        self.socks_entry = ctk.CTkEntry(pr1, height=30, font=("Consolas", 13))
        self.socks_entry.insert(0, "10808")
        self.socks_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        pr2 = ctk.CTkFrame(right, fg_color="transparent")
        pr2.pack(fill="x", padx=8, pady=2)
        pr2.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(pr2, text="HTTP", width=56, anchor="w",
                     font=("Microsoft YaHei UI", 12)).grid(row=0, column=0, sticky="w")
        self.http_entry = ctk.CTkEntry(pr2, height=30, font=("Consolas", 13))
        self.http_entry.insert(0, "10809")
        self.http_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.apply_port_btn = ctk.CTkButton(right, text="应用端口", height=30, command=self.apply_ports)
        self.apply_port_btn.pack(fill="x", padx=8, pady=(6, 4))

        ctk.CTkLabel(right, text="主题", font=("Microsoft YaHei UI", 12)).pack(anchor="w", padx=8, pady=(8, 2))
        self.theme_combo = ctk.CTkComboBox(right, height=28, values=THEME_OPTIONS, state="readonly", command=self.on_theme_change)
        self.theme_combo.set("跟随系统")
        self.theme_combo.pack(fill="x", padx=8)

        ctk.CTkLabel(right, text="订阅更新", font=("Microsoft YaHei UI", 12)).pack(anchor="w", padx=8, pady=(8, 2))
        self.refresh_interval_combo = ctk.CTkComboBox(
            right, height=28, values=REFRESH_OPTIONS, state="readonly",
            command=self.on_refresh_change
        )
        self.refresh_interval_combo.set("不自动更新")
        self.refresh_interval_combo.pack(fill="x", padx=8)
        cr = ctk.CTkFrame(right, fg_color="transparent")
        cr.pack(fill="x", padx=8, pady=4)
        self.refresh_custom_entry = ctk.CTkEntry(cr, height=28, placeholder_text="自定义小时数")
        self.refresh_custom_entry.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(cr, text="应用", width=54, height=28, command=self.apply_custom_refresh).pack(side="left", padx=(6, 0))

        ctk.CTkLabel(right, text="DNS", font=("Microsoft YaHei UI", 12)).pack(anchor="w", padx=8, pady=(6, 2))
        self.dns_combo = ctk.CTkComboBox(right, height=28, values=DNS_OPTIONS, state="readonly", command=self.on_dns_change)
        self.dns_combo.set("系统默认")
        self.dns_combo.pack(fill="x", padx=8)
        self.dns_entry = ctk.CTkEntry(right, height=28, placeholder_text="自定义 DNS，如 8.8.8.8,1.1.1.1")
        self.dns_entry.insert(0, "8.8.8.8,1.1.1.1")
        # 默认隐藏，选择「自定义」时插到 DNS 下拉框下方

        ctk.CTkLabel(right, text="日志级别", font=("Microsoft YaHei UI", 12)).pack(anchor="w", padx=8, pady=(4, 2))
        self.loglevel_combo = ctk.CTkComboBox(right, height=28, values=LOG_LEVELS, state="readonly", command=self.on_loglevel_change)
        self.loglevel_combo.set("警告")
        self.loglevel_combo.pack(fill="x", padx=8)

        # 核心类型改为二级对话框
        self.core_proto_combos = {}

        # 域名分流（精简）
        ctk.CTkLabel(right, text="直连域名", font=("Microsoft YaHei UI", 11)).pack(anchor="w", padx=8, pady=(8, 0))
        self.direct_entry = ctk.CTkEntry(right, height=28, placeholder_text="baidu.com,*.qq.com")
        self.direct_entry.pack(fill="x", padx=8, pady=2)
        ctk.CTkLabel(right, text="代理域名", font=("Microsoft YaHei UI", 11)).pack(anchor="w", padx=8)
        self.proxy_entry = ctk.CTkEntry(right, height=28, placeholder_text="google.com")
        self.proxy_entry.pack(fill="x", padx=8, pady=2)
        self.domain_apply_btn = ctk.CTkButton(right, text="应用域名规则", height=30, command=self.apply_custom_domains)
        self.domain_apply_btn.pack(fill="x", padx=8, pady=6)

        ctk.CTkLabel(right, text="字体大小", font=("Microsoft YaHei UI", 12)).pack(anchor="w", padx=8, pady=(8, 2))
        self.font_combo = ctk.CTkComboBox(right, height=28, values=FONT_SIZE_OPTIONS,
                                          state="readonly", command=self.on_font_size_change)
        self.font_combo.set(str(getattr(self, "font_size", 13)))
        self.font_combo.pack(fill="x", padx=8)

        # 右侧按钮区
        bh = 30
        btn_box = ctk.CTkFrame(right, fg_color="transparent")
        btn_box.pack(fill="x", padx=10, pady=(6, 8))
        btn_box.grid_columnconfigure(0, weight=1, uniform="btn")
        btn_box.grid_columnconfigure(1, weight=1, uniform="btn")

        self.core_type_btn = ctk.CTkButton(btn_box, text="核心设置", height=bh, command=self.open_core_type_dialog)
        self.core_type_btn.grid(row=0, column=0, sticky="ew", pady=3, padx=(0, 3))
        self.hotkey_setting_btn = ctk.CTkButton(btn_box, text="热键设置", height=bh, command=self.open_hotkey_dialog)
        self.hotkey_setting_btn.grid(row=0, column=1, sticky="ew", pady=3, padx=(3, 0))

        self.clear_log_btn = ctk.CTkButton(btn_box, text="清空日志", height=bh, command=self.clear_log)
        self.clear_log_btn.grid(row=1, column=0, sticky="ew", pady=3, padx=(0, 3))
        self.update_btn = ctk.CTkButton(btn_box, text="检查更新", height=bh, command=self.check_update_thread)
        self.update_btn.grid(row=1, column=1, sticky="ew", pady=3, padx=(3, 0))

        self.core_update_btn = ctk.CTkButton(btn_box, text="更新核心", height=bh, command=self.update_core_thread)
        self.core_update_btn.grid(row=2, column=0, sticky="ew", pady=3, padx=(0, 3))
        self.geo_update_btn = ctk.CTkButton(btn_box, text="更新规则", height=bh, command=self.update_geo_thread)
        self.geo_update_btn.grid(row=2, column=1, sticky="ew", pady=3, padx=(3, 0))

        self.admin_btn = ctk.CTkButton(btn_box, text="管理员运行", height=bh, command=self.restart_as_admin)
        self.admin_btn.grid(row=3, column=0, sticky="ew", pady=3, padx=(0, 3))
        self.about_btn = ctk.CTkButton(btn_box, text="关于", height=bh, command=self.show_about)
        self.about_btn.grid(row=3, column=1, sticky="ew", pady=3, padx=(3, 0))

        self.open_release_btn = ctk.CTkButton(btn_box, text="打开发布页", height=bh, command=self.open_releases_page)
        self.open_release_btn.grid(row=4, column=0, columnspan=2, sticky="ew", pady=3)

        # ===== 底部日志（首页） =====
        log_frame = ctk.CTkFrame(body, fg_color="transparent")
        log_frame.pack(fill="both", expand=False, pady=(4, 0))
        log_head = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_head.pack(fill="x")
        ctk.CTkLabel(log_head, text="运行日志", font=("Microsoft YaHei UI", 12, "bold")).pack(side="left")
        # 先 pack 右侧开关，保证与上方「实时统计」右边缘对齐
        self.log_autoscroll_var = ctk.BooleanVar(value=True)
        self.log_autoscroll_sw = ctk.CTkSwitch(
            log_head, text="自动滚动", variable=self.log_autoscroll_var, width=90,
            command=self._on_log_autoscroll
        )
        self.log_autoscroll_sw.pack(side="right", padx=10)
        log_tools = ctk.CTkFrame(log_head, fg_color="transparent")
        log_tools.pack(side="right", padx=(0, 4))
        self.log_filter_entry = ctk.CTkEntry(log_tools, width=160, height=26, placeholder_text="过滤器(支持正则)")
        self.log_filter_entry.pack(side="left", padx=(0, 4))
        self.log_filter_entry.bind("<KeyRelease>", lambda e: self.apply_log_filter())
        ctk.CTkButton(log_tools, text="复制", width=48, height=26, command=self.copy_log).pack(side="left", padx=2)
        ctk.CTkButton(log_tools, text="清空", width=48, height=26, fg_color="#DC2626", command=self.clear_log).pack(side="left", padx=2)
        self.log_box = ctk.CTkTextbox(log_frame, height=200, font=("Consolas", 11))
        self.log_box.pack(fill="x", pady=4)
        self._log_lines = []
        self._log_autoscroll = True
        self.log("Mobility 已启动")
        try:
            # 强制刷新右侧栏，减轻首次绘制发虚
            self.update_idletasks()
            if hasattr(self, "socks_entry"):
                self.socks_entry.update()
                self.http_entry.update()
        except Exception:
            pass

    def clear_node_list_ui(self):
        for w in getattr(self, "_node_buttons", []) or []:
            try:
                w.destroy()
            except Exception:
                pass
        self._node_buttons = []
        # 清空 scrollable 内残留
        try:
            for child in self.node_list.winfo_children():
                child.destroy()
        except Exception:
            pass

    def on_node_button_click(self, node, btn):
        self.current_node = node
        self._selected_label = node.get("_label")
        # 高亮
        for b in self._node_buttons:
            try:
                b.configure(fg_color=("gray85", "gray25"), text_color=("gray10", "gray90"))
            except Exception:
                pass
        try:
            btn.configure(fg_color=("#EA580C", "#C2410C"), text_color="white")
        except Exception:
            pass
        try:
            self.current_label.configure(text=f"当前节点：{node.get('name')}")
        except Exception:
            pass

    def is_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def refresh_version_label(self, core_name: str = None):
        """顶部显示：软件版本 + 当前核心名称与版本。"""
        try:
            if not core_name:
                node = None
                try:
                    node = self.get_selected_node()
                except Exception:
                    node = getattr(self, "current_node", None)
                if node:
                    core_name = self.resolve_core_for_node(node)
                else:
                    core_name = getattr(self, "proxy_core", None) or "Xray"
            core_name = str(core_name).strip() or "Xray"
            low = core_name.lower()
            if low.startswith("sing"):
                path = self.core_dir / "sing-box.exe"
                for c in [path, get_base_dir() / "core" / "sing-box.exe", get_base_dir() / "sing-box.exe"]:
                    if c.exists():
                        path = c
                        break
                ver = get_core_binary_version(path, "sing-box")
                label = f"sing-box {ver}"
            elif low.startswith("mihomo") or low == "clash":
                path = self.core_dir / "mihomo.exe"
                for c in [path, get_base_dir() / "core" / "mihomo.exe", get_base_dir() / "mihomo.exe"]:
                    if c.exists():
                        path = c
                        break
                ver = get_core_binary_version(path, "mihomo")
                label = f"Mihomo {ver}"
            else:
                path = getattr(self, "xray_path", None) or find_xray()
                ver = get_xray_version(path)
                self._xray_ver = ver
                label = f"Xray {ver}"
            if hasattr(self, "version_label"):
                self.version_label.configure(text=label)
        except Exception:
            try:
                if hasattr(self, "version_label"):
                    self.version_label.configure(text="")
            except Exception:
                pass

    def open_core_type_dialog(self):
        """二级窗口：按协议映射核心（类似 v2rayN）。"""
        win = ctk.CTkToplevel(self)
        win.title("核心类型设置")
        win.geometry("420x420")
        win.transient(self)
        try:
            win.grab_set()
        except Exception:
            pass

        ctk.CTkLabel(win, text="核心设置", font=("Microsoft YaHei UI", 16, "bold")).pack(
            anchor="w", padx=20, pady=(16, 8)
        )
        ctk.CTkLabel(
            win,
            text="为每种协议指定默认核心，启动时按节点协议自动选用。",
            font=("Microsoft YaHei UI", 11),
            text_color=("gray40", "gray60"),
        ).pack(anchor="w", padx=20, pady=(0, 10))

        form = ctk.CTkFrame(win, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=20)

        proto_labels = {
            "vmess": "VMess",
            "vless": "VLESS",
            "trojan": "Trojan",
            "shadowsocks": "Shadowsocks",
            "socks": "Socks",
            "http": "HTTP",
        }
        combos = {}
        if not getattr(self, "core_map", None):
            self.core_map = dict(DEFAULT_CORE_MAP)

        for proto in CORE_PROTOCOLS:
            row = ctk.CTkFrame(form, fg_color="transparent")
            row.pack(fill="x", pady=5)
            ctk.CTkLabel(
                row, text=proto_labels.get(proto, proto), width=110, anchor="w",
                font=("Microsoft YaHei UI", 12),
            ).pack(side="left")
            cb = ctk.CTkComboBox(
                row, width=160, height=30, values=CORE_OPTIONS, state="readonly",
                font=("Microsoft YaHei UI", 12),
            )
            cb.set(self.core_map.get(proto, "Xray"))
            cb.pack(side="right")
            combos[proto] = cb

        self.core_proto_combos = combos

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(side="bottom", fill="x", padx=20, pady=16)

        def do_reset():
            for proto, cb in combos.items():
                cb.set("Xray")

        def do_ok():
            if not getattr(self, "core_map", None):
                self.core_map = dict(DEFAULT_CORE_MAP)
            for proto, cb in combos.items():
                val = (cb.get() or "Xray").strip()
                self.core_map[proto] = val if val in CORE_OPTIONS else "Xray"
            self.save_settings()
            try:
                self.refresh_version_label()
            except Exception:
                pass
            self.log("核心类型映射已保存")
            try:
                win.grab_release()
            except Exception:
                pass
            win.destroy()

        def do_cancel():
            try:
                win.grab_release()
            except Exception:
                pass
            win.destroy()

        ctk.CTkButton(btn_row, text="重置", width=90, command=do_reset).pack(side="left")
        ctk.CTkButton(btn_row, text="取消", width=90, command=do_cancel).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btn_row, text="确定", width=90, fg_color="#2563EB", command=do_ok).pack(side="right")

    def on_core_map_change(self, proto: str, value=None):
        if not getattr(self, "core_map", None):
            self.core_map = dict(DEFAULT_CORE_MAP)
        self.core_map[proto] = (value or "Xray").strip()
        self.save_settings()
        self.log(f"协议 {proto} → 核心 {self.core_map[proto]}")
        try:
            self.refresh_version_label()
        except Exception:
            pass

    def resolve_core_for_node(self, node: dict) -> str:
        proto = (node.get("protocol") or "").lower()
        if proto == "ss":
            proto = "shadowsocks"
        cmap = getattr(self, "core_map", None) or DEFAULT_CORE_MAP
        core = cmap.get(proto) or getattr(self, "proxy_core", None) or "Xray"
        return str(core).strip() or "Xray"

    def on_core_change(self, value=None):
        try:
            self.proxy_core = (value or self.core_combo.get() or "Xray").strip()
        except Exception:
            self.proxy_core = "Xray"
        self.log(f"当前代理核心：{self.proxy_core}")
        if self.proxy_core == "sing-box":
            self.log("已切换：协议出站 + TUN 均由 sing-box 负责")
        else:
            self.log("已切换：协议出站由 Xray 负责；TUN 时由 sing-box 协助接管")
        self.save_settings()
        # 切换核心后若在运行则提示重启
        if self.is_running:
            self.log("核心已切换，请停止后重新启动以生效")

    def on_tun_toggle(self):
        enabled = bool(self.tun_check.get()) if hasattr(self, "tun_check") else False
        if enabled and not self.is_admin():
            self.log("启用 TUN 需要管理员权限，请点击「管理员运行」后重试")
            try:
                self.tun_check.deselect()
            except Exception:
                pass
            self.tun_enabled = False
            return
        if enabled:
            ok = ensure_wintun(self.core_dir, log_fn=self.log)
            if not ok:
                self.log("无法准备 wintun.dll，已取消 TUN")
                try:
                    self.tun_check.deselect()
                except Exception:
                    pass
                self.tun_enabled = False
                self.save_settings()
                return
            # 需要已选节点
            node = None
            try:
                node = self.get_selected_node()
            except Exception:
                node = self.current_node
            if not node and self.nodes:
                # 自动选延迟最低或第一个
                try:
                    tested = [n for n in self.nodes if isinstance(n.get("latency"), int) and n["latency"] >= 0]
                    node = min(tested, key=lambda x: x["latency"]) if tested else self.nodes[0]
                    self.current_node = node
                except Exception:
                    node = self.nodes[0]
                    self.current_node = node
            if not node:
                self.log("请先加载并选择节点，再开启 TUN")
                try:
                    self.tun_check.deselect()
                except Exception:
                    pass
                self.tun_enabled = False
                self.save_settings()
                return
            self.tun_enabled = True
            self.save_settings()
            self.log("TUN 模式：开启，正在自动连接...")
            # 若已在运行，先停再以 TUN 配置重启
            if self.is_running:
                try:
                    self.stop_proxy()
                except Exception:
                    pass
                self.after(400, self.start_proxy_thread)
            else:
                self.start_proxy_thread()
            return

        # 关闭 TUN
        self.tun_enabled = False
        self.save_settings()
        self.log("TUN 模式：关闭")
        try:
            self.start_hotkey_listener()
        except Exception:
            pass
        if self.is_running:
            self.log("已关闭 TUN，停止当前连接")
            try:
                self.stop_proxy()
            except Exception:
                pass
        try:
            self.start_btn.configure(state="normal")
        except Exception:
            pass

    def on_font_size_change(self, value=None):
        try:
            self.font_size = int(value or self.font_combo.get())
        except Exception:
            self.font_size = 13
        self.save_settings()
        self.log(f"字体大小：{self.font_size}（日志区已应用，其余部分重启后生效）")
        try:
            self.log_box.configure(font=("Consolas", max(10, self.font_size - 1)))
        except Exception:
            pass

    def open_hotkey_dialog(self):
        """二级对话框设置全局热键。"""
        win = ctk.CTkToplevel(self)
        win.title("全局热键设置")
        win.geometry("440x340")
        win.transient(self)
        try:
            win.grab_set()
        except Exception:
            pass

        ctk.CTkLabel(win, text="全局热键设置", font=("Microsoft YaHei UI", 16, "bold")).pack(
            anchor="w", padx=20, pady=(16, 12)
        )
        form = ctk.CTkFrame(win, fg_color="transparent")
        form.pack(fill="x", padx=20)

        def row(label, default):
            fr = ctk.CTkFrame(form, fg_color="transparent")
            fr.pack(fill="x", pady=6)
            ctk.CTkLabel(fr, text=label, width=120, anchor="w", font=("Microsoft YaHei UI", 12)).pack(side="left")
            ent = ctk.CTkEntry(fr, height=32)
            ent.insert(0, default or "")
            ent.pack(side="left", fill="x", expand=True, padx=(8, 0))
            return ent

        e_toggle = row("显示主界面", getattr(self, "hotkey_toggle", "ctrl+shift+m"))
        e_proxy = row("启停代理", getattr(self, "hotkey_proxy", "ctrl+shift+p"))
        e_clear = row("清除系统代理", getattr(self, "hotkey_clear_proxy", ""))
        e_set = row("配置系统代理", getattr(self, "hotkey_set_proxy", ""))

        ctk.CTkLabel(
            win,
            text="格式示例：ctrl+shift+m、alt+n\n留空表示不注册；确定后立即生效",
            font=("Microsoft YaHei UI", 11),
            text_color=("gray40", "gray60"),
            justify="left",
        ).pack(anchor="w", padx=20, pady=(10, 4))

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(side="bottom", fill="x", padx=20, pady=16)

        def do_reset():
            for e, v in ((e_toggle, "ctrl+shift+m"), (e_proxy, "ctrl+shift+p"), (e_clear, ""), (e_set, "")):
                e.delete(0, "end")
                e.insert(0, v)

        def do_ok():
            self.hotkey_toggle = (e_toggle.get() or "").strip().lower()
            self.hotkey_proxy = (e_proxy.get() or "").strip().lower()
            self.hotkey_clear_proxy = (e_clear.get() or "").strip().lower()
            self.hotkey_set_proxy = (e_set.get() or "").strip().lower()
            self.save_settings()
            self.start_hotkey_listener()
            self.log(
                f"热键已应用：显示={self.hotkey_toggle or '无'}，启停={self.hotkey_proxy or '无'}，"
                f"清代理={self.hotkey_clear_proxy or '无'}，设代理={self.hotkey_set_proxy or '无'}"
            )
            try:
                win.grab_release()
            except Exception:
                pass
            win.destroy()

        def do_cancel():
            try:
                win.grab_release()
            except Exception:
                pass
            win.destroy()

        ctk.CTkButton(btn_row, text="重置", width=90, command=do_reset).pack(side="left")
        ctk.CTkButton(btn_row, text="取消", width=90, command=do_cancel).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btn_row, text="确定", width=90, fg_color="#2563EB", command=do_ok).pack(side="right")

    def apply_hotkeys(self):
        self.save_settings()
        self.start_hotkey_listener()
        self.log(f"热键已应用：显示/隐藏={self.hotkey_toggle}，启停={self.hotkey_proxy}")

    def start_hotkey_listener(self):
        try:
            import keyboard
        except Exception:
            self.log("提示：热键需要 keyboard 库（构建时已尝试打包）")
            return
        try:
            keyboard.unhook_all_hotkeys()
        except Exception:
            pass
        try:
            if self.hotkey_toggle:
                keyboard.add_hotkey(self.hotkey_toggle, lambda: self.after(0, self.toggle_window_visibility))
            if self.hotkey_proxy:
                keyboard.add_hotkey(self.hotkey_proxy, lambda: self.after(0, self.toggle_proxy_hotkey))
            if getattr(self, "hotkey_clear_proxy", ""):
                keyboard.add_hotkey(self.hotkey_clear_proxy, lambda: self.after(0, self._hotkey_clear_proxy))
            if getattr(self, "hotkey_set_proxy", ""):
                keyboard.add_hotkey(self.hotkey_set_proxy, lambda: self.after(0, self._hotkey_set_proxy))
        except Exception as e:
            self.log(f"注册热键失败：{e}")

    def _hotkey_clear_proxy(self):
        try:
            self.set_system_proxy(False)
            self.log("热键：已清除系统代理")
        except Exception as e:
            self.log(f"热键清除代理失败：{e}")

    def _hotkey_set_proxy(self):
        try:
            _, http_port = self.get_ports()
            if self.set_system_proxy(True, http_port):
                self.log(f"热键：已配置系统代理 127.0.0.1:{http_port}")
            else:
                self.log("热键：配置系统代理失败")
        except Exception as e:
            self.log(f"热键配置代理失败：{e}")

    def toggle_window_visibility(self):
        try:
            if self.state() == "withdrawn":
                self.deiconify()
                self.lift()
            else:
                self.withdraw()
        except Exception:
            pass

    def toggle_proxy_hotkey(self):
        if self.is_running:
            self.stop_proxy()
        else:
            self.start_proxy_thread()

    def update_geo_thread(self):
        Thread(target=self.update_geo_only, daemon=True).start()

    def update_geo_only(self):
        self.log("开始更新 Geo 规则文件...")
        try:
            core_dir = get_base_dir() / "core"
            core_dir.mkdir(parents=True, exist_ok=True)
            for geo_name, geo_url in [
                ("geoip.dat", "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"),
                ("geosite.dat", "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"),
            ]:
                self.log(f"下载 {geo_name} ...")
                gr = requests.get(geo_url, timeout=90, headers={"User-Agent": "Mobility"})
                gr.raise_for_status()
                (core_dir / geo_name).write_bytes(gr.content)
                self.log(f"{geo_name} 已更新（{len(gr.content)} 字节）")
            self.log("规则文件更新完成")
        except Exception as e:
            self.log(f"更新规则失败：{e}")

    def open_releases_page(self):
        import webbrowser
        url = f"https://github.com/{GITHUB_REPO}/releases"
        try:
            webbrowser.open(url)
            self.log(f"已打开：{url}")
        except Exception as e:
            self.log(f"打开浏览器失败：{e}")

    def restart_as_admin(self):
        if self.is_admin():
            self.log("当前已是管理员权限")
            return
        try:
            if getattr(sys, "frozen", False):
                exe = sys.executable
                params = ""
            else:
                exe = sys.executable
                params = f'"{Path(__file__).resolve()}"'
            ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            self.log("已请求管理员权限，请在 UAC 确认")
            self.close_to_tray = False
            self.on_closing()
        except Exception as e:
            self.log(f"请求管理员失败：{e}")

    def show_about(self):
        try:
            from tkinter import messagebox
            messagebox.showinfo(
                "关于 Mobility",
                f"Mobility 代理客户端\n"
                f"软件版本：v{APP_VERSION}\n"
                f"Xray 核心：{getattr(self, '_xray_ver', '未知')}\n\n"
                f"仓库：{GITHUB_REPO}\n"
                f"功能：多订阅 / 测速 / 分流 / 系统代理\n"
                f"手动更新：GitHub Releases\n"
                f"核心更新：设置 → 更新核心"
            )
        except Exception as e:
            self.log(f"打开关于失败：{e}")

    def update_core_thread(self):
        Thread(target=self.update_core, daemon=True).start()

    def update_core(self):
        self.log("开始检查并更新 Xray-core ...")
        try:
            import tempfile
            import zipfile
            url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
            tmp = Path(tempfile.gettempdir()) / "xray_update.zip"
            self.log(f"下载：{url}")
            r = requests.get(url, timeout=120, headers={"User-Agent": "Mobility"})
            r.raise_for_status()
            tmp.write_bytes(r.content)
            core_dir = get_base_dir() / "core"
            core_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(tmp, "r") as zf:
                for name in zf.namelist():
                    if name.lower().endswith("xray.exe"):
                        (core_dir / "xray.exe").write_bytes(zf.read(name))
                        self.log("xray.exe 已更新")
                        break
            for geo_name, geo_url in [
                ("geoip.dat", "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"),
                ("geosite.dat", "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"),
            ]:
                try:
                    self.log(f"更新 {geo_name} ...")
                    gr = requests.get(geo_url, timeout=60, headers={"User-Agent": "Mobility"})
                    if gr.status_code == 200:
                        (core_dir / geo_name).write_bytes(gr.content)
                        self.log(f"{geo_name} 已更新")
                except Exception as ge:
                    self.log(f"{geo_name} 更新失败：{ge}")
            # 同步更新 sing-box / mihomo
            try:
                self.log("更新 sing-box ...")
                dest = self.core_dir / "sing-box.exe"
                if dest.exists():
                    try:
                        dest.unlink()
                    except Exception:
                        pass
                ensure_singbox(self.core_dir, log_fn=self.log)
            except Exception as se:
                self.log(f"sing-box 更新失败：{se}")
            try:
                self.log("更新 Mihomo ...")
                dest = self.core_dir / "mihomo.exe"
                if dest.exists():
                    try:
                        dest.unlink()
                    except Exception:
                        pass
                ensure_mihomo(self.core_dir, log_fn=self.log)
            except Exception as me:
                self.log(f"Mihomo 更新失败：{me}")
            self.log("核心/规则文件更新完成（建议重启软件）")
            try:
                self.xray_path = find_xray()
            except Exception:
                pass
        except Exception as e:
            self.log(f"更新核心失败：{e}")


    def log(self, msg: str):
        try:
            # 限制日志行数，避免 Text 过长卡顿
            if not hasattr(self, "_log_lines"):
                self._log_lines = []
            self._log_lines.append(str(msg))
            if not hasattr(self, "_log_lines"):
                self._log_lines = []
            self._log_lines.append(str(msg))
            if len(self._log_lines) > 1000:
                self._log_lines = self._log_lines[-800:]
            self.log_box.insert("end", str(msg) + "\n")
            # 自动滚动开启时，每次都滚到末尾
            if getattr(self, "_log_autoscroll", True):
                self.log_box.see("end")
            try:
                end_idx = self.log_box.index("end-1c")
                if float(str(end_idx).split(".")[0]) > 800:
                    self.log_box.delete("1.0", "200.0")
                    # 同步裁剪缓存
                    if hasattr(self, "_log_lines") and len(self._log_lines) > 800:
                        self._log_lines = self._log_lines[-600:]
            except Exception:
                pass
        except Exception:
            pass



    def apply_log_filter(self):
        try:
            filt = (self.log_filter_entry.get() or "").strip().lower()
            if not getattr(self, "_log_lines", None):
                self._log_lines = self.log_box.get("1.0", "end-1c").splitlines()
            self.log_box.delete("1.0", "end")
            for line in self._log_lines:
                if not filt or filt in line.lower():
                    self.log_box.insert("end", line + "\n")
            if getattr(self, "_log_autoscroll", True):
                self.log_box.see("end")
        except Exception:
            pass

    def copy_log(self):
        try:
            text = self.log_box.get("1.0", "end-1c")
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception:
            pass

    def _on_log_autoscroll(self):
        try:
            self._log_autoscroll = bool(self.log_autoscroll_var.get())
        except Exception:
            self._log_autoscroll = True

    def clear_log(self):
        self.log_box.delete("1.0", "end")
        self.log("日志已清空")

    def check_update_thread(self):
        Thread(target=self.check_update, daemon=True).start()

    def check_update(self):
        self.log("正在检查更新...")
        self.log(f"当前软件版本：v{APP_VERSION}")
        try:
            api = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
            r = requests.get(api, timeout=15, headers={"User-Agent": "Mobility-Client"})
            if r.status_code == 404:
                self.log("未找到 Release，请确认仓库已发布版本")
                return
            r.raise_for_status()
            data = r.json()
            tag = data.get("tag_name") or data.get("name") or ""
            url = data.get("html_url") or ""
            self.log(f"仓库最新版本：{tag}")
            if version_newer(tag, APP_VERSION):
                self.log("发现新版本，请到 GitHub Releases 下载更新")
                if url:
                    self.log(f"发布页面：{url}")
                    try:
                        import webbrowser
                        webbrowser.open(url)
                    except Exception:
                        pass
                for a in data.get("assets") or []:
                    if a.get("name"):
                        self.log(f"  资源：{a['name']}")
            else:
                if version_newer(APP_VERSION, tag):
                    self.log(f"本地版本 v{APP_VERSION} 新于仓库 v{str(tag).lstrip('v')}")
                else:
                    self.log("当前已是最新版本")
        except Exception as e:
            self.log(f"检查更新失败：{e}")

    def startup(self):
        self.prepare_core()
        try:
            self._xray_ver = get_xray_version(getattr(self, "xray_path", None) or find_xray())
        except Exception:
            self._xray_ver = "未知"
        self.load_settings()
        try:
            self.refresh_version_label()
        except Exception:
            try:
                self.version_label.configure(text=f"v{APP_VERSION} | Xray {self._xray_ver}")
            except Exception:
                pass
        try:
            self.start_hotkey_listener()
        except Exception:
            pass
        if TRAY_AVAILABLE:
            self.setup_tray()
            pass  # tray ready
        else:
            self.log("系统托盘不可用（缺少 pystray）")
        # 首页状态刷新
        self.after(1500, self.update_home_stats)
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
            self.xray_path = xray_exe
            self.log("已检测到核心文件")
            # 确保 wintun 与 xray 同目录
            try:
                ensure_wintun(self.core_dir, log_fn=None)
            except Exception:
                pass
            return
        try:
            bundled = get_resource_path("core/xray.exe")
            if bundled.exists():
                shutil.copy2(bundled, xray_exe)
                self.xray_path = xray_exe
                self.log("已提取内置核心")
                return
        except Exception as e:
            self.log(f"提取内置核心失败: {e}")
        local_core = self.base_dir / "core" / "xray.exe"
        if local_core.exists() and local_core != xray_exe:
            shutil.copy2(local_core, xray_exe)
            self.log("已使用目录内核心")
            return
        self.log("未找到核心文件，请确保 core 目录完整")

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
        """连通性：不强制要求已启动代理。
        - 先测当前节点 TCP 端口是否通
        - 若已启动代理，再经代理测 Google/YouTube
        - 若未启动，仅做节点 TCP + 本机直连参考
        """
        self.log("---------- 连通性测试 ----------")
        node = None
        try:
            node = self.get_selected_node()
        except Exception:
            node = self.current_node
        # 1) 节点 TCP
        if node and node.get("address") and node.get("port"):
            host = str(node.get("address"))
            port = int(node.get("port") or 0)
            try:
                import socket
                t0 = time.perf_counter()
                s = socket.create_connection((host, port), timeout=5)
                s.close()
                ms = int((time.perf_counter() - t0) * 1000)
                self.log(f"  节点 TCP {host}:{port}: 通 ({ms}ms)")
            except Exception as e:
                self.log(f"  节点 TCP {host}:{port}: 不通 ({e})")
        else:
            self.log("  未选择节点，跳过节点 TCP 测试")

        # 2) HTTP 目标
        targets = [
            ("https://www.google.com/generate_204", "Google"),
            ("https://www.youtube.com", "YouTube"),
            ("https://www.cloudflare.com", "Cloudflare"),
        ]
        proxies = None
        if self.is_running:
            _, http_port = self.get_ports()
            proxies = {
                "http": f"http://127.0.0.1:{http_port}",
                "https": f"http://127.0.0.1:{http_port}",
            }
            self.log("  （经当前代理测试网页）")
        else:
            self.log("  （未启动代理，以下为直连参考，失败属正常）")

        ok_count = 0
        for url, name in targets:
            try:
                t0 = time.perf_counter()
                r = requests.get(url, proxies=proxies, timeout=8, allow_redirects=True)
                ms = int((time.perf_counter() - t0) * 1000)
                if r.status_code in (200, 204, 301, 302):
                    self.log(f"  {name}: 成功 {ms}ms (HTTP {r.status_code})")
                    ok_count += 1
                else:
                    self.log(f"  {name}: 异常 HTTP {r.status_code} ({ms}ms)")
            except Exception as e:
                self.log(f"  {name}: 失败 ({e})")
        self.log(f"连通性结果：{ok_count}/{len(targets)} 成功")
        if self.is_running and ok_count == 0:
            self.log("提示：代理可能未真正可用，请更换节点后重试")

    def on_refresh_change(self, value=None):
        self.refresh_label = self.refresh_interval_combo.get() or "不自动更新"
        self.save_settings()
        self.schedule_subscription_refresh()
        self.log(f"订阅定时更新：{self.refresh_label}")

    def apply_custom_refresh(self):
        try:
            raw = ""
            if hasattr(self, "refresh_custom_entry"):
                raw = self.refresh_custom_entry.get().strip()
            elif hasattr(self, "custom_refresh_entry"):
                raw = self.custom_refresh_entry.get().strip()
            hours = float(raw)
            if hours <= 0:
                self.log("请输入大于 0 的小时数")
                return
            self.refresh_label = "自定义"
            self.settings_refresh_hours = hours
            try:
                self.refresh_interval_combo.set("自定义")
            except Exception:
                pass
            self.save_settings()
            self.schedule_subscription_refresh()
            self.log(f"自定义更新间隔：{hours} 小时")
        except Exception:
            self.log("输入无效，请输入数字（如 0.5、2、36）")


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
            label = self.refresh_interval_combo.get()
        except Exception:
            pass
        hours = REFRESH_HOURS.get(label, 0)
        if label == "自定义" or hours == -1:
            hours = float(getattr(self, "settings_refresh_hours", 0) or getattr(self, "_custom_refresh_hours", 0) or 0)
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
        self.refresh_node_list(keep_selection=False)
        self.save_settings()
        self.log(f"剪贴板导入成功：{len(nodes)} 个节点")

    def scan_screen_qr_thread(self):
        Thread(target=self.scan_screen_qr, daemon=True).start()

    def scan_screen_qr(self):
        """截取屏幕并识别二维码，导入节点或订阅链接。"""
        status = {"win": None, "label": None}

        def _open_ui():
            try:
                win = ctk.CTkToplevel(self)
                win.title("屏幕扫码")
                win.geometry("360x160")
                win.attributes("-topmost", True)
                ctk.CTkLabel(win, text="屏幕扫码", font=("Microsoft YaHei UI", 14, "bold")).pack(pady=(12, 6))
                lab = ctk.CTkLabel(win, text="请将二维码完整显示在屏幕上…\n正在截屏识别", font=("Microsoft YaHei UI", 12))
                lab.pack(pady=8)
                status["win"] = win
                status["label"] = lab
            except Exception:
                pass
        self.after(0, _open_ui)
        time.sleep(0.25)

        def _set(msg):
            self.log(msg)
            def _u():
                try:
                    if status.get("label"):
                        status["label"].configure(text=msg)
                except Exception:
                    pass
            self.after(0, _u)

        _set("正在截取屏幕…")
        try:
            from PIL import ImageGrab
        except Exception:
            _set("缺少 Pillow，无法截屏")
            return
        img = None
        try:
            img = ImageGrab.grab()
            _set("截屏完成，正在识别二维码…")
        except Exception as e:
            _set(f"截屏失败：{e}")
            return

        texts = []
        # 优先 pyzbar
        try:
            from pyzbar.pyzbar import decode as zbar_decode
            res = zbar_decode(img)
            for r in res:
                try:
                    texts.append(r.data.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
        except Exception:
            pass

        # 备选 opencv
        if not texts:
            try:
                import numpy as np
                import cv2
                arr = np.array(img.convert("RGB"))
                arr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
                det = cv2.QRCodeDetector()
                # multi
                ok, decoded, _, _ = det.detectAndDecodeMulti(arr)
                if ok and decoded:
                    for s in decoded:
                        if s:
                            texts.append(s)
                if not texts:
                    data, _, _ = det.detectAndDecode(arr)
                    if data:
                        texts.append(data)
            except Exception:
                pass

        if not texts:
            self.log("未识别到二维码。请把二维码完整显示在屏幕上后重试")
            return

        self.log(f"识别到 {len(texts)} 个二维码")
        all_nodes = []
        for i, text in enumerate(texts):
            text = (text or "").strip()
            if not text:
                continue
            self.log(f"二维码{i+1}：{text[:80]}{'...' if len(text) > 80 else ''}")
            if text.startswith(("http://", "https://")):
                try:
                    self.after(0, lambda u=text: (self.entry.delete(0, "end"), self.entry.insert(0, u)))
                    self.subscription_url = text
                    if not any(s.get("url") == text for s in self.subscriptions):
                        try:
                            from urllib.parse import urlparse
                            nm = (urlparse(text).netloc or "")[:20] or f"扫码订阅{len(self.subscriptions)+1}"
                        except Exception:
                            nm = f"扫码订阅{len(self.subscriptions)+1}"
                        self.subscriptions.append({"name": nm, "url": text})
                    resp = requests.get(text, timeout=20, headers={"User-Agent": "Mozilla/5.0 Mobility"})
                    resp.raise_for_status()
                    nodes = parse_subscription_content(resp.text)
                    all_nodes.extend(nodes)
                    self.log(f"  订阅解析：{len(nodes)} 个节点")
                except Exception as e:
                    self.log(f"  订阅拉取失败：{e}")
                continue
            nodes = parse_subscription_content(text)
            if not nodes and "://" in text:
                node = parse_link(text)
                if node:
                    nodes = [node]
            if nodes:
                all_nodes.extend(nodes)
                self.log(f"  解析节点：{len(nodes)}")
            else:
                self.log("  无法识别为节点或订阅")

        if not all_nodes:
            _set("二维码中未得到有效节点")
            def _close_empty():
                try:
                    if status.get("win"):
                        status["win"].destroy()
                except Exception:
                    pass
            self.after(1500, _close_empty)
            return

        # 合并去重
        seen = set()
        merged = []
        for n in (self.nodes or []) + all_nodes:
            key = f"{n.get('protocol')}|{n.get('address')}|{n.get('port')}"
            if key in seen:
                continue
            seen.add(key)
            merged.append(n)
        self.nodes = merged

        def _ui():
            self.refresh_node_list(keep_selection=False)
            try:
                self.refresh_sub_select()
            except Exception:
                pass
            self.save_settings()
            self.log(f"扫码导入完成，当前共 {len(self.nodes)} 个节点")
            try:
                if status.get("label"):
                    status["label"].configure(text=f"完成：导入后共 {len(self.nodes)} 个节点")
            except Exception:
                pass
            def _close_ok():
                try:
                    if status.get("win"):
                        status["win"].destroy()
                except Exception:
                    pass
            self.after(1200, _close_ok)
        self.after(0, _ui)

    def show_node_qr(self):
        """为当前节点或订阅链接生成二维码，方便手机扫描。"""
        content = ""
        title = "二维码"
        node = None
        try:
            node = self.get_selected_node()
        except Exception:
            node = self.current_node
        if node and node.get("raw"):
            content = node.get("raw") or ""
            title = f"节点：{node.get('name') or ''}"
        if not content:
            url = ""
            try:
                url = self.entry.get().strip()
            except Exception:
                pass
            if not url:
                url = self.subscription_url or ""
            if url.startswith(("http://", "https://")):
                content = url
                title = "订阅链接"
            elif url and "://" in url:
                content = url
                title = "节点链接"
        if not content:
            self.log("请先选择节点，或在订阅框填入链接后再生成二维码")
            return
        try:
            import qrcode
            from PIL import Image, ImageTk
        except Exception:
            self.log("缺少 qrcode 库，请重新构建后使用")
            return
        try:
            qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
            qr.add_data(content)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        except Exception as e:
            self.log(f"生成二维码失败：{e}")
            return

        # 弹窗显示
        try:
            import tkinter as tk
            win = ctk.CTkToplevel(self)
            win.title(title[:40] or "二维码")
            win.geometry("360x420")
            win.attributes("-topmost", True)
            ctk.CTkLabel(win, text=title[:48], font=("Microsoft YaHei UI", 13, "bold")).pack(pady=(12, 6))
            # resize for display
            disp = img.resize((280, 280), Image.Resampling.NEAREST)
            photo = ImageTk.PhotoImage(disp)
            lbl = tk.Label(win, image=photo, bg="white")
            lbl.image = photo
            lbl.pack(pady=8)
            hint = content if len(content) <= 60 else content[:57] + "..."
            ctk.CTkLabel(win, text=hint, font=("Consolas", 10), text_color=("gray40", "gray60"), wraplength=320).pack(padx=12)
            btn_row = ctk.CTkFrame(win, fg_color="transparent")
            btn_row.pack(pady=10)

            def _save():
                try:
                    from tkinter import filedialog
                    path = filedialog.asksaveasfilename(
                        defaultextension=".png",
                        filetypes=[("PNG", "*.png")],
                        initialfile="mobility-qr.png",
                    )
                    if path:
                        img.save(path)
                        self.log(f"二维码已保存：{path}")
                except Exception as e:
                    self.log(f"保存失败：{e}")

            ctk.CTkButton(btn_row, text="保存图片", width=100, command=_save).pack(side="left", padx=6)
            ctk.CTkButton(btn_row, text="关闭", width=80, command=win.destroy).pack(side="left", padx=6)
            self.log(f"已生成二维码（{title}）")
        except Exception as e:
            self.log(f"显示二维码窗口失败：{e}")

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
                "subscriptions": getattr(self, "subscriptions", []),
                "tun_enabled": bool(getattr(self, "tun_enabled", False)),
                "live_stats_enabled": bool(getattr(self, "live_stats_enabled", False)),
                "font_size": int(getattr(self, "font_size", 13)),
                "hotkey_toggle": getattr(self, "hotkey_toggle", "ctrl+shift+m"),
                "hotkey_proxy": getattr(self, "hotkey_proxy", "ctrl+shift+p"),
                "hotkey_clear_proxy": getattr(self, "hotkey_clear_proxy", ""),
                "hotkey_set_proxy": getattr(self, "hotkey_set_proxy", ""),
                "nodes": slim_nodes,
                "selected_label": (self.current_node or {}).get("_label", "") if self.nodes else "",
                "test_workers": self.workers_combo.get(),
                "proxy_mode": self.mode_combo.get() if hasattr(self, "mode_combo") else self.proxy_mode,
                "close_to_tray": bool(self.tray_check.get()) if hasattr(self, "tray_check") else self.close_to_tray,
                "auto_start": bool(self.autostart_check.get()) if hasattr(self, "autostart_check") else self.auto_start,
                "auto_connect": bool(self.autoconnect_check.get()) if hasattr(self, "autoconnect_check") else self.auto_connect,
                "socks_port": self.get_ports()[0],
                "http_port": self.get_ports()[1],
                "refresh_label": self.refresh_interval_combo.get() if hasattr(self, "refresh_interval_combo") else self.refresh_label,
                "start_minimized": bool(self.minimized_check.get()) if hasattr(self, "minimized_check") else self.start_minimized,
                "theme_label": self.theme_combo.get() if hasattr(self, "theme_combo") else self.theme_label,
                "allow_lan": bool(self.lan_check.get()) if hasattr(self, "lan_check") else self.allow_lan,
                "direct_domains": self.direct_entry.get().strip() if hasattr(self, "direct_entry") else self.direct_domains,
                "proxy_domains": self.proxy_entry.get().strip() if hasattr(self, "proxy_entry") else self.proxy_domains,
                "dns_mode": self.dns_combo.get() if hasattr(self, "dns_combo") else self.dns_mode,
                "dns_custom": self.dns_entry.get().strip() if hasattr(self, "dns_entry") else self.dns_custom,
                "log_level": self.loglevel_combo.get() if hasattr(self, "loglevel_combo") else self.log_level,
                "proxy_core": getattr(self, "proxy_core", "Xray"),
                "core_map": getattr(self, "core_map", dict(DEFAULT_CORE_MAP)),
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
            self.subscriptions = data.get("subscriptions") or []
            if not self.subscriptions and url.startswith("http"):
                self.subscriptions = [{"name": "订阅1", "url": url}]
            try:
                self.refresh_sub_select()
            except Exception:
                pass
            self.tun_enabled = bool(data.get("tun_enabled", False))

            cm = data.get("core_map") or {}
            self.core_map = dict(DEFAULT_CORE_MAP)
            if isinstance(cm, dict):
                for k, v in cm.items():
                    if k in self.core_map and v in CORE_OPTIONS:
                        self.core_map[k] = v
            self.proxy_core = data.get("proxy_core") or "Xray"
            try:
                if hasattr(self, "core_combo"):
                    self.core_combo.set(self.proxy_core if self.proxy_core in CORE_OPTIONS else "Xray")
            except Exception:
                pass
            try:
                self.refresh_version_label()
            except Exception:
                pass
            try:
                for proto, cb in getattr(self, "core_proto_combos", {}).items():
                    cb.set(self.core_map.get(proto, "Xray"))
            except Exception:
                pass
            self.live_stats_enabled = bool(data.get("live_stats_enabled", False))
            try:
                if hasattr(self, "live_stats_var"):
                    self.live_stats_var.set(self.live_stats_enabled)
            except Exception:
                pass
            if hasattr(self, "tun_check"):
                try:
                    if self.tun_enabled:
                        self.tun_check.select()
                    else:
                        self.tun_check.deselect()
                except Exception:
                    pass
            try:
                self.font_size = int(data.get("font_size") or 13)
            except Exception:
                self.font_size = 13
            if hasattr(self, "font_combo"):
                self.font_combo.set(str(self.font_size))
            self.hotkey_toggle = data.get("hotkey_toggle") or "ctrl+shift+m"
            self.hotkey_proxy = data.get("hotkey_proxy") or "ctrl+shift+p"
            self.hotkey_clear_proxy = data.get("hotkey_clear_proxy") or ""
            self.hotkey_set_proxy = data.get("hotkey_set_proxy") or ""
            try:
                self.settings_refresh_hours = float(data.get("settings_refresh_hours") or 0)
            except Exception:
                self.settings_refresh_hours = 0
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
                if hasattr(self, "refresh_interval_combo"):
                    self.refresh_interval_combo.set(rl)
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
                try:
                    self.dns_entry.pack_forget()
                except Exception:
                    pass
                try:
                    if self.dns_mode == "自定义":
                        self.dns_entry.pack(fill="x", padx=8, pady=2, after=self.dns_combo)
                except Exception:
                    if self.dns_mode == "自定义":
                        try:
                            self.dns_entry.pack(fill="x", padx=8, pady=2)
                        except Exception:
                            pass
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
                self._selected_label = data.get("selected_label") or ""
                self.refresh_node_list(keep_selection=True)
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
        self.refresh_node_list(keep_selection=True)

    def clear_node_filter(self):
        if hasattr(self, "filter_entry"):
            self.filter_entry.delete(0, "end")
        self.filter_text = ""
        self.refresh_node_list(keep_selection=False)
        self.log("已清除节点搜索过滤")

    def on_lan_option(self):
        self.allow_lan = bool(self.lan_check.get())
        self.save_settings()
        self.log(f"允许局域网连接：{'开启' if self.allow_lan else '关闭'}（需重启代理生效）")
        if self.allow_lan:
            self.log("局域网设备可使用本机 IP + 本地端口作为代理")

    def refresh_node_list(self, keep_selection: bool = True):
        """刷新左侧节点列表（滚动列表，不再用 ComboBox）。"""
        try:
            nodes = list(self.nodes or [])
            self.clear_node_list_ui()

            if not nodes:
                self.node_count_label.configure(text="节点：0")
                empty = ctk.CTkLabel(self.node_list, text="（请先加载订阅或节点）",
                                     font=("Microsoft YaHei UI", 12), text_color=("gray50", "gray55"))
                empty.pack(pady=20)
                self._node_buttons.append(empty)
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

            kw = ""
            try:
                kw = (self.filter_entry.get() or "").strip().lower()
            except Exception:
                kw = ""

            prev = self._selected_label if keep_selection else None
            shown = 0
            selected_btn = None
            for i, n in enumerate(self.nodes):
                try:
                    lb = node_label(n)
                except Exception:
                    lb = f"节点{i+1}"
                n["_label"] = lb
                n["_index"] = i
                if kw:
                    blob = f"{n.get('name','')} {n.get('address','')} {n.get('protocol','')}".lower()
                    if kw not in blob:
                        continue
                btn = ctk.CTkButton(
                    self.node_list,
                    text=lb,
                    anchor="w",
                    height=30,
                    fg_color=("gray85", "gray25"),
                    text_color=("gray10", "gray90"),
                    hover_color=("#93C5FD", "#1E3A8A"),
                    font=("Microsoft YaHei UI", 12),
                )
                btn.configure(command=lambda node=n, b=btn: self.on_node_button_click(node, b))
                btn.pack(fill="x", pady=1, padx=2)
                self._node_buttons.append(btn)
                shown += 1
                if prev and lb == prev:
                    selected_btn = (n, btn)

            self.node_count_label.configure(text=f"节点：{shown}/{len(self.nodes)}")
            if selected_btn:
                self.on_node_button_click(selected_btn[0], selected_btn[1])
            elif self._node_buttons and isinstance(self._node_buttons[0], ctk.CTkButton):
                # 默认选第一个可见节点
                first_node = None
                for n in self.nodes:
                    if n.get("_label") == self._node_buttons[0].cget("text"):
                        first_node = n
                        break
                if first_node is None and self.nodes:
                    first_node = self.nodes[0]
                if first_node is not None:
                    self.on_node_button_click(first_node, self._node_buttons[0])
            self.log(f"节点列表已更新：{shown} 条")
        except Exception as e:
            self.log(f"刷新节点列表失败：{type(e).__name__}: {e}")



    def refresh_sub_select(self):
        names = [s.get("name") or (s.get("url") or "")[:24] for s in self.subscriptions]
        if not names:
            self.sub_select.configure(values=["（无订阅）"])
            self.sub_select.set("（无订阅）")
            return
        self.sub_select.configure(values=names)
        cur = self.subscription_url
        for s in self.subscriptions:
            if s.get("url") == cur:
                self.sub_select.set(s.get("name") or (s.get("url") or "")[:24])
                return
        self.sub_select.set(names[0])

    def on_sub_select(self, value=None):
        name = value or self.sub_select.get()
        for s in self.subscriptions:
            n = s.get("name") or (s.get("url") or "")[:24]
            if n == name:
                self.entry.delete(0, "end")
                self.entry.insert(0, s.get("url") or "")
                self.subscription_url = s.get("url") or ""
                break

    def add_subscription(self):
        url = self.entry.get().strip()
        if not url.startswith(("http://", "https://")):
            self.log("请输入有效的订阅 URL 后再点添加")
            return
        for s in self.subscriptions:
            if s.get("url") == url:
                self.log("该订阅已存在")
                self.subscription_url = url
                self.refresh_sub_select()
                return
        try:
            from urllib.parse import urlparse
            name = (urlparse(url).netloc or "")[:20] or f"订阅{len(self.subscriptions)+1}"
        except Exception:
            name = f"订阅{len(self.subscriptions)+1}"
        self.subscriptions.append({"name": name, "url": url})
        self.subscription_url = url
        self.refresh_sub_select()
        self.save_settings()
        self.log(f"已添加订阅：{name}")
        self.load_nodes_thread()

    def remove_subscription(self):
        name = self.sub_select.get()
        before = len(self.subscriptions)
        self.subscriptions = [
            s for s in self.subscriptions
            if (s.get("name") or (s.get("url") or "")[:24]) != name
        ]
        if len(self.subscriptions) == before:
            self.log("未找到要删除的订阅")
            return
        self.refresh_sub_select()
        if self.subscriptions:
            self.on_sub_select(self.sub_select.get())
        else:
            self.subscription_url = ""
            self.entry.delete(0, "end")
            self.nodes = []
            self.refresh_node_list()
        self.save_settings()
        self.log(f"已删除订阅：{name}")

    def rename_subscription(self):
        name = self.sub_select.get() if hasattr(self, "sub_select") else ""
        if not name or name == "（无订阅）":
            self.log("请先选择要改名的订阅")
            return
        try:
            import tkinter.simpledialog as simpledialog
            new_name = simpledialog.askstring("订阅改名", f"当前名称：{name}\n请输入新名称：", parent=self)
        except Exception:
            new_name = None
        if not new_name:
            return
        new_name = new_name.strip()
        if not new_name:
            self.log("名称不能为空")
            return
        # 重名检查
        for s in self.subscriptions:
            n = s.get("name") or (s.get("url") or "")[:24]
            if n == new_name and n != name:
                self.log("已存在同名订阅")
                return
        for s in self.subscriptions:
            n = s.get("name") or (s.get("url") or "")[:24]
            if n == name:
                s["name"] = new_name
                self.log(f"订阅已改名：{name} → {new_name}")
                break
        self.refresh_sub_select()
        try:
            self.sub_select.set(new_name)
        except Exception:
            pass
        self.save_settings()

    def refresh_all_subs_thread(self):
        Thread(target=self.refresh_all_subs, daemon=True).start()

    def refresh_all_subs(self):
        if not self.subscriptions:
            url = self.entry.get().strip()
            if url.startswith("http"):
                self.subscriptions.append({"name": "订阅1", "url": url})
            else:
                self.log("没有可更新的订阅")
                return
        self.after(0, lambda: self.load_btn.configure(state="disabled"))
        all_nodes = []
        seen = set()
        for s in self.subscriptions:
            url = s.get("url") or ""
            if not url:
                continue
            try:
                self.log(f"更新订阅：{s.get('name')} ...")
                resp = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0 Mobility"})
                resp.raise_for_status()
                nodes = parse_subscription_content(resp.text)
                for n in nodes:
                    key = f"{n.get('protocol')}|{n.get('address')}|{n.get('port')}"
                    if key in seen:
                        continue
                    seen.add(key)
                    n["from_sub"] = s.get("name")
                    all_nodes.append(n)
                self.log(f"  -> {len(nodes)} 个节点")
            except Exception as e:
                self.log(f"  失败：{e}")
        self.nodes = all_nodes

        def _ui():
            self.refresh_node_list(keep_selection=False)
            self.save_settings()
            self.load_btn.configure(state="normal")
            self.log(f"全部订阅更新完成，去重后共 {len(self.nodes)} 个节点")
        self.after(0, _ui)

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
                if not any(s.get("url") == text for s in self.subscriptions):
                    try:
                        from urllib.parse import urlparse
                        nm = (urlparse(text).netloc or "")[:20] or f"订阅{len(self.subscriptions)+1}"
                    except Exception:
                        nm = f"订阅{len(self.subscriptions)+1}"
                    self.subscriptions.append({"name": nm, "url": text})
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
            self.refresh_node_list()
            self.after(0, lambda: self.load_btn.configure(state="normal"))
            return

        count = len(self.nodes)
        # 所有 UI 操作丢回主线程
        def _ui_ok():
            try:
                self.log(f"解析到 {count} 个节点，正在刷新列表...")
                self.refresh_node_list(keep_selection=False)
                try:
                    self.refresh_sub_select()
                except Exception:
                    pass
                self.save_settings()
            finally:
                try:
                    self.load_btn.configure(state="normal")
                except Exception:
                    pass
        self.after(0, _ui_ok)

    def on_dns_change(self, value=None):
        self.dns_mode = self.dns_combo.get() or "系统默认"
        try:
            self.dns_entry.pack_forget()
        except Exception:
            pass
        try:
            if self.dns_mode == "自定义":
                # 紧跟在 DNS 下拉框后面，避免跑到面板底部
                self.dns_entry.pack(fill="x", padx=8, pady=2, after=self.dns_combo)
                self.dns_entry.configure(state="normal")
            else:
                self.dns_entry.configure(state="disabled")
        except Exception as e:
            try:
                if self.dns_mode == "自定义":
                    self.dns_entry.pack(fill="x", padx=8, pady=2)
            except Exception:
                pass
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

        self.refresh_node_list(keep_selection=False)
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
        self.current_node = best
        self._selected_label = best.get("_label")
        self.refresh_node_list(keep_selection=True)
        self.log(f"已选择最低延迟：{best['name']} ({best['latency']}ms)")
        self.save_settings()

    def get_selected_node(self):
        if self.current_node and self.current_node in (self.nodes or []):
            return self.current_node
        if self.current_node:
            # 可能重载后对象不同，按 label 找
            lb = self.current_node.get("_label") or self.current_node.get("name")
            for n in self.nodes or []:
                if n.get("_label") == lb or n.get("name") == lb:
                    return n
        if self.nodes:
            return self.nodes[0]
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
                # 关闭 access 日志，显著降低磁盘与内存开销
                "access": "none",
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



        # Stats API 常驻（占用很小）；界面是否轮询由「实时统计」开关控制
        api_port = int(getattr(self, "api_port", 10085))
        config["stats"] = {}
        config["api"] = {"tag": "api", "services": ["StatsService"]}
        config["policy"] = {
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
            }
        }
        config["inbounds"].append({
            "tag": "api",
            "listen": "127.0.0.1",
            "port": api_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        })
        rules = config.get("routing", {}).get("rules") or []
        rules.insert(0, {"inboundTag": ["api"], "outboundTag": "api", "type": "field"})
        config.setdefault("routing", {})["rules"] = rules
        outs = config.get("outbounds") or []
        if not any(o.get("tag") == "api" for o in outs):
            outs.append({"tag": "api", "protocol": "freedom"})
            config["outbounds"] = outs

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

    def _short_node_text(self, node: dict, lat_s: str = "") -> str:
        name = (node or {}).get("name") or "无"
        proto = (node or {}).get("protocol") or ""
        if len(name) > 28:
            name = name[:26] + "…"
        base = f"当前节点：[{proto}] {name}"
        if lat_s:
            base += f" ({lat_s})"
        return base

    def _fmt_bytes(self, n: float) -> str:
        n = float(n or 0)
        for u in ("B", "KB", "MB", "GB", "TB"):
            if abs(n) < 1024:
                return f"{n:.1f} {u}" if u != "B" else f"{int(n)} {u}"
            n /= 1024
        return f"{n:.1f} PB"

    def _fmt_duration(self, secs: float) -> str:
        secs = int(max(0, secs))
        h, r = divmod(secs, 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _query_xray_traffic(self):
        """返回 (uplink_bytes, downlink_bytes) 或 None。"""
        try:
            if not self.xray_process or self.xray_process.poll() is not None:
                return None
            xray_exe = self.core_dir / "xray.exe"
            if not xray_exe.exists():
                return None
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            api_port = int(getattr(self, "api_port", 10085))

            def _one(name: str) -> int:
                try:
                    r = subprocess.run(
                        [str(xray_exe), "api", "stats", f"--server=127.0.0.1:{api_port}", f"-name={name}"],
                        capture_output=True, text=True, timeout=1.5,
                        creationflags=flags, cwd=str(self.core_dir),
                    )
                    out = (r.stdout or "") + (r.stderr or "")
                    # value: 12345
                    for line in out.splitlines():
                        line = line.strip()
                        if "value:" in line.lower() or line.isdigit():
                            num = "".join(ch for ch in line if ch.isdigit() or ch == "-")
                            if num:
                                return max(0, int(num))
                    # JSON-ish
                    import re as _re
                    ms = _re.findall(r"(\d+)", out)
                    if ms:
                        return max(0, int(ms[-1]))
                except Exception:
                    return 0
                return 0

            # 优先 outbound proxy；TUN 下同时累加 inbound tun-in
            up = _one("outbound>>>proxy>>>uplink")
            down = _one("outbound>>>proxy>>>downlink")
            if getattr(self, "tun_enabled", False):
                up = max(up, _one("inbound>>>tun-in>>>uplink"))
                down = max(down, _one("inbound>>>tun-in>>>downlink"))
            return up, down
        except Exception:
            return None


    def _xray_memory_mb(self) -> str:
        try:
            if not self.xray_process or self.xray_process.poll() is not None:
                return "--"
            pid = self.xray_process.pid
            mb = None
            try:
                import psutil
                proc = psutil.Process(pid)
                # 仅当前 xray 进程，不含子进程合计膨胀
                mb = proc.memory_info().rss / (1024 * 1024)
            except Exception:
                flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                r = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=1, creationflags=flags,
                )
                parts = [x.strip().strip('"') for x in (r.stdout or "").split(",")]
                if len(parts) >= 5:
                    mem = parts[-1].replace("K", "").replace("k", "").replace(",", "").replace(" ", "")
                    try:
                        mb = int(mem) / 1024
                    except Exception:
                        pass
            if mb is None:
                return "--"
            return f"{mb:.0f} MB"
        except Exception:
            return "--"


    def _sample_stats_worker(self):
        try:
            tr = self._query_xray_traffic()
            now = time.time()
            speed_up = getattr(self, "_speed_up", 0.0)
            speed_down = getattr(self, "_speed_down", 0.0)
            total = (getattr(self, "_bytes_up", 0) or 0) + (getattr(self, "_bytes_down", 0) or 0)
            if tr:
                up, down = tr
                last_ts = getattr(self, "_last_stat_ts", 0) or 0
                if last_ts:
                    dt = max(0.001, now - last_ts)
                    speed_up = max(0.0, (up - getattr(self, "_last_up", 0)) / dt)
                    speed_down = max(0.0, (down - getattr(self, "_last_down", 0)) / dt)
                self._last_up, self._last_down = up, down
                self._last_stat_ts = now
                self._bytes_up, self._bytes_down = up, down
                self._speed_up, self._speed_down = speed_up, speed_down
                total = up + down
            mem = "--"
            # 内存最多 15 秒刷新一次
            if not hasattr(self, "_last_mem_ts"):
                self._last_mem_ts = 0
            if now - self._last_mem_ts > 15:
                self._last_mem_ts = now
                mem = self._xray_memory_mb()
                self._last_mem_text = mem
            else:
                mem = getattr(self, "_last_mem_text", "--")

            def _apply():
                try:
                    if hasattr(self, "stat_up_label"):
                        up_mbps = (speed_up * 8) / 1_000_000
                        down_mbps = (speed_down * 8) / 1_000_000
                        self.stat_up_label.configure(
                            text=f"↑ {self._fmt_bytes(speed_up)}/s ({up_mbps:.2f} Mbps)"
                        )
                        self.stat_down_label.configure(
                            text=f"↓ {self._fmt_bytes(speed_down)}/s ({down_mbps:.2f} Mbps)"
                        )
                        self.stat_total_label.configure(text=f"流量 {self._fmt_bytes(total)}")
                    if hasattr(self, "stat_mem_label"):
                        self.stat_mem_label.configure(text=f"内存 {mem}")
                except Exception:
                    pass
                finally:
                    self._stats_busy = False
            self.after(0, _apply)
        except Exception:
            self._stats_busy = False

    def on_live_stats_toggle(self):
        try:
            self.live_stats_enabled = bool(self.live_stats_var.get())
        except Exception:
            self.live_stats_enabled = False
        if self.live_stats_enabled:
            self.log("实时统计：已开启")
            if self.is_running:
                # 立即采一次
                if not getattr(self, "_stats_busy", False):
                    self._stats_busy = True
                    Thread(target=self._sample_stats_worker, daemon=True).start()
        else:
            self.log("实时统计：已关闭")
            try:
                if hasattr(self, "stat_up_label"):
                    self.stat_up_label.configure(text="↑ --")
                    self.stat_down_label.configure(text="↓ --")
                if hasattr(self, "stat_mem_label"):
                    self.stat_mem_label.configure(text="内存 --")
            except Exception:
                pass

    def update_home_stats(self):
        try:
            if self.is_running:
                try:
                    self.status_label.configure(text="运行中", text_color="#16A34A")
                except Exception:
                    pass
                if self._run_started_at and hasattr(self, "stat_time_label"):
                    self.stat_time_label.configure(
                        text=f"时长 {self._fmt_duration(time.time() - self._run_started_at)}"
                    )
                if getattr(self, "live_stats_enabled", False):
                    if not getattr(self, "_stats_busy", False):
                        self._stats_busy = True
                        Thread(target=self._sample_stats_worker, daemon=True).start()
                else:
                    # 未开启实时统计时只更新时长
                    try:
                        if hasattr(self, "stat_up_label"):
                            self.stat_up_label.configure(text="↑ --")
                            self.stat_down_label.configure(text="↓ --")
                        if hasattr(self, "stat_mem_label"):
                            self.stat_mem_label.configure(text="内存 --")
                    except Exception:
                        pass
            else:
                try:
                    self.status_label.configure(text="未运行", text_color=("gray30", "gray70"))
                except Exception:
                    pass
                if hasattr(self, "stat_time_label"):
                    self.stat_time_label.configure(text="时长 00:00:00")
                if hasattr(self, "stat_up_label"):
                    self.stat_up_label.configure(text="↑ 0 B/s")
                    self.stat_down_label.configure(text="↓ 0 B/s")
                    total = (getattr(self, "_bytes_up", 0) or 0) + (getattr(self, "_bytes_down", 0) or 0)
                    self.stat_total_label.configure(text=f"流量 {self._fmt_bytes(total)}")
                if hasattr(self, "stat_mem_label"):
                    self.stat_mem_label.configure(text="内存 --")
        except Exception:
            pass
        self.after(12000 if getattr(self, "tun_enabled", False) else 8000, self.update_home_stats)




    def node_to_singbox_outbound(self, node: dict) -> dict:
        """把节点转成 sing-box 出站配置。"""
        proto = (node.get("protocol") or "").lower()
        server = node.get("address") or ""
        port = int(node.get("port") or 443)
        network = (node.get("network") or "tcp").lower()
        tls_enabled = False
        if proto == "trojan":
            tls_enabled = True
        elif proto in ("vless", "vmess"):
            sec = (node.get("security") or node.get("tls") or "").lower()
            tls_enabled = sec in ("tls", "reality", "xtls")
        elif node.get("tls"):
            tls_enabled = str(node.get("tls")).lower() in ("tls", "true", "1")

        outbound = {
            "type": proto if proto != "shadowsocks" else "shadowsocks",
            "tag": "proxy",
            "server": server,
            "server_port": port,
        }

        if proto == "trojan":
            outbound["password"] = node.get("password") or ""
        elif proto == "vmess":
            outbound["uuid"] = node.get("uuid") or ""
            outbound["alter_id"] = int(node.get("alterId") or 0)
            outbound["security"] = node.get("security") or "auto"
        elif proto == "vless":
            outbound["uuid"] = node.get("uuid") or ""
            outbound["flow"] = node.get("flow") or ""
            outbound["packet_encoding"] = ""
        elif proto == "shadowsocks":
            outbound["method"] = node.get("method") or "aes-256-gcm"
            outbound["password"] = node.get("password") or ""
        else:
            raise ValueError(f"sing-box 暂不支持协议：{proto}")

        # TLS
        if tls_enabled:
            tls = {
                "enabled": True,
                "server_name": node.get("sni") or node.get("host") or server,
                "insecure": True,
            }
            if (node.get("security") or "").lower() == "reality" or node.get("pbk"):
                tls["reality"] = {
                    "enabled": True,
                    "public_key": node.get("pbk") or "",
                    "short_id": node.get("sid") or "",
                }
                if node.get("fp"):
                    tls["utls"] = {"enabled": True, "fingerprint": node.get("fp") or "chrome"}
            elif node.get("fp"):
                tls["utls"] = {"enabled": True, "fingerprint": node.get("fp") or "chrome"}
            outbound["tls"] = tls

        # Transport
        if network == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": node.get("path") or "/",
                "headers": {"Host": node.get("host") or node.get("sni") or server},
            }
        elif network == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": node.get("serviceName") or node.get("path") or "",
            }
        elif network == "h2" or network == "http":
            outbound["transport"] = {
                "type": "http",
                "path": node.get("path") or "/",
                "host": [node.get("host") or node.get("sni") or server],
            }

        return outbound


    def node_to_mihomo_proxy(self, node: dict) -> dict:
        """节点转 Mihomo/Clash Meta 代理项。"""
        proto = (node.get("protocol") or "").lower()
        name = node.get("name") or "node"
        server = node.get("address") or ""
        port = int(node.get("port") or 443)
        network = (node.get("network") or "tcp").lower()
        proxy = {"name": name, "server": server, "port": port}

        if proto == "trojan":
            proxy["type"] = "trojan"
            proxy["password"] = node.get("password") or ""
            proxy["sni"] = node.get("sni") or node.get("host") or server
            proxy["skip-cert-verify"] = True
            if network == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {
                    "path": node.get("path") or "/",
                    "headers": {"Host": node.get("host") or node.get("sni") or server},
                }
            elif network == "grpc":
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = {"grpc-service-name": node.get("serviceName") or ""}
        elif proto == "vmess":
            proxy["type"] = "vmess"
            proxy["uuid"] = node.get("uuid") or ""
            proxy["alterId"] = int(node.get("alterId") or 0)
            proxy["cipher"] = node.get("security") or "auto"
            tls_on = str(node.get("tls") or "").lower() in ("tls", "true", "1")
            if tls_on or (node.get("security") or "").lower() == "tls":
                proxy["tls"] = True
                proxy["servername"] = node.get("sni") or node.get("host") or server
                proxy["skip-cert-verify"] = True
            if network == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {
                    "path": node.get("path") or "/",
                    "headers": {"Host": node.get("host") or server},
                }
            elif network == "grpc":
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = {"grpc-service-name": node.get("serviceName") or ""}
        elif proto == "vless":
            proxy["type"] = "vless"
            proxy["uuid"] = node.get("uuid") or ""
            proxy["flow"] = node.get("flow") or ""
            sec = (node.get("security") or "").lower()
            if sec in ("tls", "reality"):
                proxy["tls"] = True
                proxy["servername"] = node.get("sni") or node.get("host") or server
                proxy["skip-cert-verify"] = True
                if node.get("fp"):
                    proxy["client-fingerprint"] = node.get("fp")
                if sec == "reality" or node.get("pbk"):
                    proxy["reality-opts"] = {
                        "public-key": node.get("pbk") or "",
                        "short-id": node.get("sid") or "",
                    }
            if network == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {
                    "path": node.get("path") or "/",
                    "headers": {"Host": node.get("host") or server},
                }
            elif network == "grpc":
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = {"grpc-service-name": node.get("serviceName") or ""}
        elif proto in ("shadowsocks", "ss"):
            proxy["type"] = "ss"
            proxy["cipher"] = node.get("method") or "aes-256-gcm"
            proxy["password"] = node.get("password") or ""
        else:
            raise ValueError(f"Mihomo 暂不支持协议：{proto}")
        return proxy

    def create_mihomo_config(self, node: dict, socks_port: int, http_port: int, enable_tun: bool) -> Path:
        """生成 Mihomo (Clash Meta) 配置。"""
        proxy = self.node_to_mihomo_proxy(node)
        mode = self.proxy_mode or "规则模式"
        if "全局" in mode:
            clash_mode = "global"
        elif "直连" in mode:
            clash_mode = "direct"
        else:
            clash_mode = "rule"

        cfg = {
            "mixed-port": int(http_port),
            "socks-port": int(socks_port),
            "allow-lan": bool(getattr(self, "allow_lan", False)),
            "mode": clash_mode,
            "log-level": "warning",
            "ipv6": False,
            "external-controller": "",
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",
                "nameserver": ["8.8.8.8", "1.1.1.1"],
                "fallback": ["1.0.0.1"],
            },
            "proxies": [proxy],
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": [proxy["name"]]},
            ],
            "rules": [
                "GEOIP,lan,DIRECT",
                "MATCH,PROXY",
            ],
        }
        if enable_tun:
            cfg["tun"] = {
                "enable": True,
                "stack": "mixed",
                "auto-route": True,
                "auto-detect-interface": True,
                "dns-hijack": ["any:53"],
            }
        path = self.core_dir / "mihomo.yaml"
        # Mihomo 支持 JSON；用 JSON 避免依赖 PyYAML
        path_json = self.core_dir / "mihomo.json"
        with open(path_json, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        return path_json

    def stop_mihomo(self):
        if getattr(self, "mihomo_process", None):
            try:
                self.mihomo_process.terminate()
                try:
                    self.mihomo_process.wait(timeout=2)
                except Exception:
                    self.mihomo_process.kill()
            except Exception:
                pass
            self.mihomo_process = None

    def create_singbox_full_config(self, node: dict, socks_port: int, http_port: int, enable_tun: bool) -> Path:
        """sing-box 完整配置：mixed 入站 + 可选 TUN + 节点出站。"""
        outbound = self.node_to_singbox_outbound(node)
        inbounds = [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": int(http_port),
            }
        ]
        # SOCKS 单独端口（与界面 SOCKS 一致）
        if int(socks_port) != int(http_port):
            inbounds.append({
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": int(socks_port),
            })

        if enable_tun:
            inbounds.append({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "Mobility0",
                "address": ["172.19.0.1/30"],
                "mtu": 1400,
                "auto_route": True,
                "strict_route": False,
                "stack": "mixed",
                "route_exclude_address": [
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                ],
            })

        mode = self.proxy_mode or "规则模式"
        rules = [{"action": "sniff"}]
        if "全局" in mode:
            final = "proxy"
        elif "直连" in mode:
            final = "direct"
        else:
            # 规则：私网直连，其余代理（简化）
            rules.append({"ip_is_private": True, "outbound": "direct"})
            final = "proxy"

        cfg = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": inbounds,
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"},
            ],
            "route": {
                "auto_detect_interface": True,
                "final": final,
                "rules": rules,
            },
        }
        path = self.core_dir / "singbox-full.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        return path

    def create_singbox_tun_config(self, socks_port: int, http_port: int = None) -> Path:
        """生成 sing-box 1.13+ 兼容的 TUN 配置（无 legacy inbound 字段）。"""
        if http_port is None:
            try:
                _, http_port = self.get_ports()
            except Exception:
                http_port = 10809
        cfg = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "Mobility0",
                    "address": ["172.19.0.1/30"],
                    "mtu": 1400,
                    "auto_route": True,
                    "strict_route": False,
                    "stack": "mixed",
                    "route_exclude_address": [
                        "127.0.0.0/8",
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                    ],
                    "platform": {
                        "http_proxy": {
                            "enabled": True,
                            "server": "127.0.0.1",
                            "server_port": int(http_port),
                        }
                    },
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": int(socks_port),
                    "version": "5",
                },
                {"type": "direct", "tag": "direct"},
            ],
            "route": {
                "auto_detect_interface": True,
                "final": "proxy",
                "rules": [
                    {"action": "sniff"},
                    {"ip_is_private": True, "outbound": "direct"},
                ],
            },
        }
        path = self.core_dir / "singbox-tun.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        return path

    def stop_singbox(self):
        if getattr(self, "singbox_process", None):
            try:
                self.singbox_process.terminate()
                try:
                    self.singbox_process.wait(timeout=2)
                except Exception:
                    self.singbox_process.kill()
            except Exception:
                pass
            self.singbox_process = None

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
            text=self._short_node_text(node, lat_s)
        ))
        try:
            self.after(0, lambda: self.refresh_version_label())
        except Exception:
            pass

        core_name = self.resolve_core_for_node(node)
        self.proxy_core = core_name
        self.log(f"节点协议 [{node.get('protocol')}] → 核心 {core_name}")
        try:
            self.after(0, lambda: self.refresh_version_label(core_name))
        except Exception:
            pass

        socks_port, http_port = self.get_ports()
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        # ========== sing-box 核心：独立完整配置 ==========
        if core_name.lower().startswith("sing"):
            sb = ensure_singbox(self.core_dir, log_fn=self.log)
            if not sb:
                self.log("错误：找不到 sing-box 核心")
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return
            if getattr(self, "tun_enabled", False):
                try:
                    ensure_wintun(self.core_dir, log_fn=self.log)
                except Exception:
                    pass
            try:
                sb_cfg = self.create_singbox_full_config(
                    node, socks_port, http_port, bool(getattr(self, "tun_enabled", False))
                )
                self.log("sing-box 配置已生成")
            except Exception as e:
                self.log(f"生成 sing-box 配置失败：{e}")
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return
            try:
                sb_log = self.core_dir / "singbox.log"
                sb_log_handle = open(sb_log, "w", encoding="utf-8", errors="ignore")
                self.singbox_process = subprocess.Popen(
                    [str(sb), "run", "-c", str(sb_cfg)],
                    cwd=str(self.core_dir),
                    creationflags=flags,
                    stdout=sb_log_handle,
                    stderr=subprocess.STDOUT,
                )
                time.sleep(1.2)
                if self.singbox_process.poll() is not None:
                    self.log("sing-box 启动失败")
                    try:
                        txt = sb_log.read_text(encoding="utf-8", errors="ignore")
                        for ln in txt.strip().splitlines()[-12:]:
                            self.log("  " + ln[:220])
                    except Exception:
                        pass
                    self.singbox_process = None
                    self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                    return
                # 系统代理指向 sing-box mixed/http 端口
                if self.set_system_proxy(True, http_port):
                    self.log(f"系统代理已设置 127.0.0.1:{http_port}")
                self.is_running = True
                self.after(0, lambda: self.status_label.configure(text="运行中", text_color="#16A34A"))
                tun_s = " + TUN" if getattr(self, "tun_enabled", False) else ""
                self.log(f"代理已启动（sing-box{tun_s}）")
                self._run_started_at = time.time()
                self.set_tray_state("connected")
                self.save_settings()
            except Exception as e:
                self.log(f"启动 sing-box 失败：{e}")
                self.singbox_process = None
            self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
            return

        # ========== Xray 核心（默认） ==========
        xray_exe = self.core_dir / "xray.exe"
        if not xray_exe.exists():
            self.prepare_core()
            if not xray_exe.exists():
                self.log("错误：找不到核心文件")
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
            if getattr(self, "tun_enabled", False):
                try:
                    ensure_wintun(self.core_dir, log_fn=self.log)
                except Exception:
                    pass
            self.xray_process = subprocess.Popen(
                [str(xray_exe), "run", "-c", str(config_path)],
                cwd=str(self.core_dir),
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=log_handle,
                stderr=log_handle,
            )

            time.sleep(1.5)
            # TUN 启动后检查 error.log 是否有接口错误
            if getattr(self, "tun_enabled", False):
                try:
                    errp = self.core_dir / "error.log"
                    if errp.exists():
                        err_txt = errp.read_text(encoding="utf-8", errors="ignore")
                        low = err_txt.lower()
                        if "failed" in low or "error" in low or "wintun" in low:
                            # 只打最后几行，避免刷屏
                            lines = [ln for ln in err_txt.strip().splitlines() if ln.strip()][-8:]
                            if lines:
                                self.log("核心日志（TUN）：")
                                for ln in lines:
                                    self.log("  " + ln[:200])
                except Exception:
                    pass
            ret = self.xray_process.poll()
            if ret is not None:
                self.log(f"代理启动失败，退出码：{ret}")
                err = self.read_xray_error()
                full = err or ""
                if not full:
                    try:
                        log_handle.close()
                        full = self.log_file.read_text(encoding="utf-8", errors="ignore").strip()
                    except Exception:
                        full = ""
                if full:
                    self.log("核心输出：")
                    for line in full.splitlines()[-12:]:
                        self.log("  " + line)
                if "wintun" in full.lower():
                    self.log("TUN 启动失败：缺少或无法加载 wintun.dll，已自动关闭 TUN")
                    self.tun_enabled = False
                    try:
                        self.after(0, lambda: self.tun_check.deselect())
                    except Exception:
                        pass
                    self.save_settings()
                    self.log("请关闭 TUN 后重新启动，或点击 TUN 时自动下载 wintun")
                self.xray_process = None
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return

            socks_port, http_port = self.get_ports()
            proxy_ok = True
            if getattr(self, "tun_enabled", False):
                # TUN + 系统代理：纯 TUN 在部分环境下浏览器仍无法出网
                if self.set_system_proxy(True, http_port):
                    self.log(f"系统代理已设置 127.0.0.1:{http_port}（浏览器兼容）")
                else:
                    self.log("系统代理设置失败，仅依赖 TUN")
                sb = ensure_singbox(self.core_dir, log_fn=self.log)
                if not sb:
                    self.log("未找到 sing-box，无法启用 TUN")
                    try:
                        self.xray_process.terminate()
                    except Exception:
                        pass
                    self.xray_process = None
                    self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal"))
                    return
                try:
                    ensure_wintun(self.core_dir, log_fn=self.log)
                except Exception:
                    pass
                sb_cfg = self.create_singbox_tun_config(socks_port, http_port)
                flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                sb_log = self.core_dir / "singbox.log"
                try:
                    sb_log_handle = open(sb_log, "w", encoding="utf-8", errors="ignore")
                except Exception:
                    sb_log_handle = subprocess.DEVNULL
                self.singbox_process = subprocess.Popen(
                    [str(sb), "run", "-c", str(sb_cfg)],
                    cwd=str(self.core_dir),
                    creationflags=flags,
                    stdout=sb_log_handle,
                    stderr=subprocess.STDOUT,
                )
                time.sleep(1.2)
                if self.singbox_process.poll() is not None:
                    self.log("sing-box TUN 启动失败，请确认：①管理员运行 ②core\\wintun.dll 存在")
                    try:
                        if sb_log.exists():
                            txt = sb_log.read_text(encoding="utf-8", errors="ignore").strip()
                            if txt:
                                self.log("sing-box 输出：")
                                for ln in txt.splitlines()[-10:]:
                                    self.log("  " + ln[:220])
                    except Exception:
                        pass
                    try:
                        self.xray_process.terminate()
                    except Exception:
                        pass
                    self.xray_process = None
                    self.singbox_process = None
                    self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal"))
                    return
                core_name = getattr(self, "proxy_core", "Xray") or "Xray"
                self.log(f"sing-box TUN 已启动（代理核心：{core_name}，流量经本地 SOCKS）")
            else:
                proxy_ok = bool(self.set_system_proxy(True, http_port))
                if proxy_ok:
                    self.log(f"系统代理已设置为 127.0.0.1:{http_port}")

            if proxy_ok:
                self.is_running = True
                # TUN 时默认关闭实时统计，避免额外开销
                if getattr(self, "tun_enabled", False):
                    try:
                        self.live_stats_enabled = False
                        if hasattr(self, "live_stats_var"):
                            self.live_stats_var.set(False)
                    except Exception:
                        pass
                self.after(0, lambda: self.status_label.configure(
                    text="运行中", text_color="#16A34A"
                ))
                self.log("代理已启动" + ("（sing-box TUN）" if getattr(self, "tun_enabled", False) else ""))
                if self.allow_lan and not getattr(self, "tun_enabled", False):
                    self.log(f"已允许局域网：其他设备可连 本机IP:{http_port} (HTTP) / {self.get_ports()[0]} (SOCKS)")
                self._run_started_at = time.time()
                self._bytes_up = self._bytes_down = 0
                self._last_up = self._last_down = 0
                self._last_stat_ts = 0.0
                self._speed_up = self._speed_down = 0.0
                mode = self.proxy_mode or ""
                if getattr(self, "tun_enabled", False):
                    self.set_tray_state("connected")
                elif "规则" in mode:
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
        try:
            self.stop_singbox()
        except Exception:
            pass
        try:
            self.stop_mihomo()
        except Exception:
            pass
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

        try:
            self.set_system_proxy(False)
        except Exception:
            pass
        self.is_running = False
        self._run_started_at = None
        try:
            self.status_label.configure(text="未运行", text_color=("gray30", "gray70"))
        except Exception:
            pass
        try:
            self.set_tray_state("disconnected")
        except Exception:
            pass
        self.log("代理已停止，系统代理已关闭")
        # 恢复启动按钮
        try:
            self.after(0, lambda: self.start_btn.configure(state="normal"))
        except Exception:
            try:
                self.start_btn.configure(state="normal")
            except Exception:
                pass

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


def ensure_single_instance() -> bool:
    """Windows 下仅允许运行一个 Mobility 实例。"""
    try:
        kernel32 = ctypes.windll.kernel32
        # 全局互斥体
        handle = kernel32.CreateMutexW(None, False, "Global\\MobilityProxySingleInstance")
        last = kernel32.GetLastError()
        # ERROR_ALREADY_EXISTS = 183
        if last == 183:
            return False
        # 保持句柄，进程退出系统自动释放
        ensure_single_instance._handle = handle
        return True
    except Exception:
        return True


if __name__ == "__main__":
    if not ensure_single_instance():
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning("Mobility", "程序已在运行，不能重复启动。")
            root.destroy()
        except Exception:
            pass
        raise SystemExit(0)
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = App()
    app.mainloop()
