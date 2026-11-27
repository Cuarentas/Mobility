import customtkinter as ctk
import subprocess
import sys
import os
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
DEFAULT_TEST_TIMEOUT = 5.0
DEFAULT_CONNECTIVITY_URLS = [
    ("https://www.gstatic.com/generate_204", "GStatic"),
    ("https://www.google.com/generate_204", "Google"),
    ("https://cp.cloudflare.com/", "Cloudflare"),
]
PROXY_MODES = ["规则模式", "全局模式", "直连模式", "PAC模式"]
TUN_STACK_OPTIONS = ["system", "gvisor", "mixed"]
TUN_MTU_OPTIONS = ["9000", "1500", "1400", "1280"]
DEFAULT_TUN_SETTINGS = {
    "auto_route": True,
    "strict_route": False,
    "stack": "system",
    "mtu": 1400,
    "enable_ipv6": False,
    "route_exclude": "",
    "ipv4_address": "172.19.0.1/30",
    "interface_name": "Mobility0",
}

CORE_OPTIONS = ["自动", "Xray", "sing-box", "Mihomo"]
CORE_PROTOCOLS = ["vmess", "vless", "trojan", "shadowsocks", "socks", "http", "hysteria2", "tuic", "masque"]
# 默认「自动」：仅在选自动时由软件推荐；用户指定 Xray/sing-box/Mihomo 则严格使用
DEFAULT_CORE_MAP = {p: "自动" for p in CORE_PROTOCOLS}
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

APP_VERSION = "0.25.4"
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



def wait_local_port(port: int, host: str = "127.0.0.1", timeout: float = 8.0) -> bool:
    """等待本地端口可连接（用于确认 Xray SOCKS 已就绪再拉 TUN）。"""
    import socket
    deadline = time.time() + max(0.5, float(timeout))
    while time.time() < deadline:
        try:
            with socket.create_connection((host, int(port)), 0.4):
                return True
        except Exception:
            time.sleep(0.15)
    return False

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
        if not path.exists() or path.stat().st_size < 1000:
            return "未安装"
    except Exception:
        return "未安装"
    hint = (name_hint or path.name or "").lower()
    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        arg_lists = [
            [str(path), "-v"],
            [str(path), "version"],
            [str(path), "-version"],
            [str(path), "--version"],
        ]
        for args in arg_lists:
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=6, creationflags=flags)
                out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
                if not out:
                    continue
                if "mihomo" in hint or "clash" in hint:
                    patterns = [
                        r"(?:Mihomo|Clash(?:\s*Meta)?)[^0-9\n]*v?([0-9]+\.[0-9]+\.[0-9]+(?:-[\w.]+)?)",
                        r"\bv([0-9]+\.[0-9]+\.[0-9]+)\b",
                        r"\b([0-9]+\.[0-9]+\.[0-9]+)\b",
                    ]
                elif "sing" in hint:
                    patterns = [
                        r"version\s+([0-9]+\.[0-9]+\.[0-9]+)",
                        r"sing-box[^0-9\n]*([0-9]+\.[0-9]+\.[0-9]+)",
                        r"\b([0-9]+\.[0-9]+\.[0-9]+)\b",
                    ]
                else:
                    patterns = [
                        r"Xray\s+([0-9.]+)",
                        r"(?:Mihomo|Clash(?:\s*Meta)?)[^0-9\n]*v?([0-9]+\.[0-9]+\.[0-9]+)",
                        r"version\s+([0-9]+\.[0-9]+\.[0-9]+)",
                        r"\b([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)\b",
                    ]
                for pat in patterns:
                    m = re.search(pat, out, re.I)
                    if m and m.group(1) and m.group(1) not in (".", "0", "0.0"):
                        return m.group(1)
            except Exception:
                continue
    except Exception:
        pass
    return "未知"



def fetch_github_latest_tag(repo: str) -> str:
    """从 GitHub releases/latest 取 tag_name。"""
    try:
        api = "https://api.github.com/repos/%s/releases/latest" % repo
        r = requests.get(api, timeout=20, headers={"User-Agent": "Mobility"})
        r.raise_for_status()
        tag = (r.json() or {}).get("tag_name") or ""
        return str(tag).lstrip("vV").strip()
    except Exception:
        return ""


def fetch_xray_latest_version() -> str:
    return fetch_github_latest_tag("XTLS/Xray-core")


def fetch_singbox_latest_version() -> str:
    return fetch_github_latest_tag("SagerNet/sing-box")


def fetch_mihomo_latest_version() -> str:
    return fetch_github_latest_tag("MetaCubeX/mihomo")

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



def parse_hysteria2(link: str) -> dict | None:
    """解析 hysteria2:// 或 hy2:// 链接。"""
    try:
        from urllib.parse import urlparse, parse_qs, unquote
        raw = link.strip()
        if raw.startswith("hy2://"):
            raw = "hysteria2://" + raw[6:]
        u = urlparse(raw)
        host = u.hostname
        port = u.port or 443
        if not host:
            return None
        password = unquote(u.username or "")
        q = {k: (v[0] if v else "") for k, v in parse_qs(u.query).items()}
        name = unquote(u.fragment) if u.fragment else ("%s:%s" % (host, port))
        sni = q.get("sni") or q.get("peer") or host
        insecure = str(q.get("insecure") or q.get("allowInsecure") or "0") in ("1", "true", "True")
        obfs = q.get("obfs") or ""
        obfs_password = q.get("obfs-password") or q.get("obfs_password") or ""
        return {
            "protocol": "hysteria2",
            "name": name or host,
            "address": host,
            "port": int(port),
            "password": password,
            "sni": sni,
            "insecure": insecure,
            "obfs": obfs,
            "obfs_password": obfs_password,
            "network": "hysteria2",
            "raw": link.strip(),
        }
    except Exception:
        return None


def parse_tuic(link: str) -> dict | None:
    """解析 tuic:// 链接。"""
    try:
        from urllib.parse import urlparse, parse_qs, unquote
        u = urlparse(link.strip())
        host = u.hostname
        port = u.port or 443
        if not host:
            return None
        uuid = unquote(u.username or "")
        password = unquote(u.password or "")
        q = {k: (v[0] if v else "") for k, v in parse_qs(u.query).items()}
        name = unquote(u.fragment) if u.fragment else ("%s:%s" % (host, port))
        sni = q.get("sni") or host
        return {
            "protocol": "tuic",
            "name": name or host,
            "address": host,
            "port": int(port),
            "uuid": uuid,
            "password": password,
            "sni": sni,
            "congestion_control": q.get("congestion_control") or q.get("cc") or "bbr",
            "udp_relay_mode": q.get("udp_relay_mode") or "native",
            "alpn": q.get("alpn") or "h3",
            "allow_insecure": str(q.get("allow_insecure") or q.get("insecure") or "0") in ("1", "true", "True"),
            "network": "tuic",
            "raw": link.strip(),
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
    if link.startswith("hysteria2://") or link.startswith("hy2://"):
        return parse_hysteria2(link)
    if link.startswith("tuic://"):
        return parse_tuic(link)
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
        if not line.startswith(("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
            try:
                inner = b64_decode(line).strip()
                if inner.startswith(("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
                    line = inner
            except Exception:
                continue
        node = parse_link(line)
        if node and node.get("address"):
            nodes.append(node)
    return nodes



def _safe_yaml_unquote(s: str) -> str:
    s = (s or "").strip()
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s


def parse_clash_proxies(text: str) -> list:
    """轻量解析 Clash / Mihomo YAML 的 proxies（含 masque）。"""
    nodes = []
    if not text:
        return nodes
    import re as _re
    # 只取 proxies: 段，避免 proxy-groups 干扰
    section = text
    msec = _re.search(r"(?m)^proxies:\s*\n", text)
    if msec:
        start = msec.end()
        # 直到下一个顶层键（无缩进且以 word: 开头）
        mend = _re.search(r"(?m)^[A-Za-z0-9_-]+:\s*$", text[start:])
        section = text[start: start + mend.start()] if mend else text[start:]
    elif "type:" not in text:
        return nodes

    blocks = _re.split(r"\n(?=\s*-\s+(?:name:|\{))", "\n" + section)
    if len(blocks) <= 1:
        blocks = _re.split(r"\n\s*-\s+", "\n" + section)
    for block in blocks:
        if "type:" not in block and "type :" not in block:
            continue
        fields = {}
        for line in block.splitlines():
            raw = line.rstrip()
            if not raw.strip() or raw.strip().startswith("#"):
                continue
            # 去掉列表前缀
            line = raw.strip()
            if line.startswith("- "):
                line = line[2:].strip()
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip().lower()
            v = _safe_yaml_unquote(v.strip())
            # 简单数组 dns: [ a, b ]
            if v.startswith("[") and v.endswith("]"):
                v = v[1:-1]
            if k:
                fields[k] = v
        typ = (fields.get("type") or "").lower()
        server = fields.get("server") or fields.get("address") or ""
        port = fields.get("port") or ""
        name = fields.get("name") or server or typ or "clash"
        if not server or not port:
            continue
        try:
            port_i = int(float(str(port).split()[0]))
        except Exception:
            continue
        node = None
        if typ == "trojan":
            node = {"protocol": "trojan", "name": name, "address": server, "port": port_i,
                    "password": fields.get("password") or "",
                    "sni": fields.get("sni") or fields.get("servername") or server,
                    "network": (fields.get("network") or "tcp").lower()}
        elif typ == "vmess":
            node = {"protocol": "vmess", "name": name, "address": server, "port": port_i,
                    "uuid": fields.get("uuid") or fields.get("id") or "",
                    "alterId": int(fields.get("alterid") or fields.get("aid") or 0),
                    "security": fields.get("cipher") or fields.get("security") or "auto",
                    "network": (fields.get("network") or "tcp").lower(),
                    "path": fields.get("path") or "", "host": fields.get("host") or "",
                    "tls": "tls" if str(fields.get("tls")).lower() in ("true", "tls", "1") else ""}
        elif typ == "vless":
            node = {"protocol": "vless", "name": name, "address": server, "port": port_i,
                    "uuid": fields.get("uuid") or fields.get("id") or "",
                    "flow": fields.get("flow") or "",
                    "security": fields.get("security") or "tls",
                    "network": (fields.get("network") or "tcp").lower(),
                    "path": fields.get("path") or "", "host": fields.get("host") or "",
                    "sni": fields.get("servername") or fields.get("sni") or "",
                    "pbk": fields.get("public-key") or fields.get("pbk") or "",
                    "sid": fields.get("short-id") or fields.get("sid") or "",
                    "fp": fields.get("client-fingerprint") or fields.get("fp") or "chrome"}
        elif typ in ("ss", "shadowsocks"):
            node = {"protocol": "shadowsocks", "name": name, "address": server, "port": port_i,
                    "method": fields.get("cipher") or fields.get("method") or "aes-256-gcm",
                    "password": fields.get("password") or ""}
        elif typ in ("hysteria2", "hy2"):
            node = {"protocol": "hysteria2", "name": name, "address": server, "port": port_i,
                    "password": fields.get("password") or fields.get("auth") or "",
                    "sni": fields.get("sni") or server,
                    "insecure": str(fields.get("skip-cert-verify")).lower() in ("true", "1")}
        elif typ == "tuic":
            node = {"protocol": "tuic", "name": name, "address": server, "port": port_i,
                    "uuid": fields.get("uuid") or "", "password": fields.get("password") or "",
                    "sni": fields.get("sni") or server,
                    "congestion_control": fields.get("congestion-controller") or fields.get("congestion_controller") or "bbr"}
        elif typ == "masque":
            # Cloudflare MASQUE：仅 Mihomo/Clash Meta 可跑，先导入节点供选择
            node = {
                "protocol": "masque",
                "name": name,
                "address": server,
                "port": port_i,
                "private_key": fields.get("private-key") or fields.get("private_key") or "",
                "public_key": fields.get("public-key") or fields.get("public_key") or "",
                "ip": fields.get("ip") or "",
                "ipv6": fields.get("ipv6") or "",
                "uri": fields.get("uri") or "",
                "mtu": fields.get("mtu") or "1280",
                "sni": fields.get("sni") or "www.cloudflareaccess.com",
                "congestion_controller": fields.get("congestion-controller") or "bbr",
                "dns": fields.get("dns") or "",
                "udp": True,
            }
        if node:
            nodes.append(node)
    return nodes



def parse_json_nodes(text: str) -> list:
    nodes = []
    try:
        data = json.loads(text)
    except Exception:
        return nodes
    outs = []
    if isinstance(data, dict):
        if isinstance(data.get("outbounds"), list):
            outs = data["outbounds"]
        elif isinstance(data.get("proxies"), list):
            outs = data["proxies"]
        elif data.get("type") and data.get("server"):
            outs = [data]
    elif isinstance(data, list):
        outs = data
    for o in outs:
        if not isinstance(o, dict):
            continue
        typ = (o.get("type") or o.get("protocol") or "").lower()
        if typ in ("direct", "block", "dns", "freedom", "blackhole", "api", "selector", "urltest"):
            continue
        server = o.get("server") or o.get("address") or ""
        port = o.get("server_port") or o.get("port") or 0
        name = o.get("tag") or o.get("name") or server or typ
        if not server or not port:
            try:
                vnext = (o.get("settings") or {}).get("vnext") or []
                if vnext:
                    server = vnext[0].get("address")
                    port = vnext[0].get("port")
                    users = vnext[0].get("users") or [{}]
                    uuid = users[0].get("id") or ""
                    proto = (o.get("protocol") or typ or "vmess").lower()
                    nodes.append({"protocol": proto, "name": str(name), "address": server,
                                  "port": int(port), "uuid": uuid, "network": "tcp"})
            except Exception:
                pass
            continue
        try:
            port = int(port)
        except Exception:
            continue
        proto = "shadowsocks" if typ in ("ss", "shadowsocks") else typ
        if proto == "hy2":
            proto = "hysteria2"
        if proto not in ("hysteria2", "tuic", "trojan", "vmess", "vless", "shadowsocks"):
            continue
        tls = o.get("tls") if isinstance(o.get("tls"), dict) else {}
        nodes.append({
            "protocol": proto, "name": str(name), "address": server, "port": port,
            "password": o.get("password") or "", "uuid": o.get("uuid") or "",
            "method": o.get("method") or o.get("cipher") or "",
            "sni": tls.get("server_name") or o.get("sni") or server,
            "flow": o.get("flow") or "",
        })
    return nodes


def parse_surge_like(text: str) -> list:
    nodes = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("[") or "=" not in line:
            continue
        name, rest = line.split("=", 1)
        name = name.strip()
        parts = [p.strip() for p in rest.split(",")]
        if len(parts) < 3:
            continue
        typ = parts[0].lower()
        server = parts[1]
        try:
            port = int(parts[2])
        except Exception:
            continue
        kv = {}
        for p in parts[3:]:
            if "=" in p:
                k, v = p.split("=", 1)
                kv[k.strip().lower()] = v.strip()
        if typ == "trojan":
            nodes.append({"protocol": "trojan", "name": name, "address": server, "port": port,
                          "password": kv.get("password") or "", "sni": kv.get("sni") or server})
        elif typ in ("ss", "shadowsocks"):
            nodes.append({"protocol": "shadowsocks", "name": name, "address": server, "port": port,
                          "method": kv.get("encrypt-method") or kv.get("method") or "aes-256-gcm",
                          "password": kv.get("password") or ""})
        elif typ == "vmess":
            nodes.append({"protocol": "vmess", "name": name, "address": server, "port": port,
                          "uuid": kv.get("uuid") or kv.get("password") or "",
                          "alterId": int(kv.get("alterid") or 0), "network": kv.get("obfs") or "tcp"})
        elif typ == "vless":
            nodes.append({"protocol": "vless", "name": name, "address": server, "port": port,
                          "uuid": kv.get("uuid") or "", "sni": kv.get("sni") or server})
        elif typ in ("hysteria2", "hy2"):
            nodes.append({"protocol": "hysteria2", "name": name, "address": server, "port": port,
                          "password": kv.get("password") or "", "sni": kv.get("sni") or server})
    return nodes



def normalize_group_name(name: str, *, local: bool = False) -> str:
    """统一分组显示名：在线：/本地：前缀。"""
    g = (name or "").strip() or ("本地导入" if local else "订阅")
    if g.startswith("本地:") or g.startswith("本地："):
        return "本地：" + g.split(":", 1)[-1].split("：", 1)[-1].strip()
    if g.startswith("在线:") or g.startswith("在线："):
        return "在线：" + g.split(":", 1)[-1].split("：", 1)[-1].strip()
    if local or g.startswith("本地"):
        base = g[2:].lstrip(":：").strip() if g.startswith("本地") else g
        return "本地：" + (base or "导入")
    return "在线：" + g


def parse_nodes_any(text: str) -> list:
    """统一入口：URI 订阅 / Clash / JSON / Surge 等。"""
    text = (text or "").strip()
    if not text:
        return []
    # Clash/Mihomo YAML 优先（避免被 base64/URI 误判）
    if "proxies:" in text and ("type:" in text or "type :" in text):
        nodes = parse_clash_proxies(text)
        if nodes:
            return nodes
    nodes = []
    try:
        nodes = parse_subscription_content(text)
    except Exception:
        nodes = []
    if nodes:
        return nodes
    if text.startswith("{") or text.startswith("["):
        nodes = parse_json_nodes(text)
        if nodes:
            return nodes
    if "type:" in text and "server:" in text:
        nodes = parse_clash_proxies(text)
        if nodes:
            return nodes
    nodes = parse_surge_like(text)
    if nodes:
        return nodes
    try:
        i = text.find("{")
        if i >= 0:
            nodes = parse_json_nodes(text[i:])
    except Exception:
        pass
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
    if not node or not isinstance(node, dict):
        return None
    protocol = (node.get("protocol") or "").lower()

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


def node_key(node: dict) -> str:
    """节点唯一键，用于高亮/选中（避免同名同延迟标签撞车）。"""
    if not isinstance(node, dict):
        return ""
    return "%s|%s|%s|%s" % (
        node.get("protocol") or "",
        node.get("address") or "",
        node.get("port") or "",
        node.get("name") or "",
    )


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
        self.logs_dir = self.base_dir / "logs"
        self.logs_dir.mkdir(exist_ok=True)
        self.log_file = self.logs_dir / "xray.log"
        self.app_log_file = self.logs_dir / "mobility.log"
        self.settings_path = self.base_dir / "Subscribe.json"
        self.log_level = "调试"

        self.xray_process = None
        self.singbox_process = None
        self.mihomo_process = None
        self.is_running = False
        self.is_testing = False
        self.nodes: list[dict] = []
        self.current_node = None
        self.subscription_url = ""
        self.subscriptions = []
        self.test_timeout = DEFAULT_TEST_TIMEOUT
        self.connectivity_urls = list(DEFAULT_CONNECTIVITY_URLS)
        self.group_nodes_by_sub = True
        self.rule_set_urls = []
        self._drag_data = None
        self._pending_node = None
        self._pending_label = None
        self._node_row_meta = []
        self._xray_ver = "未知"
        self.tun_enabled = False
        self.tun_settings = dict(DEFAULT_TUN_SETTINGS)
        self.routing_extra_direct = ""
        self.routing_extra_proxy = ""
        self.routing_extra_block = ""
        self.proxy_core = "Xray"
        self.core_map = dict(DEFAULT_CORE_MAP)
        self.live_stats_enabled = True  # 实时网速/内存，默认开启
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
        self._proxy_backup = None  # 启动代理前的系统代理，退出时还原给 v2rayN 等
        self._proxy_owned = False
        self._winhttp_backup = None
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

        try:
            ctk.set_widget_scaling(1.0)
            ctk.set_window_scaling(1.0)
        except Exception:
            pass
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        try:
            self.update_idletasks()
        except Exception:
            pass
        try:
            self.bind("<Return>", self.confirm_pending_node)
            self.bind("<KP_Enter>", self.confirm_pending_node)
        except Exception:
            pass
        self.after(50, self.startup)

    def create_widgets(self):
        # 窗口图标
        try:
            ico = self.icons_dir / "mobility.ico"
            if ico.exists():
                self.iconbitmap(str(ico))
        except Exception:
            pass

        # ===== 顶栏：仅状态信息 =====
        top = ctk.CTkFrame(self, fg_color=("gray90", "gray17"), corner_radius=0, height=48)
        top.pack(fill="x")
        top.pack_propagate(False)

        self.title_label = ctk.CTkLabel(
            top, text="Mobility", font=("Microsoft YaHei UI", 18, "bold"),
            text_color=("#2563EB", "#60A5FA"))
        self.title_label.pack(side="left", padx=(16, 10))
        self.app_ver_label = ctk.CTkLabel(
            top, text=f"v{APP_VERSION}", font=("Microsoft YaHei UI", 12),
            text_color=("gray40", "gray60"))
        self.app_ver_label.pack(side="left", padx=(4, 10))
        self.status_label = ctk.CTkLabel(top, text="未运行", font=("Microsoft YaHei UI", 14, "bold"), text_color=("#DC2626", "#F87171"))
        self.status_label.pack(side="left", padx=8)
        self.version_label = ctk.CTkLabel(
            top, text="",
            font=("Microsoft YaHei UI", 11), text_color=("gray45", "gray55")
        )
        self.version_label.pack(side="left", padx=(4, 8))
        self.current_label = ctk.CTkLabel(
            top, text="当前节点：无", font=("Microsoft YaHei UI", 12),
            text_color=("gray40", "gray60"), width=260, anchor="w"
        )
        self.current_label.pack(side="left", padx=4)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=8)

        # ===== 订阅区：URL 拉长到「加载」前，右侧两行右对齐 =====
        bar = ctk.CTkFrame(body, fg_color=("gray92", "gray18"), corner_radius=10)
        bar.pack(fill="x", pady=(0, 4))
        bar_inner = ctk.CTkFrame(bar, fg_color="transparent")
        bar_inner.pack(fill="x", padx=8, pady=6)

        # 第一行：订阅 + URL（伸展）+ 加载/菜单
        row1 = ctk.CTkFrame(bar_inner, fg_color="transparent")
        row1.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(row1, text="订阅", font=("Microsoft YaHei UI", 13, "bold")).pack(side="left")
        self.sub_select = ctk.CTkComboBox(
            row1, width=120, height=32, values=["（无订阅）"], state="readonly",
            command=self.on_sub_select
        )
        self.sub_select.set("（无订阅）")
        self.sub_select.pack(side="left", padx=(6, 4))
        # 右侧按钮先 pack，URL 再 fill 中间剩余空间，一直顶到「加载」前
        self.import_menu_btn = ctk.CTkButton(
            row1, text="导入 ▾", width=72, height=32, fg_color="#0EA5E9",
            command=self.open_import_menu
        )
        self.import_menu_btn.pack(side="right", padx=(2, 0))
        self.node_menu_btn = ctk.CTkButton(
            row1, text="节点工具 ▾", width=96, height=32, fg_color="#7C3AED",
            command=self.open_node_menu
        )
        self.node_menu_btn.pack(side="right", padx=2)
        self.sub_menu_btn = ctk.CTkButton(
            row1, text="订阅管理 ▾", width=96, height=32, fg_color="#0D9488",
            command=self.open_sub_menu
        )
        self.sub_menu_btn.pack(side="right", padx=2)
        self.load_btn = ctk.CTkButton(row1, text="加载", width=60, height=32, command=self.load_nodes_thread)
        self.load_btn.pack(side="right", padx=2)
        self.entry = ctk.CTkEntry(row1, height=32, placeholder_text="订阅 URL 或节点链接")
        self.entry.pack(side="left", fill="x", expand=True, padx=(4, 8))

        # 第二行：并发/模式/启动/停止 右对齐，停止与导入右边缘对齐
        row2 = ctk.CTkFrame(bar_inner, fg_color="transparent")
        row2.pack(fill="x")
        right2 = ctk.CTkFrame(row2, fg_color="transparent")
        right2.pack(side="right")
        ctk.CTkLabel(right2, text="并发", font=("Microsoft YaHei UI", 12)).pack(side="left", padx=(4, 2))
        self.workers_combo = ctk.CTkComboBox(right2, width=72, height=30, values=TEST_WORKERS_OPTIONS, state="readonly")
        self.workers_combo.set(str(TEST_WORKERS_DEFAULT))
        self.workers_combo.pack(side="left", padx=2)
        ctk.CTkLabel(right2, text="模式", font=("Microsoft YaHei UI", 13)).pack(side="left", padx=(10, 2))
        self.mode_combo = ctk.CTkComboBox(
            right2, width=120, height=30, values=PROXY_MODES, state="readonly",
            command=self.on_mode_change, font=("Microsoft YaHei UI", 13),
        )
        self.mode_combo.set(PROXY_MODE_DEFAULT)
        self.mode_combo.pack(side="left", padx=(2, 10))
        self.start_btn = ctk.CTkButton(right2, text="启动", width=72, height=32, command=self.start_proxy_thread)
        self.start_btn.pack(side="left", padx=2)
        self.stop_btn = ctk.CTkButton(
            right2, text="停止", width=72, height=32,
            fg_color="#DC2626", hover_color="#B91C1C", command=self.stop_proxy
        )
        self.stop_btn.pack(side="left", padx=(2, 0))

        # 兼容旧引用
        self.add_sub_btn = self.sub_menu_btn
        self.del_sub_btn = self.sub_menu_btn
        self.rename_sub_btn = self.sub_menu_btn
        self.refresh_all_btn = self.sub_menu_btn
        self.clip_btn = self.import_menu_btn
        self.qr_btn = self.import_menu_btn
        self.show_qr_btn = self.import_menu_btn
        self.test_btn = self.node_menu_btn
        self.test_filter_btn = self.node_menu_btn
        self.best_btn = self.node_menu_btn
        self.copy_btn = self.node_menu_btn
        self.ping_btn = self.node_menu_btn
        self.move_up_btn = self.node_menu_btn
        self.move_down_btn = self.node_menu_btn

        # ===== 运行状态条（不再放启动/停止）=====
        stats = ctk.CTkFrame(body, fg_color=("gray90", "gray20"), corner_radius=8, height=48)
        stats.pack(fill="x", pady=(2, 6))
        stats.pack_propagate(False)

        self.live_stats_var = ctk.BooleanVar(value=True)
        self.live_stats_enabled = True
        self.live_stats_sw = ctk.CTkSwitch(
            stats, text="实时统计", variable=self.live_stats_var, width=90,
            command=self.on_live_stats_toggle
        )
        self.live_stats_sw.pack(side="right", padx=10)

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
        # TUN/路由 详细设置见下方按钮区，避免重复入口

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
        self.loglevel_combo.set("调试")
        self.loglevel_combo.pack(fill="x", padx=8)

        # 核心类型改为二级对话框
        self.core_proto_combos = {}

        # 域名分流已并入「路由设置」弹窗，避免与路由规则重复
        self.direct_entry = None
        self.proxy_entry = None

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

        self.tun_setting_btn = ctk.CTkButton(btn_box, text="TUN 设置", height=bh, command=self.open_tun_settings_dialog)
        self.tun_setting_btn.grid(row=1, column=0, sticky="ew", pady=3, padx=(0, 3))
        self.route_setting_btn = ctk.CTkButton(btn_box, text="路由设置", height=bh, command=self.open_routing_dialog)
        self.route_setting_btn.grid(row=1, column=1, sticky="ew", pady=3, padx=(3, 0))

        self.clear_log_btn = ctk.CTkButton(btn_box, text="清空日志", height=bh, command=self.clear_log)
        self.clear_log_btn.grid(row=2, column=0, sticky="ew", pady=3, padx=(0, 3))
        self.update_btn = ctk.CTkButton(btn_box, text="检查更新", height=bh, command=self.check_update_thread)
        self.update_btn.grid(row=2, column=1, sticky="ew", pady=3, padx=(3, 0))

        self.core_update_btn = ctk.CTkButton(btn_box, text="更新核心", height=bh, command=self.open_core_update_dialog)
        self.core_update_btn.grid(row=3, column=0, sticky="ew", pady=3, padx=(0, 3))
        self.geo_update_btn = ctk.CTkButton(btn_box, text="更新规则", height=bh, command=self.update_geo_thread)
        self.geo_update_btn.grid(row=3, column=1, sticky="ew", pady=3, padx=(3, 0))

        self.admin_btn = ctk.CTkButton(btn_box, text="管理员运行", height=bh, command=self.restart_as_admin)
        self.admin_btn.grid(row=4, column=0, sticky="ew", pady=3, padx=(0, 3))
        self.about_btn = ctk.CTkButton(btn_box, text="关于", height=bh, command=self.show_about)
        self.about_btn.grid(row=4, column=1, sticky="ew", pady=3, padx=(3, 0))

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
        self.log_box = ctk.CTkTextbox(log_frame, height=360, font=("Consolas", 11))
        self.log_box.pack(fill="x", pady=4)
        self._log_lines = []
        self._log_autoscroll = True
        try:
            self._setup_log_tags()
        except Exception:
            pass
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

    def _update_node_latency_labels(self):
        """测速后只更新按钮文字，不销毁重建列表。"""
        try:
            meta = getattr(self, "_node_row_meta", None) or []
            for item in meta:
                n = item.get("node")
                btn = item.get("btn")
                if not n or not btn:
                    continue
                try:
                    lb = node_label(n)
                except Exception:
                    lb = n.get("name") or "节点"
                n["_label"] = lb
                try:
                    btn.configure(text=lb)
                except Exception:
                    pass
            try:
                self._paint_node_buttons()
            except Exception:
                pass
        except Exception:
            try:
                self.refresh_node_list(keep_selection=True, resort=False)
            except Exception:
                pass

    def _paint_node_buttons(self):
        """只高亮：一个预选（蓝）+ 一个已确认（橙）；按节点唯一键匹配，不按显示文本。"""
        pend_key = None
        pn = getattr(self, "_pending_node", None)
        if isinstance(pn, dict):
            pend_key = node_key(pn)
        cur_key = None
        cn = getattr(self, "current_node", None)
        if isinstance(cn, dict):
            cur_key = node_key(cn)
        # 优先用 row_meta（带 node 引用）
        metas = getattr(self, "_node_row_meta", None) or []
        painted = set()
        for meta in metas:
            b = meta.get("btn")
            n = meta.get("node")
            if not b or not isinstance(n, dict):
                continue
            k = node_key(n)
            painted.add(id(b))
            try:
                if pend_key and k == pend_key:
                    b.configure(fg_color=("#2563EB", "#1D4ED8"), text_color="white")
                elif cur_key and k == cur_key:
                    b.configure(fg_color=("#EA580C", "#C2410C"), text_color="white")
                else:
                    b.configure(fg_color=("gray85", "gray25"), text_color=("gray10", "gray90"))
            except Exception:
                pass
        # 兼容无 meta 的按钮：全部置灰
        for b in getattr(self, "_node_buttons", []) or []:
            if id(b) in painted:
                continue
            try:
                b.configure(fg_color=("gray85", "gray25"), text_color=("gray10", "gray90"))
            except Exception:
                pass

    def on_node_button_click(self, node, btn):
        """左键预选节点：只改高亮，不整表刷新（避免卡顿）。"""
        if not isinstance(node, dict):
            return
        self._pending_node = node
        self._pending_label = node.get("_label") or node.get("name")
        self._pending_key = node_key(node)
        g = (node.get("_group") or node.get("group") or "").strip()
        if g:
            self._active_test_group = g
            try:
                self._paint_group_headers()
            except Exception:
                pass
        self._paint_node_buttons()

    def confirm_pending_node(self, event=None):
        """回车确认预选节点为当前唯一使用节点。"""
        node = getattr(self, "_pending_node", None)
        if not node:
            return "break"
        try:
            focus = self.focus_get()
            if focus is not None:
                cls = focus.__class__.__name__.lower()
                if "entry" in cls or "textbox" in cls or "text" in cls:
                    return None
        except Exception:
            pass
        # 确认后仅此一个为当前代理节点；同步测速分组到该节点所在组
        live = self.resolve_live_node(node) if hasattr(self, "resolve_live_node") else node
        if live:
            node = live
        self.current_node = node
        self._selected_label = node.get("_label") or node.get("name")
        self._pending_node = node
        self._pending_label = self._selected_label
        self._pending_key = node_key(node)
        g = (node.get("_group") or node.get("group") or "").strip()
        if g:
            self._active_test_group = g
        self._paint_node_buttons()
        try:
            self._paint_group_headers()
        except Exception:
            pass
        try:
            self.current_label.configure(text=self._short_node_text(node))
        except Exception:
            pass
        try:
            self.log("已确认使用节点：%s%s" % (node.get("name"), ("（分组：%s）" % g) if g else ""))
        except Exception:
            pass
        if g:
            try:
                before = set(getattr(self, "_collapsed_groups", set()) or set())
                self._focus_group_only(g)
                after = set(getattr(self, "_collapsed_groups", set()) or set())
                if before != after:
                    self.refresh_node_list(keep_selection=True, resort=False)
                else:
                    self._paint_group_headers()
                    self._paint_node_buttons()
            except Exception:
                pass
        try:
            self.save_settings()
        except Exception:
            pass
        # 运行中换节点：按新节点协议自动匹配核心并热重启
        if getattr(self, "is_running", False):
            try:
                self.log("检测到代理运行中，正在按新节点自动切换核心并重启…")
            except Exception:
                pass
            Thread(target=self._restart_proxy_quick, daemon=True).start()
        return "break"

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
            text="为每种协议指定核心。选「自动」才由软件推荐；\n选 Xray / sing-box / Mihomo 则严格按你的选择启动。",
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
            "hysteria2": "Hysteria2",
            "tuic": "TUIC",
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
                cb.set("自动")

        def do_ok():
            if not getattr(self, "core_map", None):
                self.core_map = dict(DEFAULT_CORE_MAP)
            for proto, cb in combos.items():
                val = (cb.get() or "自动").strip()
                self.core_map[proto] = val if val in CORE_OPTIONS else "自动"
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
        self.core_map[proto] = (value or "自动").strip()
        self.save_settings()
        self.log(f"协议 {proto} → 核心 {self.core_map[proto]}")
        try:
            self.refresh_version_label()
        except Exception:
            pass

    def resolve_core_for_node(self, node: dict) -> str:
        """按用户在「核心设置」中的映射选择核心。
        - 指定 Xray / sing-box / Mihomo：严格使用，不再改判
        - 选择「自动」：再按协议做推荐
        """
        proto = (node.get("protocol") or "").lower()
        if proto == "ss":
            proto = "shadowsocks"
        cmap = getattr(self, "core_map", None) or DEFAULT_CORE_MAP
        chosen = str(cmap.get(proto) or "自动").strip()
        # Hysteria2 / TUIC 仅 sing-box 可出站
        if proto in ("hysteria", "hysteria2", "hy2", "tuic"):
            return "sing-box"
        if proto in ("masque", "wireguard"):
            return "Mihomo"
        if chosen in ("Xray", "sing-box", "Mihomo"):
            return chosen
        if proto in ("wireguard",):
            return "sing-box"
        return "Xray"

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
            # 无论是否已在运行，都先干净停止再以 TUN 配置启动，避免半开状态
            try:
                if self.is_running:
                    self.stop_proxy()
            except Exception:
                pass
            self.after(600, self.start_proxy_thread)
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



    def _popup_action_menu(self, title: str, actions: list, anchor_widget=None):
        """轻量二级菜单：actions = [(显示名, 回调), ...]
        - 不用 FocusOut（Windows 上会闪退）
        - 支持 Esc / 关闭按钮 / 点击主窗口空白处收起
        """
        try:
            old = getattr(self, "_action_menu_win", None)
            if old is not None and old.winfo_exists():
                old.destroy()
        except Exception:
            pass
        try:
            if getattr(self, "_menu_outside_bound", False):
                self.unbind("<Button-1>")
                self._menu_outside_bound = False
        except Exception:
            pass

        win = ctk.CTkToplevel(self)
        self._action_menu_win = win
        win.title(title)
        win.resizable(False, False)
        try:
            win.attributes("-topmost", True)
        except Exception:
            pass
        try:
            win.transient(self)
        except Exception:
            pass
        try:
            ico = self.icons_dir / "mobility.ico"
            if ico.exists():
                win.iconbitmap(str(ico))
            else:
                for name in ("logo-main.png", "logo-main-32.png"):
                    png = self.icons_dir / name
                    if png.exists():
                        try:
                            from PIL import Image, ImageTk
                            img = Image.open(png)
                            win._menu_icon = ImageTk.PhotoImage(img)
                            win.iconphoto(True, win._menu_icon)
                        except Exception:
                            pass
                        break
        except Exception:
            pass

        try:
            actions = sorted(list(actions or []), key=lambda a: (len(str(a[0] or "")), str(a[0] or "")))
        except Exception:
            actions = list(actions or [])
        max_len = max((len(str(a[0] or "")) for a in actions), default=8)
        w = max(220, min(360, 48 + max_len * 16))
        h = 52 + 40 * max(1, len(actions))
        try:
            if anchor_widget is not None:
                anchor_widget.update_idletasks()
                ax = anchor_widget.winfo_rootx()
                ay = anchor_widget.winfo_rooty() + anchor_widget.winfo_height() + 2
                win.geometry("%dx%d+%d+%d" % (w, h, ax, ay))
            else:
                win.geometry("%dx%d" % (w, h))
        except Exception:
            win.geometry("%dx%d" % (w, h))

        head = ctk.CTkFrame(win, fg_color=("#E2E8F0", "#0F172A"), corner_radius=0, height=36)
        head.pack(fill="x")
        head.pack_propagate(False)
        ctk.CTkLabel(head, text=title, font=("Microsoft YaHei UI", 13, "bold"),
                     text_color=("#0F172A", "#F8FAFC")).pack(side="left", padx=12, pady=6)
        box = ctk.CTkFrame(win, fg_color="transparent")
        box.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        def dismiss():
            try:
                if getattr(self, "_menu_outside_bound", False):
                    self.unbind("<Button-1>")
                    self._menu_outside_bound = False
            except Exception:
                pass
            try:
                if getattr(self, "_action_menu_win", None) is win:
                    self._action_menu_win = None
                if win.winfo_exists():
                    win.destroy()
            except Exception:
                pass

        def make_cmd(fn):
            def _run():
                dismiss()
                try:
                    fn()
                except Exception as e:
                    self.log("%s 失败：%s" % (title, e))
            return _run

        try:
            actions = sorted(list(actions or []), key=lambda a: (len(str(a[0] or "")), str(a[0] or "")))
        except Exception:
            actions = list(actions or [])
        for label, fn in actions:
            ctk.CTkButton(
                box, text="  " + str(label), height=34, anchor="w",
                fg_color=("#F1F5F9", "#1E293B"), text_color=("#0F172A", "#E2E8F0"),
                hover_color=("#BFDBFE", "#1D4ED8"),
                font=("Microsoft YaHei UI", 12),
                corner_radius=8,
                command=make_cmd(fn),
            ).pack(fill="x", pady=3)

        def on_outside(event):
            try:
                if not win.winfo_exists():
                    dismiss()
                    return
                x, y = int(event.x_root), int(event.y_root)
                wx, wy = int(win.winfo_rootx()), int(win.winfo_rooty())
                ww, wh = int(win.winfo_width()), int(win.winfo_height())
                if wx <= x <= wx + ww and wy <= y <= wy + wh:
                    return
                dismiss()
            except Exception:
                dismiss()

        def enable_outside():
            try:
                self.bind("<Button-1>", on_outside, add="+")
                self._menu_outside_bound = True
            except Exception:
                pass

        win.after(220, enable_outside)
        win.bind("<Escape>", lambda e: dismiss())
        try:
            win.protocol("WM_DELETE_WINDOW", dismiss)
        except Exception:
            pass
        try:
            win.lift()
            win.focus_force()
        except Exception:
            pass

    def open_sub_menu(self):
        self._popup_action_menu(
            "订阅管理",
            [
                ("更新当前订阅", self.refresh_current_sub_thread),
                ("添加当前链接到订阅", self.add_subscription),
                ("删除当前订阅", self.remove_subscription),
                ("重命名当前订阅", self.rename_subscription),
                ("更新全部订阅", self.refresh_all_subs_thread),
            ],
            getattr(self, "sub_menu_btn", None),
        )

    def rename_node_group_dialog(self):
        """重命名当前选中节点所在分组（支持本地/在线）。"""
        node = getattr(self, "current_node", None) or getattr(self, "_pending_node", None)
        if not node:
            for n in (self.nodes or []):
                if isinstance(n, dict):
                    node = n
                    break
        if not node:
            self.log("请先选中一个节点再重命名分组")
            return
        old_g = (node.get("_group") or node.get("group") or "").strip() or "未分组"
        try:
            import tkinter.simpledialog as simpledialog
            base = old_g
            for pref in ("在线：", "在线:", "本地：", "本地:"):
                if base.startswith(pref):
                    base = base[len(pref):]
                    break
            new_base = simpledialog.askstring(
                "重命名分组",
                "当前分组：%s\n请输入新名称（自动保留 在线/本地 前缀）：" % old_g,
                initialvalue=base,
                parent=self,
            )
        except Exception as e:
            self.log("无法打开改名对话框：%s" % e)
            return
        if not new_base or not str(new_base).strip():
            return
        is_local = old_g.startswith("本地") or bool(node.get("from_local"))
        new_g = normalize_group_name(str(new_base).strip(), local=is_local)
        cnt = 0
        for n in self.nodes or []:
            if not isinstance(n, dict):
                continue
            g = (n.get("_group") or n.get("group") or "").strip()
            if g == old_g:
                n["_group"] = new_g
                n["group"] = new_g
                cnt += 1
        self.group_nodes_by_sub = True
        self.refresh_node_list(keep_selection=True)
        self.save_settings()
        self.log("分组已改名：%s → %s（%s 个节点）" % (old_g, new_g, cnt))

    def open_node_menu(self):
        self._popup_action_menu(
            "节点工具",
            [
                ("节点上移", lambda: self.move_selected_node(-1)),
                ("节点下移", lambda: self.move_selected_node(1)),
                ("测速全部", self.test_all_thread),
                ("连接诊断", self.open_diagnostics_dialog),
                ("重命名分组", self.rename_node_group_dialog),
                ("选择最快节点", self.select_best),
                ("复制当前节点", self.copy_selected_node),
                ("删除当前节点", self.delete_selected_node),
                ("连通性测试", self.connectivity_test_thread),
                ("测速所选分组", self.test_current_group_thread),
                ("测速筛选结果", self.test_filtered_thread),
                ("测速/连通性设置", self.open_speed_settings_dialog),
            ],
            getattr(self, "node_menu_btn", None),
        )


    def refresh_current_sub_thread(self):
        Thread(target=self.refresh_current_sub, daemon=True).start()

    def refresh_current_sub(self):
        """只更新当前选中的订阅（或输入框中的 URL）。"""
        url = ""
        try:
            url = (self.entry.get() or "").strip()
        except Exception:
            url = ""
        if not url.startswith(("http://", "https://")):
            # 从当前订阅选择回填
            name = ""
            try:
                name = self.sub_select.get()
            except Exception:
                name = ""
            for s in self.subscriptions or []:
                n = s.get("name") or (s.get("url") or "")[:24]
                if n == name and s.get("url"):
                    url = s.get("url")
                    try:
                        self.entry.delete(0, "end")
                        self.entry.insert(0, url)
                    except Exception:
                        pass
                    break
        if not url.startswith(("http://", "https://")):
            self.log("请先选择订阅或在输入框填入订阅 URL")
            return
        self.subscription_url = url
        self.log("正在更新当前订阅…")
        self.load_nodes()

    def delete_selected_node(self):
        node = None
        try:
            node = self.get_selected_node()
        except Exception:
            node = getattr(self, "current_node", None)
        if not node:
            self.log("请先选择要删除的节点")
            return
        try:
            idx = self.nodes.index(node)
        except ValueError:
            lab = node.get("_label") or node.get("name")
            idx = next(
                (i for i, n in enumerate(self.nodes or [])
                 if (n.get("_label") or n.get("name")) == lab),
                -1,
            )
        if idx < 0:
            self.log("未在列表中找到该节点")
            return
        removed = self.nodes.pop(idx)
        name = removed.get("name") or removed.get("_label") or "节点"
        if self.current_node is removed or (
            self.current_node
            and (self.current_node.get("_label") or self.current_node.get("name"))
            == (removed.get("_label") or removed.get("name"))
        ):
            self.current_node = self.nodes[idx] if idx < len(self.nodes) else (
                self.nodes[idx - 1] if self.nodes else None
            )
            self._selected_label = (
                self.current_node.get("_label") if self.current_node else None
            )
        self.refresh_node_list(keep_selection=True, resort=False)
        self.save_settings()
        try:
            if self.current_node:
                self.current_label.configure(text=self._short_node_text(self.current_node))
            else:
                self.current_label.configure(text="当前节点：无")
        except Exception:
            pass
        self.log("已删除节点：%s" % name)

    def open_import_menu(self):
        self._popup_action_menu(
            "导入 / 二维码",
            [
                ("从剪贴板导入", self.import_clipboard_thread),
                ("从本地文件导入", self.import_local_nodes_dialog),
                ("扫描屏幕二维码", self.scan_screen_qr_thread),
                ("生成节点二维码", self.show_node_qr),
                ("导出节点与设置", self.export_config_dialog),
                ("导入节点与设置", self.import_config_dialog),
            ],

            getattr(self, "import_menu_btn", None),
        )

    def open_tun_settings_dialog(self):
        """TUN 模式设置（参考 v2rayN）。"""
        win = ctk.CTkToplevel(self)
        win.title("TUN 模式设置")
        win.geometry("520x520")
        win.transient(self)
        try:
            win.grab_set()
        except Exception:
            pass

        ts = dict(DEFAULT_TUN_SETTINGS)
        ts.update(getattr(self, "tun_settings", {}) or {})

        ctk.CTkLabel(win, text="TUN 模式设置", font=("Microsoft YaHei UI", 16, "bold")).pack(
            anchor="w", padx=20, pady=(16, 8)
        )
        form = ctk.CTkFrame(win, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=20)

        def switch_row(label, key):
            fr = ctk.CTkFrame(form, fg_color="transparent")
            fr.pack(fill="x", pady=6)
            ctk.CTkLabel(fr, text=label, width=120, anchor="w").pack(side="left")
            var = ctk.BooleanVar(value=bool(ts.get(key)))
            sw = ctk.CTkSwitch(fr, text="", variable=var)
            sw.pack(side="right")
            return var

        def combo_row(label, values, current):
            fr = ctk.CTkFrame(form, fg_color="transparent")
            fr.pack(fill="x", pady=6)
            ctk.CTkLabel(fr, text=label, width=120, anchor="w").pack(side="left")
            cb = ctk.CTkComboBox(fr, width=160, values=values, state="readonly")
            cb.set(str(current if current is not None else values[0]))
            cb.pack(side="right")
            return cb

        def entry_row(label, current, placeholder=""):
            fr = ctk.CTkFrame(form, fg_color="transparent")
            fr.pack(fill="x", pady=6)
            ctk.CTkLabel(fr, text=label, width=120, anchor="w").pack(side="left")
            ent = ctk.CTkEntry(fr, width=260, placeholder_text=placeholder)
            ent.insert(0, str(current or ""))
            ent.pack(side="right", fill="x", expand=True, padx=(8, 0))
            return ent

        var_auto = switch_row("自动路由", "auto_route")
        var_strict = switch_row("严格路由", "strict_route")
        cb_stack = combo_row("协议栈", TUN_STACK_OPTIONS, ts.get("stack", "system"))
        cb_mtu = combo_row("MTU", TUN_MTU_OPTIONS, ts.get("mtu", 1400))
        var_v6 = switch_row("启用 IPv6", "enable_ipv6")
        ent_exclude = entry_row("路由排除地址", ts.get("route_exclude", ""), "逗号分隔")
        ent_v4 = entry_row("IPv4 地址", ts.get("ipv4_address", "172.19.0.1/30"), "172.19.0.1/30")
        ent_if = entry_row("接口名称", ts.get("interface_name", "Mobility0"), "Mobility0")

        ctk.CTkLabel(
            form,
            text="自动路由=接管系统默认路由；严格路由更激进。修改后需重新启动代理生效。",
            font=("Microsoft YaHei UI", 11),
            text_color=("gray40", "gray60"),
            justify="left",
        ).pack(anchor="w", pady=(10, 4))

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(side="bottom", fill="x", padx=20, pady=16)

        def do_reset():
            var_auto.set(True)
            var_strict.set(False)
            cb_stack.set("system")
            cb_mtu.set("1400")
            var_v6.set(False)
            ent_exclude.delete(0, "end")
            ent_v4.delete(0, "end")
            ent_v4.insert(0, "172.19.0.1/30")
            ent_if.delete(0, "end")
            ent_if.insert(0, "Mobility0")

        def do_ok():
            try:
                mtu = int(cb_mtu.get() or 1400)
            except Exception:
                mtu = 1400
            self.tun_settings = {
                "auto_route": bool(var_auto.get()),
                "strict_route": bool(var_strict.get()),
                "stack": (cb_stack.get() or "system").strip(),
                "mtu": mtu,
                "enable_ipv6": bool(var_v6.get()),
                "route_exclude": (ent_exclude.get() or "").strip(),
                "ipv4_address": (ent_v4.get() or "172.19.0.1/30").strip(),
                "interface_name": (ent_if.get() or "Mobility0").strip(),
            }
            self.save_settings()
            self.log("TUN 设置已保存，重新启动代理后生效")
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


    def open_speed_settings_dialog(self):
        win = ctk.CTkToplevel(self)
        win.title("测速 / 连通性设置")
        win.geometry("480x360")
        win.transient(self)
        try:
            win.grab_set()
        except Exception:
            pass
        ctk.CTkLabel(win, text="测速与连通性", font=("Microsoft YaHei UI", 16, "bold")).pack(
            anchor="w", padx=16, pady=(14, 8)
        )
        form = ctk.CTkFrame(win, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=16)
        row = ctk.CTkFrame(form, fg_color="transparent")
        row.pack(fill="x", pady=6)
        ctk.CTkLabel(row, text="TCP 测速超时(秒)", width=140, anchor="w").pack(side="left")
        timeout_entry = ctk.CTkEntry(row, width=100)
        timeout_entry.insert(0, str(getattr(self, "test_timeout", DEFAULT_TEST_TIMEOUT)))
        timeout_entry.pack(side="left", padx=8)
        row2 = ctk.CTkFrame(form, fg_color="transparent")
        row2.pack(fill="x", pady=6)
        group_var = ctk.BooleanVar(value=bool(getattr(self, "group_nodes_by_sub", True)))
        ctk.CTkCheckBox(row2, text="节点列表按订阅分组显示", variable=group_var).pack(side="left")
        ctk.CTkLabel(form, text="连通性测试目标（每行：URL 或 URL|名称）", anchor="w").pack(fill="x", pady=(10, 4))
        urls_box = ctk.CTkTextbox(form, height=140)
        urls_box.pack(fill="both", expand=True)
        lines = []
        for item in getattr(self, "connectivity_urls", None) or DEFAULT_CONNECTIVITY_URLS:
            if isinstance(item, (list, tuple)):
                u, n = item[0], (item[1] if len(item) > 1 else item[0])
            else:
                u, n = item, item
            lines.append(f"{u}|{n}" if n and n != u else str(u))
        urls_box.insert("1.0", "\n".join(lines))

        def save():
            try:
                self.test_timeout = max(1.0, float(timeout_entry.get().strip() or DEFAULT_TEST_TIMEOUT))
            except Exception:
                self.test_timeout = DEFAULT_TEST_TIMEOUT
            self.group_nodes_by_sub = bool(group_var.get())
            parsed = []
            for line in urls_box.get("1.0", "end").splitlines():
                line = line.strip()
                if not line:
                    continue
                if "|" in line:
                    u, n = line.split("|", 1)
                    parsed.append((u.strip(), n.strip() or u.strip()))
                else:
                    parsed.append((line, line))
            if parsed:
                self.connectivity_urls = parsed
            self.save_settings()
            self.refresh_node_list(keep_selection=True, resort=False)
            self.log(f"测速超时={self.test_timeout}s，分组={'开' if self.group_nodes_by_sub else '关'}")
            win.destroy()

        ctk.CTkButton(win, text="保存", width=100, command=save).pack(pady=12)

    def open_diagnostics_dialog(self):
        win = ctk.CTkToplevel(self)
        win.title("连接诊断")
        win.geometry("560x480")
        win.transient(self)
        try:
            win.grab_set()
        except Exception:
            pass
        ctk.CTkLabel(win, text="连接诊断", font=("Microsoft YaHei UI", 16, "bold")).pack(
            anchor="w", padx=16, pady=(14, 6)
        )
        box = ctk.CTkTextbox(win, height=360)
        box.pack(fill="both", expand=True, padx=16, pady=6)
        lines = []
        lines.append(f"软件版本: v{APP_VERSION}")
        lines.append(f"运行状态: {'运行中' if getattr(self, 'is_running', False) else '未运行'}")
        lines.append(f"TUN: {'开' if getattr(self, 'tun_enabled', False) else '关'}")
        lines.append(f"代理模式: {getattr(self, 'proxy_mode', '')}")
        try:
            sp, hp = self.get_ports()
        except Exception:
            sp, hp = 10808, 10809
        lines.append(f"本地端口: SOCKS {sp} / HTTP {hp}")
        node = getattr(self, "current_node", None)
        if node:
            lines.append(f"当前节点: [{node.get('protocol')}] {node.get('name')} {node.get('address')}:{node.get('port')}")
        else:
            lines.append("当前节点: 无")
        for name, attr in (("Xray", "xray_process"), ("sing-box", "singbox_process"), ("Mihomo", "mihomo_process")):
            proc = getattr(self, attr, None)
            if proc and proc.poll() is None:
                lines.append(f"{name} 进程: PID {proc.pid}")
            else:
                lines.append(f"{name} 进程: 未运行")
        try:
            reg = self._read_proxy_reg()
            lines.append(f"系统代理启用: {reg.get('ProxyEnable')}")
            lines.append(f"ProxyServer: {reg.get('ProxyServer') or '（空）'}")
            lines.append(f"AutoConfigURL: {reg.get('AutoConfigURL') or '（空）'}")
        except Exception as e:
            lines.append(f"读取系统代理失败: {e}")
        for port in (sp, hp):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.4)
                ok = s.connect_ex(("127.0.0.1", int(port))) == 0
                s.close()
                lines.append(f"127.0.0.1:{port} 监听: {'是' if ok else '否'}")
            except Exception as e:
                lines.append(f"127.0.0.1:{port} 探测失败: {e}")
        for fn in ("xray.exe", "sing-box.exe", "mihomo.exe", "geoip.dat", "geosite.dat", "wintun.dll"):
            fp = self.core_dir / fn
            lines.append(f"core/{fn}: {'存在' if fp.exists() else '缺失'}")
        text = "\n".join(lines)
        box.insert("1.0", text)
        box.configure(state="disabled")

        def copy_all():
            try:
                self.clipboard_clear()
                self.clipboard_append(text)
                self.log("诊断信息已复制")
            except Exception as e:
                self.log(f"复制失败：{e}")

        bf = ctk.CTkFrame(win, fg_color="transparent")
        bf.pack(fill="x", padx=16, pady=10)
        ctk.CTkButton(bf, text="复制全部", width=100, command=copy_all).pack(side="left")
        ctk.CTkButton(bf, text="关闭", width=80, command=win.destroy).pack(side="right")

    def export_config_dialog(self):
        """导出：可选 URI列表 / Clash YAML / 软件备份JSON。"""
        win = ctk.CTkToplevel(self)
        win.title("导出节点")
        win.geometry("380x280")
        win.transient(self)
        try:
            win.grab_set()
        except Exception:
            pass
        ctk.CTkLabel(win, text="选择导出格式", font=("Microsoft YaHei UI", 15, "bold")).pack(
            anchor="w", padx=18, pady=(16, 8)
        )
        fmt_var = ctk.StringVar(value="URI 节点列表 (.txt)")
        options = [
            "URI 节点列表 (.txt)",
            "Clash / Mihomo proxies (.yaml)",
            "软件备份 JSON（节点+设置）",
        ]
        box = ctk.CTkComboBox(win, values=options, variable=fmt_var, width=320, state="readonly")
        box.pack(padx=18, pady=6)
        ctk.CTkLabel(
            win,
            text="URI：vmess/vless/trojan/ss 等链接\nClash：可导入其他 Clash 客户端\n备份 JSON：本软件完整恢复用",
            font=("Microsoft YaHei UI", 11),
            text_color=("gray40", "gray60"),
            justify="left",
        ).pack(anchor="w", padx=18, pady=8)

        def do_export():
            fmt = fmt_var.get()
            try:
                from tkinter import filedialog
            except Exception:
                self.log("无法打开文件对话框")
                return
            try:
                win.destroy()
            except Exception:
                pass
            if "备份" in fmt or "JSON" in fmt:
                path = filedialog.asksaveasfilename(
                    title="导出备份", defaultextension=".json",
                    initialfile="Mobility-backup.json",
                    filetypes=[("JSON", "*.json"), ("All", "*.*")],
                )
                if not path:
                    return
                try:
                    self.save_settings()
                    Path(path).write_text(self.settings_path.read_text(encoding="utf-8"), encoding="utf-8")
                    self.log("已导出备份：%s" % path)
                except Exception as e:
                    self.log("导出失败：%s" % e)
                return
            if "Clash" in fmt or "yaml" in fmt.lower():
                path = filedialog.asksaveasfilename(
                    title="导出 Clash", defaultextension=".yaml",
                    initialfile="Mobility-clash.yaml",
                    filetypes=[("YAML", "*.yaml *.yml"), ("All", "*.*")],
                )
                if not path:
                    return
                try:
                    Path(path).write_text(self.export_nodes_clash_yaml(), encoding="utf-8")
                    self.log("已导出 Clash：%s（%s 个节点）" % (path, len(self.nodes or [])))
                except Exception as e:
                    self.log("导出 Clash 失败：%s" % e)
                return
            # URI list
            path = filedialog.asksaveasfilename(
                title="导出 URI 列表", defaultextension=".txt",
                initialfile="Mobility-nodes.txt",
                filetypes=[("Text", "*.txt"), ("All", "*.*")],
            )
            if not path:
                return
            try:
                lines = []
                for n in (self.nodes or []):
                    u = self.node_to_share_uri(n)
                    if u:
                        lines.append(u)
                Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
                self.log("已导出 URI：%s（%s 条）" % (path, len(lines)))
            except Exception as e:
                self.log("导出 URI 失败：%s" % e)

        bf = ctk.CTkFrame(win, fg_color="transparent")
        bf.pack(fill="x", padx=18, pady=16)
        ctk.CTkButton(bf, text="导出", width=100, command=do_export).pack(side="left")
        ctk.CTkButton(bf, text="取消", width=80, command=win.destroy).pack(side="right")

    def node_to_share_uri(self, node: dict) -> str:
        """尽量还原分享链接；不支持的返回空。"""
        if not node:
            return ""
        if node.get("raw") and str(node.get("raw")).startswith(("vmess://", "vless://", "trojan://", "ss://", "hy2://", "hysteria2://", "tuic://")):
            return str(node.get("raw")).strip()
        proto = (node.get("protocol") or "").lower()
        name = node.get("name") or "node"
        host = node.get("address") or ""
        port = node.get("port") or ""
        if not host or not port:
            return ""
        try:
            from urllib.parse import quote
            if proto == "trojan":
                pwd = quote(node.get("password") or "", safe="")
                sni = node.get("sni") or host
                return "trojan://%s@%s:%s?sni=%s#%s" % (pwd, host, port, quote(sni), quote(name))
            if proto in ("ss", "shadowsocks"):
                import base64
                method = node.get("method") or "aes-256-gcm"
                password = node.get("password") or ""
                userinfo = base64.urlsafe_b64encode(("%s:%s" % (method, password)).encode()).decode().rstrip("=")
                return "ss://%s@%s:%s#%s" % (userinfo, host, port, quote(name))
            if proto == "vless":
                uuid = node.get("uuid") or ""
                return "vless://%s@%s:%s?encryption=none#%s" % (uuid, host, port, quote(name))
            if proto in ("hysteria2", "hy2"):
                pwd = quote(node.get("password") or "", safe="")
                return "hysteria2://%s@%s:%s#%s" % (pwd, host, port, quote(name))
        except Exception:
            return ""
        return ""

    def export_nodes_clash_yaml(self) -> str:
        """导出为简易 Clash proxies YAML。"""
        lines = ["# Mobility exported proxies", "proxies:"]
        for n in (self.nodes or []):
            if not isinstance(n, dict):
                continue
            try:
                proxy = self.node_to_mihomo_proxy(n)
            except Exception:
                continue
            lines.append("  - name: %s" % json.dumps(proxy.get("name") or "node", ensure_ascii=False))
            for k, v in proxy.items():
                if k == "name":
                    continue
                if isinstance(v, bool):
                    lines.append("    %s: %s" % (k, "true" if v else "false"))
                elif isinstance(v, (int, float)):
                    lines.append("    %s: %s" % (k, v))
                elif isinstance(v, list):
                    lines.append("    %s: [%s]" % (k, ", ".join(str(x) for x in v)))
                elif isinstance(v, dict):
                    lines.append("    %s:" % k)
                    for k2, v2 in v.items():
                        if isinstance(v2, dict):
                            lines.append("      %s: %s" % (k2, json.dumps(v2, ensure_ascii=False)))
                        else:
                            lines.append("      %s: %s" % (k2, json.dumps(v2, ensure_ascii=False) if isinstance(v2, str) else v2))
                else:
                    lines.append("    %s: %s" % (k, json.dumps(str(v), ensure_ascii=False)))
        return "\n".join(lines) + "\n"


    def import_local_nodes_dialog(self):
        """从本地文件导入节点：支持 URI 订阅、Clash、V2Ray/sing-box JSON、Surge/Loon。"""
        try:
            from tkinter import filedialog
        except Exception:
            self.log("无法打开文件对话框")
            return
        path = filedialog.askopenfilename(
            title="导入本地节点文件",
            filetypes=[
                ("节点/订阅文件", "*.txt *.yaml *.yml *.json *.conf *.list *.ini"),
                ("全部文件", "*.*"),
            ],
        )
        if not path:
            return
        try:
            raw = Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.log("读取文件失败：%s" % e)
            return
        nodes = parse_nodes_any(raw)
        if not nodes:
            self.log("未能从文件解析出节点（请确认是 Clash/URI/JSON/Surge 等文本格式）")
            return
        group_name = normalize_group_name(Path(path).stem[:24], local=True)
        for n in nodes:
            if isinstance(n, dict):
                n["_group"] = group_name
                n["group"] = group_name
                n["from_local"] = True
        # 保留已有节点分组，新节点单独一组
        seen = set()
        merged = []
        for n in list(self.nodes or []) + nodes:
            if not isinstance(n, dict):
                continue
            key = "%s|%s|%s|%s" % (n.get("protocol"), n.get("address"), n.get("port"), n.get("name"))
            if key in seen:
                continue
            seen.add(key)
            if not n.get("_group") and not n.get("group"):
                n["_group"] = "默认"
            merged.append(n)
        self.nodes = merged
        self.group_nodes_by_sub = True
        try:
            if not hasattr(self, "_collapsed_groups") or not isinstance(self._collapsed_groups, set):
                self._collapsed_groups = set()
            self._collapsed_groups.add(group_name)
        except Exception:
            pass
        self.refresh_node_list(keep_selection=False)
        self.save_settings()
        self.log("本地导入成功：%s 个节点（组：%s，已折叠）" % (len(nodes), group_name))

    def import_config_dialog(self):
        try:
            from tkinter import filedialog
        except Exception:
            self.log("无法打开文件对话框")
            return
        path = filedialog.askopenfilename(
            title="导入节点与设置",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
        )
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                self.log("导入文件格式无效")
                return
            self.settings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            self.load_settings()
            self.refresh_node_list(keep_selection=False, resort=False)
            try:
                self.refresh_sub_select()
            except Exception:
                pass
            self.log(f"已导入：{path}")
        except Exception as e:
            self.log(f"导入失败：{e}")

    def fetch_rule_set_and_merge(self, url: str, kind: str = "direct"):
        url = (url or "").strip()
        if not url.startswith(("http://", "https://")):
            self.log("规则集 URL 无效")
            return
        try:
            self.log(f"正在拉取规则集：{url}")
            resp = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0 Mobility"})
            resp.raise_for_status()
            domains = []
            for line in (resp.text or "").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                if line.startswith("domain:"):
                    line = line[7:].strip()
                elif line.startswith("full:"):
                    line = line[5:].strip()
                elif line.startswith("regexp:"):
                    continue
                line = line.split("#")[0].strip()
                if line:
                    domains.append(line)
            if not domains:
                self.log("规则集中未解析到域名")
                return
            attr = {"direct": "routing_extra_direct", "proxy": "routing_extra_proxy", "block": "routing_extra_block"}.get(kind, "routing_extra_direct")
            old = getattr(self, attr, "") or ""
            existing = set(x.strip() for x in old.replace(",", "\n").splitlines() if x.strip())
            added = 0
            for d in domains:
                if d not in existing:
                    existing.add(d)
                    added += 1
            setattr(self, attr, "\n".join(sorted(existing)))
            self.save_settings()
            self.log(f"规则集合并完成：新增 {added}，总计 {len(existing)}（{kind}）")
        except Exception as e:
            self.log(f"拉取规则集失败：{e}")

    def open_routing_dialog(self):
        """路由与分流增强设置。"""
        win = ctk.CTkToplevel(self)
        win.title("路由与分流设置")
        win.geometry("520x580")
        win.transient(self)
        try:
            win.grab_set()
        except Exception:
            pass

        ctk.CTkLabel(win, text="路由与分流设置", font=("Microsoft YaHei UI", 16, "bold")).pack(
            anchor="w", padx=20, pady=(16, 6)
        )
        ctk.CTkLabel(
            win,
            text="统一管理直连 / 代理 / 拦截域名（每行一条或逗号分隔）。\n保存后重新启动代理生效。",
            font=("Microsoft YaHei UI", 11),
            text_color=("gray40", "gray60"),
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 8))

        form = ctk.CTkFrame(win, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=20)

        def box(title, default):
            ctk.CTkLabel(form, text=title, font=("Microsoft YaHei UI", 12, "bold")).pack(anchor="w", pady=(8, 2))
            tb = ctk.CTkTextbox(form, height=90)
            tb.pack(fill="x")
            if default:
                tb.insert("1.0", default)
            return tb

        d0 = (getattr(self, "routing_extra_direct", "") or "").strip()
        p0 = (getattr(self, "routing_extra_proxy", "") or "").strip()
        dd = (getattr(self, "direct_domains", "") or "").strip()
        pd = (getattr(self, "proxy_domains", "") or "").strip()
        if dd and dd not in d0:
            d0 = (d0 + "\n" + dd.replace(",", "\n")).strip() if d0 else dd.replace(",", "\n")
        if pd and pd not in p0:
            p0 = (p0 + "\n" + pd.replace(",", "\n")).strip() if p0 else pd.replace(",", "\n")

        tb_direct = box("强制直连（含原直连域名）", d0)
        tb_proxy = box("强制代理（含原代理域名）", p0)
        tb_block = box("拦截（黑名单）", getattr(self, "routing_extra_block", "") or "")

        ctk.CTkLabel(form, text="从 URL 更新规则集", font=("Microsoft YaHei UI", 12, "bold")).pack(anchor="w", pady=(10, 2))
        ru = ctk.CTkFrame(form, fg_color="transparent")
        ru.pack(fill="x", pady=4)
        rule_url_entry = ctk.CTkEntry(ru, height=30, placeholder_text="规则列表 URL（每行一个域名）")
        rule_url_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        kind_cb = ctk.CTkComboBox(ru, width=90, values=["direct", "proxy", "block"], state="readonly")
        kind_cb.set("direct")
        kind_cb.pack(side="left", padx=4)

        def do_fetch_rules():
            u = rule_url_entry.get().strip()
            k = kind_cb.get() or "direct"
            def _run():
                self.fetch_rule_set_and_merge(u, k)
                def _ui():
                    try:
                        if k == "direct":
                            tb_direct.delete("1.0", "end")
                            tb_direct.insert("1.0", getattr(self, "routing_extra_direct", "") or "")
                        elif k == "proxy":
                            tb_proxy.delete("1.0", "end")
                            tb_proxy.insert("1.0", getattr(self, "routing_extra_proxy", "") or "")
                        else:
                            tb_block.delete("1.0", "end")
                            tb_block.insert("1.0", getattr(self, "routing_extra_block", "") or "")
                    except Exception:
                        pass
                self.after(0, _ui)
            Thread(target=_run, daemon=True).start()

        ctk.CTkButton(ru, text="拉取合并", width=88, command=do_fetch_rules).pack(side="left", padx=4)

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(side="bottom", fill="x", padx=20, pady=16)

        def do_ok():
            self.routing_extra_direct = tb_direct.get("1.0", "end").strip()
            self.routing_extra_proxy = tb_proxy.get("1.0", "end").strip()
            self.routing_extra_block = tb_block.get("1.0", "end").strip()
            self.direct_domains = ",".join(
                [x.strip() for x in self.routing_extra_direct.replace(",", "\n").splitlines() if x.strip()]
            )
            self.proxy_domains = ",".join(
                [x.strip() for x in self.routing_extra_proxy.replace(",", "\n").splitlines() if x.strip()]
            )
            self.save_settings()
            self.log("路由规则已保存，请重新启动代理")
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

        ctk.CTkButton(btn_row, text="取消", width=90, command=do_cancel).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btn_row, text="确定", width=90, fg_color="#2563EB", command=do_ok).pack(side="right")

    def move_selected_node(self, delta: int):
        node = None
        try:
            node = self.get_selected_node()
        except Exception:
            node = getattr(self, "current_node", None)
        if not node or not self.nodes:
            self.log("请先选择要移动的节点")
            return
        try:
            idx = self.nodes.index(node)
        except ValueError:
            lab = node.get("_label") or node.get("name")
            idx = next((i for i, n in enumerate(self.nodes) if (n.get("_label") or n.get("name")) == lab), -1)
        if idx < 0:
            return
        new_i = idx + int(delta)
        if new_i < 0 or new_i >= len(self.nodes):
            return
        self.nodes[idx], self.nodes[new_i] = self.nodes[new_i], self.nodes[idx]
        self.current_node = self.nodes[new_i]
        try:
            self._selected_label = self.current_node.get("_label") or node_label(self.current_node)
        except Exception:
            self._selected_label = self.current_node.get("_label")
        # 快速更新两个按钮文案，避免 100+ 节点整表销毁重建导致卡顿
        try:
            self._swap_node_buttons(idx, new_i)
        except Exception:
            self.refresh_node_list(keep_selection=True, resort=False)
        # 持久化节流：不每次写盘
        try:
            if hasattr(self, "_move_save_after") and self._move_save_after:
                self.after_cancel(self._move_save_after)
        except Exception:
            pass
        self._move_save_after = self.after(800, self.save_settings)
        self.log("节点已" + ("上移" if delta < 0 else "下移"))

    def _swap_node_buttons(self, i: int, j: int):
        """仅交换两个节点按钮显示，不重建列表。"""
        btns = [b for b in getattr(self, "_node_buttons", []) if hasattr(b, "configure") and hasattr(b, "cget")]
        # _node_buttons 与当前过滤列表对应；无过滤时与 self.nodes 对齐
        if not btns or max(i, j) >= len(btns) or max(i, j) >= len(self.nodes):
            self.refresh_node_list(keep_selection=True, resort=False)
            return
        for pos in (i, j):
            n = self.nodes[pos]
            try:
                lb = node_label(n)
            except Exception:
                lb = n.get("_label") or n.get("name") or ("节点%d" % (pos + 1))
            n["_label"] = lb
            n["_index"] = pos
            try:
                btns[pos].configure(text=lb)
            except Exception:
                pass
        # 高亮当前
        sel = getattr(self, "_selected_label", None)
        for b in btns:
            try:
                txt = b.cget("text")
                if sel and txt == sel:
                    b.configure(fg_color=("#EA580C", "#C2410C"), text_color="white")
                else:
                    b.configure(fg_color=("gray85", "gray25"), text_color=("gray10", "gray90"))
            except Exception:
                pass
        try:
            self.current_label.configure(text=self._short_node_text(self.current_node))
        except Exception:
            pass

    def export_diagnostics(self):
        try:
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(
                title="导出诊断信息",
                defaultextension=".txt",
                filetypes=[("Text", "*.txt")],
                initialfile="Mobility-diag-v%s.txt" % APP_VERSION,
            )
            if not path:
                return
            lines = [
                "Mobility v%s" % APP_VERSION,
                "Core map: %s" % (getattr(self, "core_map", {}),),
                "Proxy mode: %s" % (getattr(self, "proxy_mode", ""),),
                "TUN: %s settings=%s" % (getattr(self, "tun_enabled", False), getattr(self, "tun_settings", {})),
                "Node: %s" % (getattr(self, "current_node", None),),
                "",
                "---- log ----",
            ]
            try:
                if hasattr(self, "log_box"):
                    lines.append(self.log_box.get("1.0", "end"))
            except Exception:
                pass
            for name in ("xray.log", "error.log", "singbox.log", "singbox-tun.json", "config.json"):
                fp = self.core_dir / name
                if fp.exists():
                    lines.append("")
                    lines.append("---- %s ----" % name)
                    try:
                        lines.append(fp.read_text(encoding="utf-8", errors="ignore")[-8000:])
                    except Exception as e:
                        lines.append(str(e))
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            self.log("诊断信息已导出：%s" % path)
        except Exception as e:
            self.log("导出失败：%s" % e)

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
            if self.apply_system_proxy_for_mode(http_port):
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

    def get_download_proxies(self):
        """若本软件代理已运行，返回供 requests 使用的本地代理，加速 GitHub 下载。"""
        if not getattr(self, "is_running", False):
            return None
        try:
            _sp, hp = self.get_ports()
            hp = int(hp)
        except Exception:
            hp = int(getattr(self, "http_port", 10809) or 10809)
        url = "http://127.0.0.1:%s" % hp
        return {"http": url, "https": url}

    def http_get(self, url: str, timeout: int = 120, headers=None):
        """带可选本地代理的 GET；代理失败时回退直连一次。"""
        headers = headers or {"User-Agent": "Mobility"}
        proxies = None
        try:
            proxies = self.get_download_proxies()
        except Exception:
            proxies = None
        if proxies:
            try:
                self.log("通过本地代理下载：%s" % url[:80])
                r = requests.get(url, timeout=timeout, headers=headers, proxies=proxies)
                r.raise_for_status()
                return r
            except Exception as e:
                self.log("代理下载失败，改直连：%s" % e)
        r = requests.get(url, timeout=timeout, headers=headers)
        r.raise_for_status()
        return r

    def update_geo_thread(self):
        Thread(target=self.update_geo_only, daemon=True).start()

    def update_geo_only(self):
        """更新 geoip.dat + geosite.dat 两个规则文件。"""
        self.log("开始更新规则文件（geoip.dat + geosite.dat）...")
        try:
            core_dir = Path(get_base_dir()) / "core"
            core_dir.mkdir(parents=True, exist_ok=True)
            items = [
                ("geoip.dat", "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"),
                ("geosite.dat", "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"),
            ]
            ok = 0
            for geo_name, geo_url in items:
                try:
                    self.log("下载 %s ..." % geo_name)
                    gr = self.http_get(geo_url, timeout=120)
                    data = gr.content
                    (core_dir / geo_name).write_bytes(data)
                    self.log("%s 已更新（%s 字节）" % (geo_name, len(data)))
                    ok += 1
                except Exception as ge:
                    self.log("%s 更新失败：%s" % (geo_name, ge))
            self.log("规则文件更新结束：成功 %s/2（geoip.dat、geosite.dat）" % ok)
        except Exception as e:
            self.log("更新规则失败：%s" % e)

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

    def open_core_update_dialog(self):
        """二级窗口：每核心「仅检查」+「更新」共 6 个按钮；打开时不联网、不跑版本对比。"""
        win = ctk.CTkToplevel(self)
        win.title("更新核心")
        win.geometry("400x460")
        win.transient(self)
        try:
            win.attributes("-topmost", True)
        except Exception:
            pass
        try:
            win.grab_set()
        except Exception:
            pass

        ctk.CTkLabel(win, text="更新核心", font=("Microsoft YaHei UI", 16, "bold")).pack(
            anchor="w", padx=20, pady=(16, 4)
        )
        ctk.CTkLabel(
            win,
            text="打开本窗口不检查版本（避免卡顿）。\n「仅检查」：对比本地与最新版；「更新」：下载并替换。\n规则文件请使用主界面「更新规则」。",
            font=("Microsoft YaHei UI", 11),
            text_color=("gray40", "gray60"),
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 10))

        def run(fn):
            try:
                win.destroy()
            except Exception:
                pass
            Thread(target=fn, daemon=True).start()

        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20)

        rows = [
            ("仅检查 Xray 版本", self.check_xray_version_only, "更新 Xray 核心", self.update_xray_core),
            ("仅检查 sing-box 版本", self.check_singbox_version_only, "更新 sing-box 核心", self.update_singbox_core),
            ("仅检查 Mihomo 版本", self.check_mihomo_version_only, "更新 Mihomo 核心", self.update_mihomo_core),
        ]
        for c1, f1, c2, f2 in rows:
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", pady=4)
            row.grid_columnconfigure(0, weight=1)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkButton(row, text=c1, height=34, command=lambda f=f1: run(f)).grid(
                row=0, column=0, sticky="ew", padx=(0, 4)
            )
            ctk.CTkButton(row, text=c2, height=34, command=lambda f=f2: run(f)).grid(
                row=0, column=1, sticky="ew", padx=(4, 0)
            )

        ctk.CTkButton(
            body, text="全部更新三个核心", height=34,
            fg_color="#2563EB", command=lambda: run(self.update_all_cores)
        ).pack(fill="x", pady=(12, 4))
        ctk.CTkButton(win, text="关闭", width=90, command=win.destroy).pack(pady=10)

    def check_xray_version_only(self):
        self.log("检查 Xray 版本 ...")
        try:
            local = get_xray_version(getattr(self, "xray_path", None) or find_xray())
            self.log("本地 Xray：%s" % local)
            remote = fetch_xray_latest_version()
            if remote:
                self.log("最新 Xray：%s" % remote)
                if local and local not in ("未知", "无", "未安装") and not version_newer(remote, local):
                    self.log("Xray 已是最新版本（%s）" % local)
                elif local and local not in ("未知", "无", "未安装"):
                    self.log("发现新版本：%s → %s（可点「更新 Xray 核心」）" % (local, remote))
                else:
                    self.log("本地未检测到有效版本，可点「更新 Xray 核心」安装")
            else:
                self.log("无法获取 Xray 最新版本（网络或 GitHub 限制）")
        except Exception as e:
            self.log("检查 Xray 失败：%s" % e)

    def check_singbox_version_only(self):
        self.log("检查 sing-box 版本 ...")
        try:
            path = self.core_dir / "sing-box.exe"
            local = get_core_binary_version(path, "sing-box") if path.exists() else "未安装"
            self.log("本地 sing-box：%s" % local)
            remote = fetch_singbox_latest_version()
            if remote:
                self.log("最新 sing-box：%s" % remote)
                if local and local not in ("未知", "无", "未安装") and not version_newer(remote, local):
                    self.log("sing-box 已是最新版本（%s）" % local)
                elif local and local not in ("未知", "无", "未安装"):
                    self.log("发现新版本：%s → %s（可点「更新 sing-box 核心」）" % (local, remote))
                else:
                    self.log("本地未安装，可点「更新 sing-box 核心」安装")
            else:
                self.log("无法获取 sing-box 最新版本")
        except Exception as e:
            self.log("检查 sing-box 失败：%s" % e)

    def check_mihomo_version_only(self):
        self.log("检查 Mihomo 版本 ...")
        try:
            path = self.core_dir / "mihomo.exe"
            local = get_core_binary_version(path, "mihomo") if path.exists() else "未安装"
            self.log("本地 Mihomo：%s" % local)
            remote = fetch_mihomo_latest_version()
            if remote:
                self.log("最新 Mihomo：%s" % remote)
                if local and local not in ("未知", "无", "未安装", ".") and not version_newer(remote, local):
                    self.log("Mihomo 已是最新版本（%s）" % local)
                elif local and local not in ("未知", "无", "未安装", "."):
                    self.log("发现新版本：%s → %s（可点「更新 Mihomo 核心」）" % (local, remote))
                else:
                    self.log("本地未检测到有效版本，可点「更新 Mihomo 核心」安装")
            else:
                self.log("无法获取 Mihomo 最新版本")
        except Exception as e:
            self.log("检查 Mihomo 失败：%s" % e)

    def _stop_core_process(self, attr: str, name: str):
        try:
            proc = getattr(self, attr, None)
            if proc is not None and proc.poll() is None:
                self.log("检测到 %s 正在运行，先停止..." % name)
                try:
                    proc.terminate()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                setattr(self, attr, None)
                time.sleep(0.35)
        except Exception:
            pass

    def _replace_exe(self, dest: Path, data: bytes, label: str) -> bool:
        dest = Path(dest)
        tmp_exe = dest.with_suffix(dest.suffix + ".new")
        try:
            tmp_exe.write_bytes(data)
            if dest.exists():
                try:
                    dest.unlink()
                except PermissionError:
                    self.log("%s 仍被占用，请先点「停止」再更新" % label)
                    self.log("已另存为 %s" % tmp_exe.name)
                    return False
            tmp_exe.replace(dest)
            self.log("%s 已更新" % label)
            return True
        except Exception as e:
            self.log("写入 %s 失败：%s" % (label, e))
            return False

    def _with_proxy_env(self, fn):
        _old_http = os.environ.get("HTTP_PROXY")
        _old_https = os.environ.get("HTTPS_PROXY")
        try:
            px = self.get_download_proxies()
            if px:
                os.environ["HTTP_PROXY"] = px.get("http") or ""
                os.environ["HTTPS_PROXY"] = px.get("https") or ""
                self.log("下载将尝试使用本地代理")
            return fn()
        finally:
            if _old_http is None:
                os.environ.pop("HTTP_PROXY", None)
            else:
                os.environ["HTTP_PROXY"] = _old_http
            if _old_https is None:
                os.environ.pop("HTTPS_PROXY", None)
            else:
                os.environ["HTTPS_PROXY"] = _old_https

    def _capture_running_state(self) -> bool:
        return bool(getattr(self, "is_running", False))

    def _restore_running_state(self, was_running: bool, did_stop: bool = False):
        """仅在实际停止过核心时恢复代理；已在运行则不动。"""
        if getattr(self, "_skip_core_restore", False):
            return
        if not was_running:
            return
        if not did_stop:
            # 未停止过（例如已是最新），保持现状
            return
        if getattr(self, "is_running", False):
            self.log("代理仍在运行，无需重新启动")
            return
        self.log("更新前代理为开启状态，正在自动重新启动...")
        try:
            self.after(300, self.start_proxy_thread)
        except Exception:
            try:
                self.start_proxy_thread()
            except Exception as e:
                self.log("自动重新启动失败：%s" % e)

    def update_xray_core(self):
        was = self._capture_running_state()
        did_stop = False
        self.log("检查 Xray 版本 ...")
        try:
            local = get_xray_version(getattr(self, "xray_path", None) or find_xray())
            self.log("本地 Xray：%s" % local)
            remote = ""
            try:
                px = self.get_download_proxies()
                api = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
                r = requests.get(api, timeout=20, headers={"User-Agent": "Mobility"}, proxies=px)
                r.raise_for_status()
                remote = str((r.json() or {}).get("tag_name") or "").lstrip("vV")
            except Exception:
                remote = fetch_xray_latest_version()
            if remote:
                self.log("最新 Xray：%s" % remote)
            if remote and local and local not in ("未知", "无", "未安装") and not version_newer(remote, local):
                self.log("Xray 已是最新版本（%s），无需更新" % local)
                return
            if not remote:
                self.log("无法获取远端版本，继续尝试下载最新包 ...")

            import tempfile, zipfile
            url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
            tmp = Path(tempfile.gettempdir()) / "xray_update.zip"
            self.log("下载：%s" % url)
            r = self.http_get(url, timeout=120)
            tmp.write_bytes(r.content)
            core_dir = Path(get_base_dir()) / "core"
            core_dir.mkdir(parents=True, exist_ok=True)

            # 仅当 Xray 在跑时才停（当前代理用的是 Xray）
            proc = getattr(self, "xray_process", None)
            if proc is not None and proc.poll() is None:
                self._stop_core_process("xray_process", "Xray")
                did_stop = True
                self.is_running = False
                try:
                    self.after(0, self.restore_proxy_backup)
                except Exception:
                    pass
                time.sleep(0.5)

            with zipfile.ZipFile(tmp, "r") as zf:
                for name in zf.namelist():
                    if name.lower().endswith("xray.exe"):
                        self._replace_exe(core_dir / "xray.exe", zf.read(name), "xray.exe")
                        break
            new_v = get_xray_version(core_dir / "xray.exe")
            self._xray_ver = new_v
            self.log("当前 Xray 版本：%s" % new_v)
            try:
                self.after(0, lambda: self.refresh_version_label("Xray"))
            except Exception:
                pass
            self.log("Xray 核心更新流程结束")
        except Exception as e:
            self.log("更新 Xray 失败：%s" % e)
        self._restore_running_state(was, did_stop=did_stop)

    def update_singbox_core(self):
        was = self._capture_running_state()
        did_stop = False
        self.log("检查 sing-box 版本 ...")
        try:
            path = self.core_dir / "sing-box.exe"
            local = get_core_binary_version(path, "sing-box") if path.exists() else "未安装"
            self.log("本地 sing-box：%s" % local)
            remote = fetch_singbox_latest_version()
            if remote:
                self.log("最新 sing-box：%s" % remote)
            if remote and local and local not in ("未知", "无", "未安装") and not version_newer(remote, local):
                self.log("sing-box 已是最新版本（%s），无需更新" % local)
                return

            # 仅当 sing-box 进程在跑时才停；Xray 代理运行中不强制重启
            proc = getattr(self, "singbox_process", None)
            if proc is not None and proc.poll() is None:
                self._stop_core_process("singbox_process", "sing-box")
                did_stop = True
                # TUN/sing-box 作为主代理时才标记未运行
                if getattr(self, "proxy_core", "").lower().startswith("sing") or getattr(self, "tun_enabled", False):
                    self.is_running = False
                    try:
                        self.after(0, self.restore_proxy_backup)
                    except Exception:
                        pass
                time.sleep(0.4)

            if path.exists():
                try:
                    path.unlink()
                except Exception as e:
                    self.log("删除旧 sing-box 失败：%s（若文件占用请先停止）" % e)
            self._with_proxy_env(lambda: ensure_singbox(self.core_dir, log_fn=self.log))
            new_v = get_core_binary_version(self.core_dir / "sing-box.exe", "sing-box")
            self.log("当前 sing-box 版本：%s" % new_v)
            try:
                self.after(0, lambda: self.refresh_version_label("sing-box"))
            except Exception:
                pass
            self.log("sing-box 核心更新流程结束")
        except Exception as e:
            self.log("更新 sing-box 失败：%s" % e)
        # 仅当我们停过且当前主核心依赖 sing-box 时才自动重启
        need = did_stop and was
        self._restore_running_state(need, did_stop=did_stop)

    def update_mihomo_core(self):
        was = self._capture_running_state()
        did_stop = False
        self.log("检查 Mihomo 版本 ...")
        try:
            path = self.core_dir / "mihomo.exe"
            local = get_core_binary_version(path, "mihomo") if path.exists() else "未安装"
            self.log("本地 Mihomo：%s" % local)
            remote = fetch_mihomo_latest_version()
            if remote:
                self.log("最新 Mihomo：%s" % remote)
            if remote and local and local not in ("未知", "无", "未安装") and not version_newer(remote, local):
                self.log("Mihomo 已是最新版本（%s），无需更新" % local)
                return

            proc = getattr(self, "mihomo_process", None)
            if proc is not None and proc.poll() is None:
                self._stop_core_process("mihomo_process", "Mihomo")
                did_stop = True
                if str(getattr(self, "proxy_core", "")).lower().startswith("mihomo"):
                    self.is_running = False
                    try:
                        self.after(0, self.restore_proxy_backup)
                    except Exception:
                        pass
                time.sleep(0.4)

            if path.exists():
                try:
                    path.unlink()
                except Exception as e:
                    self.log("删除旧 Mihomo 失败：%s" % e)
            self._with_proxy_env(lambda: ensure_mihomo(self.core_dir, log_fn=self.log))
            new_v = get_core_binary_version(self.core_dir / "mihomo.exe", "mihomo")
            self.log("当前 Mihomo 版本：%s" % new_v)
            try:
                self.after(0, lambda: self.refresh_version_label("Mihomo"))
            except Exception:
                pass
            self.log("Mihomo 核心更新流程结束")
        except Exception as e:
            self.log("更新 Mihomo 失败：%s" % e)
        need = did_stop and was
        self._restore_running_state(need, did_stop=did_stop)

    def update_all_cores(self):
        was = self._capture_running_state()
        self.log("开始检查并全部更新核心 ...")
        self._skip_core_restore = True
        any_stop = {"v": False}
        try:
            # 包装：记录是否停过
            def wrap(fn):
                before = getattr(self, "is_running", False)
                fn()
                after = getattr(self, "is_running", False)
                if before and not after:
                    any_stop["v"] = True
            wrap(self.update_xray_core)
            wrap(self.update_singbox_core)
            wrap(self.update_mihomo_core)
        finally:
            self._skip_core_restore = False
        self.log("全部核心检查/更新结束（规则请用「更新规则」）")
        self._restore_running_state(was, did_stop=any_stop["v"])

    def update_core_thread(self):
        # 兼容旧入口：打开选择对话框
        self.after(0, self.open_core_update_dialog)

    def update_core(self):
        # 兼容旧调用
        self.update_all_cores()


    def _setup_log_tags(self):
        """为运行日志配置颜色标签。"""
        try:
            tb = getattr(self.log_box, "_textbox", None) or self.log_box
            tb.tag_configure("log_error", foreground="#DC2626")
            tb.tag_configure("log_warn", foreground="#D97706")
            tb.tag_configure("log_ok", foreground="#16A34A")
            tb.tag_configure("log_update", foreground="#2563EB")
        except Exception:
            pass

    def _log_tag_for(self, line: str) -> str:
        low = (line or "").lower()
        for k in ("失败", "错误", "异常", "error", "exception", "traceback",
                  "permission denied", "access is denied", "denied", "崩溃", "fatal", "critical"):
            if k in low:
                return "log_error"
        for k in ("警告", "warning", "warn]", "[warn", "deprecated"):
            if k in low:
                return "log_warn"
        for k in ("已更新", "完成", "成功", "已启动", "success"):
            if k in low:
                return "log_ok"
        for k in ("更新", "下载", "update", "download", "拉取", "检查并更新"):
            if k in low:
                return "log_update"
        return ""

    def _insert_log_line(self, line: str):
        tag = self._log_tag_for(line)
        try:
            tb = getattr(self.log_box, "_textbox", None)
            if tb is not None and tag:
                tb.insert("end", line + "\n", tag)
            elif tb is not None:
                tb.insert("end", line + "\n")
            else:
                self.log_box.insert("end", line + "\n")
        except Exception:
            try:
                self.log_box.insert("end", line + "\n")
            except Exception:
                pass

    def log(self, msg: str):
        """写界面日志（带颜色）+ logs/mobility.log。"""
        try:
            if not hasattr(self, "_log_lines"):
                self._log_lines = []
            line = str(msg)
            try:
                logs_dir = getattr(self, "logs_dir", None)
                if logs_dir is None:
                    logs_dir = Path(getattr(self, "base_dir", Path("."))) / "logs"
                    logs_dir.mkdir(parents=True, exist_ok=True)
                    self.logs_dir = logs_dir
                app_log = getattr(self, "app_log_file", None) or (logs_dir / "mobility.log")
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                with open(app_log, "a", encoding="utf-8", errors="ignore") as f:
                    f.write("[%s] %s\n" % (ts, line))
            except Exception:
                pass
            self._log_lines.append(line)
            if len(self._log_lines) > 2000:
                self._log_lines = self._log_lines[-1200:]
            if not hasattr(self, "log_box"):
                return

            def _ui():
                try:
                    self._insert_log_line(line)
                    if getattr(self, "_log_autoscroll", True):
                        now = time.time()
                        last = getattr(self, "_log_scroll_ts", 0) or 0
                        if now - last >= 0.25:
                            self._log_scroll_ts = now
                            self.log_box.see("end")
                    try:
                        end_idx = self.log_box.index("end-1c")
                        if float(str(end_idx).split(".")[0]) > 800:
                            self.log_box.delete("1.0", "200.0")
                    except Exception:
                        pass
                except Exception:
                    pass

            try:
                self.after(0, _ui)
            except Exception:
                _ui()
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
                    self._insert_log_line(line)
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
        self.log("当前软件版本：v%s" % APP_VERSION)
        tag = ""
        url = "https://github.com/%s/releases" % GITHUB_REPO
        try:
            headers = {
                "User-Agent": "Mobility-Client",
                "Accept": "application/vnd.github+json",
            }
            proxies = None
            try:
                proxies = self.get_download_proxies()
            except Exception:
                proxies = None
            api = "https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO
            r = None
            try:
                r = requests.get(api, timeout=15, headers=headers, proxies=proxies)
            except Exception:
                r = None
            if r is not None and r.status_code == 200:
                data = r.json()
                tag = data.get("tag_name") or data.get("name") or ""
                url = data.get("html_url") or url
            elif r is not None and r.status_code == 403:
                self.log("GitHub API 访问受限（限流），改用发布页检测...")
            elif r is not None and r.status_code == 404:
                self.log("未找到 Release，请确认仓库已发布版本")
                return

            if not tag:
                try:
                    page = "https://github.com/%s/releases/latest" % GITHUB_REPO
                    rr = requests.get(
                        page, timeout=15, headers={"User-Agent": "Mobility-Client"},
                        proxies=proxies, allow_redirects=True,
                    )
                    final = str(rr.url or "")
                    m = re.search(r"/releases/tag/([^/\s?#]+)", final)
                    if m:
                        tag = m.group(1)
                        url = final
                    elif rr.status_code == 200:
                        m2 = re.search(r"/releases/tag/([vV0-9][^\"'/\s]*)", rr.text or "")
                        if m2:
                            tag = m2.group(1)
                except Exception as e2:
                    self.log("发布页检测失败：%s" % e2)

            if not tag:
                self.log("检查更新失败：无法获取版本（可开启代理后重试，或稍后再试）")
                return

            self.log("仓库最新版本：%s" % tag)
            if version_newer(tag, APP_VERSION):
                self.log("发现新版本，请到 GitHub Releases 下载更新")
                if url:
                    self.log("发布页面：%s" % url)
                    try:
                        import webbrowser
                        webbrowser.open(url)
                    except Exception:
                        pass
            else:
                if version_newer(APP_VERSION, tag):
                    self.log("本地版本 v%s 新于仓库 %s" % (APP_VERSION, str(tag).lstrip("v")))
                else:
                    self.log("当前已是最新版本")
        except Exception as e:
            msg = str(e)
            if "403" in msg or "rate limit" in msg.lower():
                self.log("检查更新失败：GitHub 限流，请稍后再试或先启动代理后重试")
            else:
                self.log("检查更新失败：%s" % e)

    def startup(self):
        """分阶段启动，减轻首屏卡顿。"""
        try:
            self.load_settings()
        except Exception as e:
            try:
                self.log("加载设置失败：%s" % e)
            except Exception:
                pass
        try:
            if hasattr(self, "app_ver_label"):
                self.app_ver_label.configure(text="v%s" % APP_VERSION)
        except Exception:
            pass
        self.after(80, self._startup_core)
        self.after(350, self._startup_tray_hotkeys)
        self.after(1500, self.update_home_stats)
        try:
            self.schedule_subscription_refresh()
        except Exception:
            pass
        if getattr(self, "start_minimized", False) and TRAY_AVAILABLE:
            self.after(500, self.withdraw)
            self.log("已按设置启动后最小化到托盘")
        if getattr(self, "auto_connect", False) and self.nodes:
            self.log("已开启启动自动连接，正在启动代理...")
            self.after(1200, self.start_proxy_thread)

    def _startup_core(self):
        try:
            self.prepare_core()
        except Exception:
            pass
        try:
            self._xray_ver = get_xray_version(getattr(self, "xray_path", None) or find_xray())
        except Exception:
            self._xray_ver = "未知"
        try:
            self.refresh_version_label()
        except Exception:
            try:
                self.version_label.configure(text="Xray %s" % self._xray_ver)
            except Exception:
                pass

    def _startup_tray_hotkeys(self):
        try:
            self.start_hotkey_listener()
        except Exception:
            pass
        if TRAY_AVAILABLE:
            try:
                self.setup_tray()
            except Exception as e:
                self.log("托盘初始化失败：%s" % e)
        else:
            self.log("系统托盘不可用（缺少 pystray）")

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
        targets = list(getattr(self, "connectivity_urls", None) or DEFAULT_CONNECTIVITY_URLS)
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
        for n in nodes:
            if isinstance(n, dict) and not n.get("_group"):
                n["_group"] = n.get("group") or "手动导入"
        self.nodes = nodes
        self.refresh_node_list(keep_selection=False)
        self.save_settings()
        self.log(f"剪贴板导入成功：{len(nodes)} 个节点")

    def scan_screen_qr_thread(self):
        # 改为主线程弹窗，用户确认后再截屏（类似身份验证器扫码）
        self.after(0, self.open_qr_scanner_dialog)

    def open_qr_scanner_dialog(self):
        """屏幕扫码：先展示取景界面，用户点击「开始识别」再截屏。"""
        win = ctk.CTkToplevel(self)
        win.title("扫描二维码")
        win.geometry("380x420")
        win.attributes("-topmost", True)
        try:
            win.grab_set()
        except Exception:
            pass

        ctk.CTkLabel(win, text="扫描节点二维码", font=("Microsoft YaHei UI", 16, "bold")).pack(pady=(16, 4))
        ctk.CTkLabel(
            win,
            text="请将订阅/节点二维码完整显示在屏幕上\n（可先把本窗口移开），再点击下方按钮",
            font=("Microsoft YaHei UI", 12),
            text_color=("gray40", "gray60"),
            justify="center",
        ).pack(pady=(0, 10))

        # 简易取景框
        frame = ctk.CTkFrame(win, width=240, height=240, fg_color=("gray90", "gray20"), corner_radius=12)
        frame.pack(pady=8)
        frame.pack_propagate(False)
        ctk.CTkLabel(
            frame,
            text="▢\n\n将二维码置于屏幕可见区域\n\n▢",
            font=("Microsoft YaHei UI", 14),
            text_color=("#2563EB", "#60A5FA"),
            justify="center",
        ).pack(expand=True)

        status = ctk.CTkLabel(win, text="等待开始…", font=("Microsoft YaHei UI", 12))
        status.pack(pady=8)

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(side="bottom", fill="x", padx=20, pady=16)

        def do_close():
            try:
                win.grab_release()
            except Exception:
                pass
            win.destroy()

        def do_scan():
            status.configure(text="3 秒后截屏，请露出二维码…")
            scan_btn.configure(state="disabled")

            def _countdown(n):
                if n > 0:
                    status.configure(text="%d 秒后截屏…" % n)
                    win.after(1000, lambda: _countdown(n - 1))
                else:
                    status.configure(text="正在截屏识别…")
                    Thread(target=self._scan_screen_qr_worker, args=(win, status, scan_btn), daemon=True).start()

            # 先隐藏扫码窗，避免挡到二维码
            try:
                win.withdraw()
            except Exception:
                pass
            self.after(300, lambda: _countdown(2))

        scan_btn = ctk.CTkButton(btn_row, text="开始识别", width=120, height=36, fg_color="#2563EB", command=do_scan)
        scan_btn.pack(side="right")
        ctk.CTkButton(btn_row, text="取消", width=90, height=36, command=do_close).pack(side="right", padx=(0, 8))

    def _scan_screen_qr_worker(self, win, status_label, scan_btn):
        def ui(msg, reopen=False):
            def _():
                try:
                    if reopen:
                        win.deiconify()
                        win.lift()
                    status_label.configure(text=msg)
                    scan_btn.configure(state="normal")
                except Exception:
                    pass
            self.after(0, _)

        try:
            from PIL import ImageGrab
        except Exception:
            ui("缺少 Pillow，无法截屏", reopen=True)
            return

        try:
            img = ImageGrab.grab()
        except Exception as e:
            ui("截屏失败：%s" % e, reopen=True)
            return

        texts = []
        try:
            from pyzbar.pyzbar import decode as zbar_decode
            for obj in zbar_decode(img):
                try:
                    texts.append(obj.data.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
        except Exception:
            pass
        if not texts:
            try:
                import cv2
                import numpy as np
                arr = np.array(img.convert("RGB"))
                arr = arr[:, :, ::-1]
                det = cv2.QRCodeDetector()
                val, _, _ = det.detectAndDecode(arr)
                if val:
                    texts.append(val)
                # multi
                try:
                    ok, decoded, _, _ = det.detectAndDecodeMulti(arr)
                    if ok and decoded:
                        for v in decoded:
                            if v and v not in texts:
                                texts.append(v)
                except Exception:
                    pass
            except Exception:
                pass

        if not texts:
            self.log("未识别到二维码。请把二维码完整显示在屏幕上后重试")
            ui("未识别到二维码，请重试", reopen=True)
            return

        self.log("识别到 %d 个二维码" % len(texts))
        # 复用原有导入逻辑
        try:
            self._import_qr_texts(texts)
            ui("导入成功", reopen=True)
            self.after(1000, lambda: win.destroy() if win.winfo_exists() else None)
        except Exception as e:
            self.log("扫码导入失败：%s" % e)
            ui("导入失败：%s" % e, reopen=True)

    def _import_qr_texts(self, texts):
        """解析扫码文本并入订阅/节点。"""
        from urllib.parse import urlparse
        added_nodes = []
        for i, text in enumerate(texts):
            text = (text or "").strip()
            if not text:
                continue
            self.log("二维码%d：%s%s" % (i + 1, text[:80], "..." if len(text) > 80 else ""))
            low = text.lower()
            if low.startswith("http://") or low.startswith("https://"):
                try:
                    nm = (urlparse(text).netloc or "")[:20] or ("扫码订阅%d" % (len(self.subscriptions) + 1))
                except Exception:
                    nm = "扫码订阅%d" % (len(self.subscriptions) + 1)
                self.subscriptions.append({"name": nm, "url": text})
                self.subscription_url = text
                try:
                    self.entry.delete(0, "end")
                    self.entry.insert(0, text)
                    self.load_nodes_thread()
                except Exception:
                    pass
            else:
                node = None
                try:
                    node = parse_link(text)
                except Exception:
                    node = None
                if node:
                    added_nodes.append(node)
                else:
                    try:
                        more = parse_subscription_content(text)
                        if more:
                            added_nodes.extend(more)
                    except Exception:
                        pass
        if added_nodes:
            self.nodes = list(self.nodes or []) + added_nodes
            # 去重
            seen = set()
            merged = []
            for n in self.nodes:
                key = "%s|%s|%s" % (n.get("protocol"), n.get("address"), n.get("port"))
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
            self.log("扫码导入完成，当前共 %d 个节点" % len(self.nodes))
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
            sp_s = self._safe_widget_get("socks_entry", None)
            hp_s = self._safe_widget_get("http_entry", None)
            if sp_s is not None and hp_s is not None:
                sp = int(str(sp_s).strip())
                hp = int(str(hp_s).strip())
                if 1 <= sp <= 65535 and 1 <= hp <= 65535 and sp != hp:
                    return sp, hp
        except Exception:
            pass
        return int(getattr(self, "socks_port", 10808) or 10808), int(getattr(self, "http_port", 10809) or 10809)

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
            pystray.MenuItem("启动 / 重连", self.tray_start),
            pystray.MenuItem("停止代理", self.tray_stop),
            pystray.MenuItem("重新连接当前节点", lambda: self.after(0, self._tray_reconnect)),
            pystray.MenuItem("切换最低延迟节点", lambda: self.after(0, self._tray_select_best)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("切换：规则模式", lambda: self.after(0, lambda: self._tray_set_mode("规则模式"))),
            pystray.MenuItem("切换：全局模式", lambda: self.after(0, lambda: self._tray_set_mode("全局模式"))),
            pystray.MenuItem("切换：PAC模式", lambda: self.after(0, lambda: self._tray_set_mode("PAC模式"))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("显示当前状态", lambda: self.after(0, self._tray_show_status)),
            pystray.MenuItem("清除系统代理", lambda: self.after(0, self._hotkey_clear_proxy)),
            pystray.MenuItem("退出", self.tray_quit),
        )
        img = self.load_tray_image("disconnected")
        self.tray_icon = pystray.Icon("Mobility", img, "Mobility - 未连接", menu)
        Thread(target=self.tray_icon.run, daemon=True).start()

    def tray_show_window(self, icon=None, item=None):
        def _do():
            try:
                self.deiconify()
            except Exception:
                pass
            try:
                w = int(self.winfo_width() or 0)
                h = int(self.winfo_height() or 0)
                if w < 500 or h < 400:
                    self.geometry("1100x720")
            except Exception:
                try:
                    self.geometry("1100x720")
                except Exception:
                    pass
            try:
                self.lift()
                self.focus_force()
                self.attributes("-topmost", True)
                self.after(180, lambda: self.attributes("-topmost", False))
            except Exception:
                pass
            try:
                self.update_idletasks()
            except Exception:
                pass
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

    def _tray_set_mode(self, mode: str):
        try:
            if mode in PROXY_MODES:
                self.proxy_mode = mode
                if hasattr(self, "mode_combo"):
                    self.mode_combo.set(mode)
                self.save_settings()
                self.log("托盘切换模式：" + mode)
                if self.is_running:
                    self.stop_proxy()
                    self.after(400, self.start_proxy_thread)
        except Exception as e:
            self.log("托盘切换模式失败：%s" % e)


    def _tray_reconnect(self):
        """托盘：停止后重连当前节点。"""
        try:
            if self.is_running:
                self.stop_proxy()
            self.after(400, self.start_proxy_thread)
            self.log("托盘：重新连接当前节点")
        except Exception as e:
            self.log("托盘重连失败：%s" % e)

    def _tray_select_best(self):
        try:
            if not self.nodes:
                self.log("托盘：无节点，请先加载订阅")
                return
            self.select_best()
            if self.is_running:
                self._tray_reconnect()
            else:
                self.log("托盘：已切换到最低延迟节点（未启动，可点启动）")
        except Exception as e:
            self.log("托盘切换最快节点失败：%s" % e)

    def _tray_show_status(self):
        try:
            st = "运行中" if self.is_running else "未运行"
            node = getattr(self, "current_node", None) or {}
            name = node.get("name") or "无"
            lat = node.get("latency")
            lat_s = "%sms" % lat if isinstance(lat, int) and lat >= 0 else "未测速"
            mode = getattr(self, "proxy_mode", "")
            core = getattr(self, "proxy_core", "")
            msg = "%s | %s | %s | %s (%s)" % (st, mode, core, name, lat_s)
            self.log("托盘状态：" + msg)
            try:
                if self.tray_icon:
                    self.tray_icon.title = "Mobility - " + msg[:80]
            except Exception:
                pass
        except Exception as e:
            self.log("托盘状态失败：%s" % e)


    def save_settings(self):
        try:
            slim_nodes = []
            for n in (self.nodes or []):
                if not isinstance(n, dict):
                    continue
                item = {}
                for k, v in n.items():
                    if str(k).startswith("_"):
                        continue
                    item[k] = v
                g = n.get("_group") or n.get("group")
                if g:
                    item["group"] = g
                slim_nodes.append(item)

            def read_str(attr_widget, attr_fallback, default=""):
                w = getattr(self, attr_widget, None)
                if w is not None:
                    try:
                        return str(w.get())
                    except Exception:
                        pass
                return str(getattr(self, attr_fallback, default) or default)

            def read_bool(attr_widget, attr_fallback, default=False):
                w = getattr(self, attr_widget, None)
                if w is not None:
                    try:
                        return bool(w.get())
                    except Exception:
                        pass
                return bool(getattr(self, attr_fallback, default))

            entry_txt = ""
            w = getattr(self, "entry", None)
            if w is not None:
                try:
                    entry_txt = str(w.get() or "").strip()
                except Exception:
                    entry_txt = ""

            cur = getattr(self, "current_node", None)
            selected_label = ""
            if isinstance(cur, dict):
                selected_label = cur.get("_label") or cur.get("name") or ""

            data = {
                "subscription_url": getattr(self, "subscription_url", "") or entry_txt,
                "subscriptions": list(getattr(self, "subscriptions", []) or []),
                "tun_enabled": bool(getattr(self, "tun_enabled", False)),
                "live_stats_enabled": True,
                "tun_settings": dict(getattr(self, "tun_settings", {}) or {}),
                "routing_extra_direct": getattr(self, "routing_extra_direct", "") or "",
                "routing_extra_proxy": getattr(self, "routing_extra_proxy", "") or "",
                "routing_extra_block": getattr(self, "routing_extra_block", "") or "",
                "nodes": slim_nodes,
                "selected_label": selected_label,
                "test_workers": read_str("workers_combo", "test_workers", str(TEST_WORKERS_DEFAULT)),
                "proxy_mode": read_str("mode_combo", "proxy_mode", PROXY_MODE_DEFAULT),
                "close_to_tray": read_bool("tray_check", "close_to_tray", True),
                "auto_start": read_bool("autostart_check", "auto_start", False),
                "auto_connect": read_bool("autoconnect_check", "auto_connect", False),
                "socks_port": self.get_ports()[0],
                "http_port": self.get_ports()[1],
                "refresh_label": read_str("refresh_interval_combo", "refresh_label", "不自动更新"),
                "start_minimized": read_bool("minimized_check", "start_minimized", False),
                "theme_label": read_str("theme_combo", "theme_label", "跟随系统"),
                "allow_lan": read_bool("lan_check", "allow_lan", False),
                "direct_domains": read_str("direct_entry", "direct_domains", ""),
                "proxy_domains": read_str("proxy_entry", "proxy_domains", ""),
                "dns_mode": read_str("dns_combo", "dns_mode", "系统默认"),
                "dns_custom": read_str("dns_entry", "dns_custom", ""),
                "log_level": read_str("loglevel_combo", "log_level", "调试"),
                "proxy_core": getattr(self, "proxy_core", "Xray") or "Xray",
                "core_map": dict(getattr(self, "core_map", None) or DEFAULT_CORE_MAP),
                "test_timeout": float(getattr(self, "test_timeout", DEFAULT_TEST_TIMEOUT) or DEFAULT_TEST_TIMEOUT),
                "group_nodes_by_sub": bool(getattr(self, "group_nodes_by_sub", True)),
                "rule_set_urls": list(getattr(self, "rule_set_urls", []) or []),
                "connectivity_urls": [],
            }
            try:
                lv = getattr(self, "live_stats_var", None)
                if lv is not None:
                    data["live_stats_enabled"] = bool(lv.get())
            except Exception:
                data["live_stats_enabled"] = bool(getattr(self, "live_stats_enabled", False))

            cu_out = []
            for x in (getattr(self, "connectivity_urls", None) or DEFAULT_CONNECTIVITY_URLS or []):
                try:
                    if isinstance(x, (list, tuple)) and x:
                        cu_out.append([str(x[0]), str(x[1] if len(x) > 1 else x[0])])
                    elif isinstance(x, dict) and x.get("url"):
                        cu_out.append([str(x.get("url")), str(x.get("name") or x.get("url"))])
                except Exception:
                    continue
            data["connectivity_urls"] = cu_out

            self.settings_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
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
                if getattr(self, "entry", None) is not None:
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
            self.live_stats_enabled = bool(data.get("live_stats_enabled", True))
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
            ts = data.get("tun_settings") or {}
            self.tun_settings = dict(DEFAULT_TUN_SETTINGS)
            if isinstance(ts, dict):
                self.tun_settings.update(ts)
            self.routing_extra_direct = data.get("routing_extra_direct") or ""
            self.routing_extra_proxy = data.get("routing_extra_proxy") or ""
            self.routing_extra_block = data.get("routing_extra_block") or ""
            try:
                self.test_timeout = float(data.get("test_timeout") or DEFAULT_TEST_TIMEOUT)
            except Exception:
                self.test_timeout = DEFAULT_TEST_TIMEOUT
            self.group_nodes_by_sub = bool(data.get("group_nodes_by_sub", True))
            self.rule_set_urls = data.get("rule_set_urls") if isinstance(data.get("rule_set_urls"), list) else []
            cu = data.get("connectivity_urls")
            if isinstance(cu, list) and cu:
                parsed = []
                for item in cu:
                    if isinstance(item, (list, tuple)) and item:
                        parsed.append((item[0], item[1] if len(item) > 1 else item[0]))
                    elif isinstance(item, dict) and item.get("url"):
                        parsed.append((item.get("url"), item.get("name") or item.get("url")))
                if parsed:
                    self.connectivity_urls = parsed
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
            if getattr(self, "socks_entry", None) is not None:
                self.socks_entry.delete(0, "end")
                self.socks_entry.insert(0, str(self.socks_port))
            if getattr(self, "http_entry", None) is not None:
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
            if getattr(self, "direct_entry", None) is not None:
                self.direct_entry.delete(0, "end")
                self.direct_entry.insert(0, self.direct_domains)
            if getattr(self, "proxy_entry", None) is not None:
                self.proxy_entry.delete(0, "end")
                self.proxy_entry.insert(0, self.proxy_domains)
            self.dns_mode = data.get("dns_mode") or "系统默认"
            if self.dns_mode in DNS_OPTIONS and hasattr(self, "dns_combo"):
                self.dns_combo.set(self.dns_mode)
            self.dns_custom = data.get("dns_custom") or "8.8.8.8,1.1.1.1"
            if getattr(self, "dns_entry", None) is not None:
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
            self.log_level = raw_lv if raw_lv in LOG_LEVELS else "调试"
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

    def _toggle_group_collapse(self, name: str):
        """点击三角形：折叠/展开；展开时同时选中该组为测速组。"""
        if not hasattr(self, "_collapsed_groups") or not isinstance(self._collapsed_groups, set):
            self._collapsed_groups = set()
        if name in self._collapsed_groups:
            # 展开 + 选中
            self._collapsed_groups.discard(name)
            self._active_test_group = name
            try:
                self.log("已展开并选中分组：%s" % name)
            except Exception:
                pass
        else:
            # 折叠（保持选中状态，便于折叠后仍测该组）
            self._collapsed_groups.add(name)
        self.refresh_node_list(keep_selection=True, resort=False)

    def _on_group_header_click(self, name: str):
        """单击分组栏：一次选中该组并展开（不自动测速、不二次折叠）。"""
        if not hasattr(self, "_collapsed_groups") or not isinstance(self._collapsed_groups, set):
            self._collapsed_groups = set()
        was_active = (getattr(self, "_active_test_group", None) == name)
        was_collapsed = name in self._collapsed_groups
        # 始终展开；选中新组时切换高亮
        self._collapsed_groups.discard(name)
        self._active_test_group = name
        if not was_active:
            try:
                self.log("已选择测速分组：%s（点「测速所选分组」开始）" % name)
            except Exception:
                pass
        # 仅折叠状态变化才整表刷新；只换高亮则原地改颜色，避免二次刷新卡顿
        if was_collapsed:
            try:
                self.refresh_node_list(keep_selection=True, resort=False)
            except Exception:
                pass
        else:
            try:
                self._paint_group_headers()
            except Exception:
                try:
                    self.refresh_node_list(keep_selection=True, resort=False)
                except Exception:
                    pass

    def _focus_group_only(self, keep_name: str):
        """只展开 keep_name，其余分组全部收起。"""
        keep_name = (keep_name or "").strip()
        if not keep_name:
            return
        if not hasattr(self, "_collapsed_groups") or not isinstance(self._collapsed_groups, set):
            self._collapsed_groups = set()
        # 收集全部分组名
        names = set()
        for n in self.nodes or []:
            if not isinstance(n, dict):
                continue
            g = (n.get("_group") or n.get("group") or "").strip()
            if g:
                names.add(g)
        for g in names:
            if g == keep_name:
                self._collapsed_groups.discard(g)
            else:
                self._collapsed_groups.add(g)
        self._active_test_group = keep_name

    def _paint_group_headers(self):
        """只更新分组标题高亮，不重建节点列表。"""
        active = getattr(self, "_active_test_group", None)
        for item in getattr(self, "_group_header_meta", None) or []:
            g = item.get("name")
            btn = item.get("btn")
            if not btn:
                continue
            is_active = (g == active)
            try:
                btn.configure(
                    fg_color=("#F59E0B", "#D97706") if is_active else "transparent",
                    text_color=("white", "white") if is_active else ("#2563EB", "#93C5FD"),
                    hover_color=("#FBBF24", "#B45309") if is_active else ("gray90", "gray25"),
                )
            except Exception:
                pass


    def refresh_node_list(self, keep_selection: bool = True, resort: bool = False):
        """刷新节点列表：按订阅分组 + 拖拽排序。"""
        try:
            import time as _t
            now = _t.time()
            last = float(getattr(self, "_last_refresh_ts", 0) or 0)
            if (now - last) < 0.4 and not resort:
                self._refresh_pending = (keep_selection, resort)
                if not getattr(self, "_refresh_scheduled", False):
                    self._refresh_scheduled = True
                    def _later():
                        self._refresh_scheduled = False
                        pend = getattr(self, "_refresh_pending", None)
                        if pend is not None:
                            self._refresh_pending = None
                            self.refresh_node_list(pend[0], pend[1])
                    self.after(450, _later)
                return
            self._last_refresh_ts = now
        except Exception:
            pass
        try:
            nodes = list(self.nodes or [])
            self.clear_node_list_ui()
            self._node_row_meta = []
            self._group_header_meta = []

            if not nodes:
                try:
                    self.node_count_label.configure(text="节点：0")
                except Exception:
                    pass
                empty = ctk.CTkLabel(
                    self.node_list, text="（请先加载订阅或节点）",
                    font=("Microsoft YaHei UI", 12), text_color=("gray50", "gray55"),
                )
                empty.pack(pady=20)
                self._node_buttons.append(empty)
                return

            if resort:
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
            group_by = bool(getattr(self, "group_nodes_by_sub", False))
            collapsed = getattr(self, "_collapsed_groups", None)
            if not isinstance(collapsed, set):
                collapsed = set()
                self._collapsed_groups = collapsed

            display = []
            groups, order = {}, []
            for n in self.nodes:
                raw_g = (n.get("_group") or n.get("group") or n.get("sub") or "").strip() or "未分组"
                is_local = raw_g.startswith("本地") or bool(n.get("from_local"))
                if raw_g in ("未分组", "默认"):
                    g = raw_g
                else:
                    try:
                        g = normalize_group_name(raw_g, local=is_local)
                    except Exception:
                        g = raw_g
                    if g != raw_g:
                        n["_group"] = g
                        n["group"] = g
                if g not in groups:
                    groups[g] = []
                    order.append(g)
                groups[g].append(n)
            # 组内按延迟从小到大（超时/未测排后）
            def _lat_key(n):
                lat = n.get("latency")
                if lat is None:
                    return (2, 999999)
                try:
                    v = int(lat)
                except Exception:
                    return (2, 999999)
                if v < 0:
                    return (1, 999999)
                return (0, v)
            for g in list(groups.keys()):
                groups[g] = sorted(groups[g], key=_lat_key)

            # 超过一组就显示分组标题；设置里可关
            show_headers = len(order) > 1
            if not group_by:
                show_headers = False
            if group_by and len(order) == 1 and order[0] not in ("未分组", "默认"):
                show_headers = True

            if show_headers:
                for g in order:
                    display.append(("group", g))
                    if g in collapsed:
                        continue
                    for n in groups[g]:
                        display.append(("node", n))
            else:
                for n in self.nodes:
                    display.append(("node", n))

            for kind, payload in display:
                if kind == "group":
                    g = payload
                    is_collapsed = g in collapsed
                    mark = "▸" if is_collapsed else "▾"
                    cnt = len(groups.get(g, []))
                    is_active = (getattr(self, "_active_test_group", None) or "") == g
                    row_g = ctk.CTkFrame(self.node_list, fg_color="transparent")
                    row_g.pack(fill="x", padx=4, pady=(6, 1))
                    # 左侧三角形：仅负责折叠/展开
                    tri = ctk.CTkButton(
                        row_g,
                        text=mark,
                        width=32,
                        height=28,
                        fg_color="transparent",
                        text_color=("#2563EB", "#93C5FD"),
                        hover_color=("gray90", "gray25"),
                        font=("Microsoft YaHei UI", 14, "bold"),
                        command=lambda name=g: self._toggle_group_collapse(name),
                    )
                    tri.pack(side="left", padx=(0, 2))
                    # 右侧标题：选中测速分组
                    hdr = ctk.CTkButton(
                        row_g,
                        text=f"{g}  ({cnt})",
                        anchor="w",
                        height=28,
                        fg_color=("#F59E0B", "#D97706") if is_active else "transparent",
                        text_color=("white", "white") if is_active else ("#2563EB", "#93C5FD"),
                        hover_color=("#FBBF24", "#B45309") if is_active else ("gray90", "gray25"),
                        font=("Microsoft YaHei UI", 12, "bold"),
                        command=lambda name=g: self._on_group_header_click(name),
                    )
                    hdr.pack(side="left", fill="x", expand=True)
                    if not hasattr(self, "_group_header_meta") or self._group_header_meta is None:
                        self._group_header_meta = []
                    self._group_header_meta.append({"name": g, "btn": hdr, "tri": tri})
                    continue
                n = payload
                try:
                    lb = node_label(n)
                except Exception:
                    lb = n.get("name") or "节点"
                n["_label"] = lb
                if kw:
                    blob = f"{n.get('name','')} {n.get('address','')} {n.get('protocol','')} {n.get('_group','')}".lower()
                    if kw not in blob:
                        continue
                row = ctk.CTkFrame(self.node_list, fg_color="transparent")
                row.pack(fill="x", pady=1, padx=2)
                btn = ctk.CTkButton(
                    row, text=lb, anchor="w", height=30,
                    fg_color=("gray85", "gray25"), text_color=("gray10", "gray90"),
                    hover_color=("#93C5FD", "#1E3A8A"), font=("Microsoft YaHei UI", 12),
                )
                btn.pack(side="left", fill="x", expand=True)
                btn.configure(command=lambda node=n, b=btn: self.on_node_button_click(node, b))
                btn.bind("<ButtonPress-1>", lambda e, node=n, b=btn: self._node_drag_start(e, node, b))
                btn.bind("<B1-Motion>", lambda e, node=n, b=btn: self._node_drag_motion(e, node, b))
                btn.bind("<ButtonRelease-1>", lambda e, node=n, b=btn: self._node_drag_end(e, node, b))
                self._node_buttons.append(btn)
                self._node_row_meta.append({"node": n, "btn": btn, "row": row})
                shown += 1
                # 不在这里按文本高亮，统一走 _paint_node_buttons，避免同延迟同名多选

            try:
                self.node_count_label.configure(text=f"节点：{shown}/{len(self.nodes)}")
            except Exception:
                pass
            # 恢复唯一高亮（按节点键，不会把同延迟节点全选中）
            try:
                self._paint_node_buttons()
            except Exception:
                pass
            try:
                cn = getattr(self, "current_node", None)
                if isinstance(cn, dict):
                    self.current_label.configure(text=self._short_node_text(cn))
            except Exception:
                pass
        except Exception as e:
            try:
                self.log(f"刷新节点列表失败：{e}")
            except Exception:
                pass

    def _node_drag_start(self, event, node, btn):
        self._drag_data = {"node": node, "btn": btn, "start_y": event.y_root, "moved": False}
        try:
            btn.configure(fg_color=("#FDBA74", "#9A3412"))
        except Exception:
            pass

    def _node_drag_motion(self, event, node, btn):
        d = getattr(self, "_drag_data", None)
        if not d or d.get("node") is not node:
            return
        if abs(event.y_root - d.get("start_y", 0)) > 6:
            d["moved"] = True

    def _node_drag_end(self, event, node, btn):
        d = getattr(self, "_drag_data", None)
        self._drag_data = None
        if not d or d.get("node") is not node:
            return
        if not d.get("moved"):
            try:
                self.on_node_button_click(node, btn)
            except Exception:
                pass
            return
        target = None
        try:
            y = event.y_root
            nearest, best_dist = None, 10**9
            for meta in getattr(self, "_node_row_meta", []) or []:
                b = meta.get("btn")
                n2 = meta.get("node")
                if not b or n2 is None:
                    continue
                try:
                    by = b.winfo_rooty()
                    bh = b.winfo_height() or 30
                    if by <= y <= by + bh:
                        target = n2
                        break
                    dist = abs(by + bh / 2 - y)
                    if dist < best_dist:
                        best_dist, nearest = dist, n2
                except Exception:
                    continue
            if target is None:
                target = nearest
        except Exception:
            target = None
        if not target or target is node:
            try:
                self.on_node_button_click(node, btn)
            except Exception:
                pass
            return
        try:
            nodes = list(self.nodes or [])
            i = nodes.index(node)
            j = nodes.index(target)
            nodes.pop(i)
            nodes.insert(j, node)
            self.nodes = nodes
            self.current_node = node
            self._selected_label = node.get("_label")
            self.refresh_node_list(keep_selection=True, resort=False)
            self.save_settings()
            self.log("已拖拽调整节点顺序")
        except Exception as e:
            self.log(f"拖拽排序失败：{e}")


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
        # 保留本地导入等非在线订阅组
        keep_nodes = []
        for n in list(self.nodes or []):
            if not isinstance(n, dict):
                continue
            g = str(n.get("_group") or n.get("group") or "")
            if g.startswith("本地:") or g.startswith("本地：") or n.get("from_local"):
                keep_nodes.append(n)
        all_nodes = []
        seen = set()
        for n in keep_nodes:
            key = f"{n.get('protocol')}|{n.get('address')}|{n.get('port')}|{n.get('name')}"
            seen.add(key)
            all_nodes.append(n)
        for s in self.subscriptions:
            url = s.get("url") or ""
            if not url:
                continue
            try:
                self.log(f"更新订阅：{s.get('name')} ...")
                resp = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0 Mobility"})
                resp.raise_for_status()
                nodes = parse_nodes_any(resp.text) or parse_subscription_content(resp.text)
                gname = normalize_group_name(s.get("name") or (url[:24] if url else "订阅"), local=False)
                cnt = 0
                for n in nodes or []:
                    if not isinstance(n, dict):
                        continue
                    n["_group"] = gname
                    n["group"] = gname
                    n["from_sub"] = s.get("name")
                    key = f"{n.get('protocol')}|{n.get('address')}|{n.get('port')}|{n.get('name')}"
                    if key in seen:
                        continue
                    seen.add(key)
                    all_nodes.append(n)
                    cnt += 1
                self.log(f"  -> {cnt} 个节点（组：{gname}）")
            except Exception as e:
                self.log(f"  失败：{e}")
        self.nodes = all_nodes
        self.group_nodes_by_sub = True

        def _ui():
            self.refresh_node_list(keep_selection=False)
            self.save_settings()
            self.load_btn.configure(state="normal")
            local_n = sum(1 for n in self.nodes if str(n.get('_group') or '').startswith('本地:'))
            self.log(f"全部订阅更新完成：合计 {len(self.nodes)}（其中本地保留 {local_n}）")
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

        prev_nodes = list(self.nodes or [])
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
                last_err = None
                resp = None
                for attempt in range(2):
                    try:
                        resp = requests.get(
                            text,
                            timeout=20,
                            headers={"User-Agent": "Mozilla/5.0 Mobility/0.4"}
                        )
                        resp.raise_for_status()
                        break
                    except Exception as e:
                        last_err = e
                        if attempt == 0:
                            self.log("订阅拉取失败，1 秒后重试…")
                            time.sleep(1)
                        else:
                            raise last_err
                new_nodes = parse_nodes_any(resp.text) or parse_subscription_content(resp.text)
                sub_name = "订阅"
                try:
                    if getattr(self, "sub_select", None) is not None:
                        sub_name = (self.sub_select.get() or "订阅").strip() or "订阅"
                except Exception:
                    pass
                try:
                    for s in self.subscriptions or []:
                        if (s.get("url") or "").strip() == text:
                            sub_name = (s.get("name") or sub_name).strip() or sub_name
                            break
                except Exception:
                    pass
                sub_name = normalize_group_name(sub_name, local=False)
                for n in new_nodes or []:
                    if isinstance(n, dict):
                        n["_group"] = sub_name
                        n["group"] = sub_name
                # 多订阅共存：只替换本订阅组，保留其它在线组与本地组
                seen = set()
                merged = []
                for n in list(prev_nodes or []):
                    if not isinstance(n, dict):
                        continue
                    g = (n.get("_group") or n.get("group") or "").strip()
                    if g == sub_name:
                        continue
                    key = "%s|%s|%s|%s" % (n.get("protocol"), n.get("address"), n.get("port"), n.get("name"))
                    if key in seen:
                        continue
                    seen.add(key)
                    merged.append(n)
                added = 0
                for n in list(new_nodes or []):
                    if not isinstance(n, dict):
                        continue
                    key = "%s|%s|%s|%s" % (n.get("protocol"), n.get("address"), n.get("port"), n.get("name"))
                    if key in seen:
                        continue
                    seen.add(key)
                    merged.append(n)
                    added += 1
                self.nodes = merged
                self.group_nodes_by_sub = True
                # 新拉取的分组默认折叠，避免展开大量节点导致卡顿
                try:
                    if not hasattr(self, "_collapsed_groups") or not isinstance(self._collapsed_groups, set):
                        self._collapsed_groups = set()
                    self._collapsed_groups.add(sub_name)
                except Exception:
                    pass
                self.log("订阅解析完成：本组 %s 个，合计 %s 个（多订阅共存，新组已折叠）" % (added, len(self.nodes)))
            else:
                self.subscription_url = ""
                if "://" in text and "\n" not in text:
                    node = parse_link(text)
                    if node:
                        # 单节点追加，不清空已有
                        node["_group"] = node.get("_group") or "手动导入"
                        prev = list(prev_nodes or [])
                        prev.append(node)
                        self.nodes = prev
                    else:
                        self.nodes = prev_nodes
                else:
                    parsed = parse_subscription_content(text) or parse_nodes_any(text) or []
                    for n in parsed:
                        if isinstance(n, dict) and not n.get("_group"):
                            n["_group"] = "手动导入"
                    seen = set()
                    merged = list(prev_nodes or [])
                    for n in merged:
                        if isinstance(n, dict):
                            seen.add("%s|%s|%s|%s" % (n.get("protocol"), n.get("address"), n.get("port"), n.get("name")))
                    for n in parsed:
                        if not isinstance(n, dict):
                            continue
                        key = "%s|%s|%s|%s" % (n.get("protocol"), n.get("address"), n.get("port"), n.get("name"))
                        if key in seen:
                            continue
                        seen.add(key)
                        merged.append(n)
                    self.nodes = merged
                self.log("解析完成，共 %s 个节点" % len(self.nodes or []))
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

        def _ui_ok():
            try:
                self.log(f"解析到 {count} 个节点，正在刷新列表...")
                # 拉取成功后清空中间网址框（订阅已在下拉中）
                try:
                    if text.startswith(("http://", "https://")):
                        self.entry.delete(0, "end")
                except Exception:
                    pass
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

    def test_current_group_thread(self):
        if self.is_testing:
            self.log("正在测速中，请稍候...")
            return
        if not self.nodes:
            self.log("请先加载节点")
            return
        g = (getattr(self, "_active_test_group", None) or "").strip()
        if not g:
            node = getattr(self, "current_node", None) or getattr(self, "_pending_node", None)
            if not node:
                for n in self.nodes:
                    if isinstance(n, dict):
                        node = n
                        break
            if node:
                g = (node.get("_group") or node.get("group") or "未分组").strip() or "未分组"
        if not g:
            self.log("请先点击要测速的分组栏，再点「当前分组测速」")
            return
        self._active_test_group = g
        Thread(target=lambda gg=g: self.test_all(only_filtered=False, only_group=gg), daemon=True).start()

    def test_all(self, only_filtered: bool = False, only_group: str | None = None):

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

        if only_group:
            g0 = str(only_group).strip()
            targets = [
                (i, n) for i, n in targets
                if ((n.get("_group") or n.get("group") or "").strip() or "未分组") == g0
            ]
            self._last_tested_group = g0
            self.log("仅测速当前分组：%s（%s 个）" % (g0, len(targets)))
        else:
            self._last_tested_group = None

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
        timeout = float(getattr(self, "test_timeout", DEFAULT_TEST_TIMEOUT) or DEFAULT_TEST_TIMEOUT)
        self.log(f"开始并行测速：{total} 个节点，并发 {workers}，超时 {timeout}s")

        t_start = time.perf_counter()

        def _one(pair):
            i, node = pair
            ms = tcp_ping(node["address"], int(node["port"]), timeout=timeout)
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

        try:
            # 重建列表以按组内延迟排序
            self.after(0, lambda: self.refresh_node_list(keep_selection=True, resort=False))
        except Exception:
            try:
                self.after(0, self._update_node_latency_labels)
            except Exception:
                pass
        try:
            self.after(0, self.select_best)
        except Exception:
            pass
        try:
            self.save_settings()
        except Exception:
            pass

        self.is_testing = False
        self.after(0, lambda: self.test_btn.configure(state="normal"))
        self.after(0, lambda: self.load_btn.configure(state="normal"))
        if hasattr(self, "test_filter_btn"):
            self.after(0, lambda: self.test_filter_btn.configure(state="normal"))

    def select_best(self):
        if not self.nodes:
            self.log("没有节点可选")
            return
        # 优先：刚测过的分组；否则当前选中节点所在分组
        prefer_g = (getattr(self, "_last_tested_group", None) or "").strip()
        if not prefer_g:
            cur = getattr(self, "current_node", None) or getattr(self, "_pending_node", None) or {}
            prefer_g = (cur.get("_group") or cur.get("group") or "").strip()
        pool = []
        for n in self.nodes:
            lat = n.get("latency")
            if lat is None or (isinstance(lat, (int, float)) and lat < 0):
                continue
            if prefer_g:
                g = (n.get("_group") or n.get("group") or "").strip()
                if g != prefer_g:
                    continue
            pool.append(n)
        if not pool:
            pool = [n for n in self.nodes if isinstance(n.get("latency"), int) and n.get("latency") >= 0]
        best = None
        for n in pool:
            lat = n.get("latency")
            if best is None or lat < best["latency"]:
                best = n
            elif best is not None and lat == best["latency"]:
                if node_key(n) < node_key(best):
                    best = n
        if best is None:
            self.log("没有测速成功的节点，请先点「当前分组测速」或「测速全部」")
            return
        self.current_node = best
        self._selected_label = best.get("_label") or best.get("name")
        self._pending_node = best
        self._pending_label = self._selected_label
        self._pending_key = node_key(best)
        self.refresh_node_list(keep_selection=True, resort=False)
        try:
            self._paint_node_buttons()
        except Exception:
            pass
        try:
            self.current_label.configure(text=self._short_node_text(best, f"{best.get('latency')}ms"))
        except Exception:
            pass
        self.log(f"已选择最低延迟：{best['name']} ({best['latency']}ms)")
        self.save_settings()

    def resolve_live_node(self, node):
        """按唯一键从当前 self.nodes 取最新节点对象，避免列表刷新后引用失效。"""
        if not isinstance(node, dict):
            return None
        try:
            k = node_key(node)
        except Exception:
            k = None
        if k:
            for n in self.nodes or []:
                if not isinstance(n, dict):
                    continue
                try:
                    if node_key(n) == k:
                        return n
                except Exception:
                    pass
        # 回退：地址端口协议
        addr, port, proto = node.get("address"), node.get("port"), node.get("protocol")
        for n in self.nodes or []:
            if not isinstance(n, dict):
                continue
            if n.get("address") == addr and n.get("port") == port and n.get("protocol") == proto:
                return n
        return node if node in (self.nodes or []) else None

    def get_selected_node(self):
        node = getattr(self, "current_node", None) or getattr(self, "_pending_node", None)
        live = self.resolve_live_node(node) if node else None
        if live:
            return live
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
        if getattr(self, "direct_entry", None) is not None:
            self.direct_domains = self.direct_entry.get().strip()
        if getattr(self, "proxy_entry", None) is not None:
            self.proxy_domains = self.proxy_entry.get().strip()
        self.save_settings()
        dd = self.parse_domain_list(self.direct_domains)
        pd = self.parse_domain_list(self.proxy_domains)
        self.log(f"自定义域名已保存：直连 {len(dd)} 条，代理 {len(pd)} 条")
        if self.is_running:
            self.log("域名规则已更改，请停止后重新启动代理以生效")


    def _safe_widget_get(self, name: str, default=""):
        """安全读取控件值，避免控件为 None 时 .get 报错。"""
        w = getattr(self, name, None)
        if w is None:
            return default
        try:
            return w.get()
        except Exception:
            return default

    def build_routing_rules(self) -> list:
        """根据代理模式生成路由规则"""
        mode = self.proxy_mode or PROXY_MODE_DEFAULT
        direct_txt = self._safe_widget_get("direct_entry", None)
        if direct_txt is None:
            direct_txt = getattr(self, "direct_domains", "") or ""
        proxy_txt = self._safe_widget_get("proxy_entry", None)
        if proxy_txt is None:
            proxy_txt = getattr(self, "proxy_domains", "") or ""
        custom_direct = self.parse_domain_list(direct_txt or "")
        custom_proxy = self.parse_domain_list(proxy_txt or "")

        rules = []
        # 自定义域名优先
        if custom_direct:
            rules.append({"type": "field", "outboundTag": "direct", "domain": custom_direct})
        if custom_proxy:
            rules.append({"type": "field", "outboundTag": "proxy", "domain": custom_proxy})
        extra_d = self.parse_domain_list(getattr(self, "routing_extra_direct", "") or "")
        extra_p = self.parse_domain_list(getattr(self, "routing_extra_proxy", "") or "")
        extra_b = self.parse_domain_list(getattr(self, "routing_extra_block", "") or "")
        if extra_d:
            rules.append({"type": "field", "outboundTag": "direct", "domain": extra_d})
        if extra_p:
            rules.append({"type": "field", "outboundTag": "proxy", "domain": extra_p})
        if extra_b:
            rules.append({"type": "field", "outboundTag": "block", "domain": extra_b})

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
        dns_mode = self._safe_widget_get("dns_combo", None)
        if dns_mode is None:
            dns_mode = getattr(self, "dns_mode", "系统默认") or "系统默认"
        dns_servers = DNS_PRESETS.get(dns_mode) if isinstance(DNS_PRESETS, dict) else None
        if dns_mode == "自定义":
            raw = self._safe_widget_get("dns_entry", None)
            if raw is None:
                raw = getattr(self, "dns_custom", "") or ""
            dns_servers = [x.strip() for x in str(raw).split(",") if x.strip()]
        log_level_label = self._safe_widget_get("loglevel_combo", None)
        if log_level_label is None:
            log_level_label = getattr(self, "log_level", "调试") or "调试"
        log_level = LOG_LEVEL_MAP.get(log_level_label, "warning") if isinstance(LOG_LEVEL_MAP, dict) else "warning"

        config = {
            "log": {
                "loglevel": log_level,
                "access": str(getattr(self, "logs_dir", self.core_dir) / "xray-access.log"),
                "error": str(getattr(self, "logs_dir", self.core_dir) / "xray-error.log"),
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
        try:
            _sp, _hp = self.get_ports()
            api_port = int(_hp) + 976
            if api_port > 60000:
                api_port = 10085
            self.api_port = api_port
        except Exception:
            api_port = int(getattr(self, "api_port", 10085))
        config["stats"] = {}
        config["api"] = {"tag": "api", "services": ["StatsService", "HandlerService"]}
        config["policy"] = {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            },
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
        if not any((o or {}).get("tag") == "api" for o in outs if isinstance(o, dict)):
            outs.append({"tag": "api", "protocol": "freedom"})
            config["outbounds"] = outs

        config_path = self.core_dir / "config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return config_path

    def write_pac_file(self, port: int) -> Path:
        """生成更稳妥的 PAC：直连内网/常用国内域名，其余走代理。"""
        pac_path = Path(getattr(self, "base_dir", Path("."))) / "mobility.pac"
        port = int(port)
        body = (
            "function FindProxyForURL(url, host) {\n"
            "  host = host.toLowerCase();\n"
            "  if (isPlainHostName(host) || shExpMatch(host, \"localhost\") ||\n"
            "      shExpMatch(host, \"127.*\") || shExpMatch(host, \"10.*\") ||\n"
            "      shExpMatch(host, \"192.168.*\") || shExpMatch(host, \"172.16.*\") ||\n"
            "      shExpMatch(host, \"172.17.*\") || shExpMatch(host, \"172.18.*\") ||\n"
            "      shExpMatch(host, \"172.19.*\") || shExpMatch(host, \"172.2*.*\") ||\n"
            "      shExpMatch(host, \"172.30.*\") || shExpMatch(host, \"172.31.*\") ||\n"
            "      shExpMatch(host, \"*.local\") || shExpMatch(host, \"*.lan\"))\n"
            "    return \"DIRECT\";\n"
            "  if (shExpMatch(host, \"*.cn\") || shExpMatch(host, \"*.baidu.com\") ||\n"
            "      shExpMatch(host, \"*.qq.com\") || shExpMatch(host, \"*.aliyun.com\") ||\n"
            "      shExpMatch(host, \"*.taobao.com\") || shExpMatch(host, \"*.jd.com\") ||\n"
            "      shExpMatch(host, \"*.163.com\") || shExpMatch(host, \"*.126.com\"))\n"
            "    return \"DIRECT\";\n"
            "  return \"PROXY 127.0.0.1:%d; DIRECT\";\n"
            "}\n"
        ) % port
        try:
            pac_path.write_text(body, encoding="utf-8")
        except Exception:
            pass
        return pac_path


    def apply_system_proxy_for_mode(self, port: int) -> bool:
        mode = getattr(self, "proxy_mode", "") or ""
        if "PAC" in mode:
            # 现代 Windows/浏览器常忽略 file:// PAC，导致网页全挂。
            # 等效实现：系统 HTTP 代理 + Xray 规则分流；同时写出 pac 文件供手工使用。
            try:
                self.write_pac_file(port)
            except Exception:
                pass
            ok = self.set_system_proxy(True, port, pac=False)
            if ok:
                self.log("PAC 模式：已设系统代理 127.0.0.1:%s（规则分流，兼容浏览器）" % port)
                self.log("已生成 mobility.pac（若需可在系统设置中手动指定）")
            return ok
        return self.set_system_proxy(True, port, pac=False)

    def _notify_proxy_change(self):
        """通知系统代理设置已变更。"""
        try:
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            INTERNET_OPTION_PROXY_SETTINGS_CHANGED = 95
            fn = ctypes.windll.Wininet.InternetSetOptionW
            fn(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            fn(0, INTERNET_OPTION_PROXY_SETTINGS_CHANGED, 0, 0)
            fn(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception:
            pass

    def _read_proxy_reg(self):
        """读取当前 WinINet 代理设置。"""
        data = {
            "ProxyEnable": 0,
            "ProxyServer": "",
            "AutoConfigURL": "",
            "had_auto": False,
            "had_server": False,
        }
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
            try:
                data["ProxyEnable"], _ = winreg.QueryValueEx(k, "ProxyEnable")
            except Exception:
                pass
            try:
                data["ProxyServer"], _ = winreg.QueryValueEx(k, "ProxyServer")
                data["had_server"] = True
            except Exception:
                pass
            try:
                data["AutoConfigURL"], _ = winreg.QueryValueEx(k, "AutoConfigURL")
                data["had_auto"] = True
            except Exception:
                pass
            winreg.CloseKey(k)
        except Exception:
            pass
        return data

    def _proxy_backup_path(self) -> Path:
        base = Path(getattr(self, "base_dir", Path(".")))
        d = base / "logs"
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return d / "proxy_backup.json"

    def save_proxy_before_override(self):
        """在本软件写入系统代理前，备份当前设置（便于退出后还给 v2rayN）。"""
        # 已接管过则保留首次备份，避免把 Mobility 自己的代理当备份
        if self._proxy_owned and self._proxy_backup is not None:
            return
        self._proxy_backup = self._read_proxy_reg()
        try:
            import json as _json
            self._proxy_backup_path().write_text(
                _json.dumps(self._proxy_backup, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass
        self._winhttp_backup = None

    def restore_proxy_backup(self):
        """还原进入本软件前的系统代理（优先内存备份，其次磁盘备份）。"""
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        b = self._proxy_backup
        if b is None:
            try:
                import json as _json
                bp = self._proxy_backup_path()
                if bp.exists():
                    b = _json.loads(bp.read_text(encoding="utf-8"))
                    self._proxy_backup = b
            except Exception:
                b = None
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
            if not b:
                # 无备份：仅当我们确实改过代理时才关闭，否则不动（避免误伤 v2rayN）
                if getattr(self, "_proxy_owned", False):
                    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                    # 只有 ProxyServer 仍指向本软件常用端口才删
                    try:
                        val, _ = winreg.QueryValueEx(k, "ProxyServer")
                        v = (val or "").lower().replace(" ", "")
                        ours = (
                            "127.0.0.1:%s" % int(getattr(self, "http_port", 10809) or 10809),
                            "127.0.0.1:%s" % int(getattr(self, "socks_port", 10808) or 10808),
                        )
                        if any(p in v for p in ours):
                            try:
                                winreg.DeleteValue(k, "ProxyServer")
                            except Exception:
                                pass
                    except Exception:
                        pass
            else:
                try:
                    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(b.get("ProxyEnable") or 0))
                except Exception:
                    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                if b.get("had_server") and (b.get("ProxyServer") or ""):
                    winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, str(b.get("ProxyServer") or ""))
                else:
                    try:
                        winreg.DeleteValue(k, "ProxyServer")
                    except Exception:
                        try:
                            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, "")
                        except Exception:
                            pass
                if b.get("had_auto") and (b.get("AutoConfigURL") or ""):
                    winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, str(b.get("AutoConfigURL") or ""))
                else:
                    try:
                        winreg.DeleteValue(k, "AutoConfigURL")
                    except Exception:
                        pass
                try:
                    if int(b.get("ProxyEnable") or 0) == 0:
                        val, _ = winreg.QueryValueEx(k, "ProxyServer")
                        v = (val or "").lower().replace(" ", "")
                        hp = str(int(getattr(self, "http_port", 10809) or 10809))
                        sp = str(int(getattr(self, "socks_port", 10808) or 10808))
                        if ("127.0.0.1:%s" % hp) in v or ("127.0.0.1:%s" % sp) in v:
                            if b.get("had_server") and b.get("ProxyServer") and "127.0.0.1:%s" % hp not in str(b.get("ProxyServer")).lower():
                                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, str(b.get("ProxyServer")))
                            else:
                                try:
                                    winreg.DeleteValue(k, "ProxyServer")
                                except Exception:
                                    try:
                                        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, "")
                                    except Exception:
                                        pass
                except Exception:
                    pass
            winreg.CloseKey(k)
        except Exception:
            pass
        # 多次通知，确保浏览器/v2rayN 能读到变更
        for _ in range(2):
            try:
                self._notify_proxy_change()
            except Exception:
                pass
        self._proxy_owned = False
        try:
            bp = self._proxy_backup_path()
            if bp.exists():
                bp.unlink()
        except Exception:
            pass

    def clear_system_proxy_force(self) -> bool:
        """强制关闭系统代理（仅在无备份或明确需要清空时使用）。"""
        ok = True
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        try:
            internet_settings = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS
            )
            try:
                winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            except Exception:
                ok = False
            for name in ("AutoConfigURL", "ProxyServer"):
                try:
                    winreg.DeleteValue(internet_settings, name)
                except Exception:
                    pass
            winreg.CloseKey(internet_settings)
        except Exception:
            ok = False
        self._notify_proxy_change()
        return ok

    def kill_stale_core_processes(self):
        """只结束后台由本软件拉起的核心进程，绝不按进程名全局 taskkill（会误杀 v2rayN 的 xray）。"""
        procs = []
        for attr in ("xray_process", "singbox_process", "mihomo_process"):
            proc = getattr(self, attr, None)
            if proc is not None:
                procs.append((attr, proc))
        for attr, proc in procs:
            try:
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass
            try:
                setattr(self, attr, None)
            except Exception:
                pass
        # 不再使用 taskkill /IM xray.exe —— 那会杀掉 v2rayN 正在用的核心

    def restore_network_environment(self, kill_cores: bool = True):
        """停止核心并还原系统代理（优先还原进入前的设置，兼容 v2rayN）。"""
        if getattr(self, "_restoring_network", False):
            return
        self._restoring_network = True
        try:
            for stopper in (getattr(self, "stop_singbox", None), getattr(self, "stop_mihomo", None)):
                if stopper:
                    try:
                        stopper()
                    except Exception:
                        pass
            if self.xray_process:
                try:
                    self.xray_process.kill()
                except Exception:
                    pass
                self.xray_process = None
            if kill_cores:
                try:
                    self.kill_stale_core_processes()
                except Exception:
                    pass
            # 关键点：还原备份，而不是粗暴清空（否则 v2rayN 需换节点重写代理）
            try:
                # 只要曾经写过系统代理或存在备份，就还原；绝不强制清空
                if self._proxy_owned or self._proxy_backup is not None:
                    self.restore_proxy_backup()
                else:
                    # 尝试从磁盘备份还原（异常退出后的二次打开再退出）
                    try:
                        if self._proxy_backup_path().exists():
                            self.restore_proxy_backup()
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                self.clear_local_proxy_env()
            except Exception:
                pass
        finally:
            self._restoring_network = False

    def set_system_proxy(self, enable: bool, port: int = 10809, pac: bool = False):
        try:
            # 关闭：只还原备份，绝不先清空（否则会把 v2rayN 的系统代理弄丢）
            if not enable:
                try:
                    self.restore_proxy_backup()
                except Exception:
                    pass
                self._proxy_owned = False
                return True

            try:
                self.save_proxy_before_override()
            except Exception:
                pass
            internet_settings = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_ALL_ACCESS
            )
            if pac:
                pac_path = self.write_pac_file(port)
                url = pac_path.resolve().as_uri()
                winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(internet_settings, "AutoConfigURL", 0, winreg.REG_SZ, url)
            else:
                # 必须清掉 PAC，否则浏览器仍走旧 AutoConfigURL
                for _ in range(2):
                    try:
                        winreg.DeleteValue(internet_settings, "AutoConfigURL")
                    except Exception:
                        pass
                    try:
                        winreg.SetValueEx(internet_settings, "AutoConfigURL", 0, winreg.REG_SZ, "")
                    except Exception:
                        pass
                winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                ps = "http=127.0.0.1:%(p)s;https=127.0.0.1:%(p)s" % {"p": int(port)}
                winreg.SetValueEx(internet_settings, "ProxyServer", 0, winreg.REG_SZ, ps)
                try:
                    winreg.SetValueEx(
                        internet_settings, "ProxyOverride", 0, winreg.REG_SZ,
                        "localhost;127.*;10.*;192.168.*;<local>",
                    )
                except Exception:
                    pass
            winreg.CloseKey(internet_settings)
            self._notify_proxy_change()
            self._proxy_owned = True
            try:
                cur = self._read_proxy_reg()
                self.log(
                    "系统代理状态：Enable=%s Server=%s PAC=%s"
                    % (cur.get("ProxyEnable"), (cur.get("ProxyServer") or "")[:80],
                       "有" if (cur.get("AutoConfigURL") or "").strip() else "无")
                )
            except Exception:
                pass
            return True
        except Exception as e:
            self.log("设置系统代理失败：%s" % e)
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
        # 顶栏空间有限，过长用省略号，避免挡住核心版本
        max_name = 18
        if len(name) > max_name:
            name = name[: max_name - 1] + "…"
        base = f"节点：{name}"
        if proto:
            base = f"节点：[{proto}] {name}"
        if lat_s:
            base += f" ({lat_s})"
        if len(base) > 36:
            base = base[:35] + "…"
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

    def _probe_stats_api(self):
        """启动后探测 Stats API 是否可用（只提示一次）。"""
        try:
            if getattr(self, "_stats_api_probed", False):
                return
            self._stats_api_probed = True
            xray_exe = self.core_dir / "xray.exe"
            if not xray_exe.exists() or not self.xray_process:
                return
            api_port = int(getattr(self, "api_port", 10085))
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.4)
                ok = s.connect_ex(("127.0.0.1", api_port)) == 0
                s.close()
            except Exception:
                ok = False
            if not ok:
                self.log("流量统计：API 端口 %s 未监听，统计可能为 0" % api_port)
                return
            r = subprocess.run(
                [str(xray_exe), "api", "statsquery", "--server=127.0.0.1:%d" % api_port, "-pattern", "outbound"],
                capture_output=True, text=True, timeout=2.5,
                creationflags=flags, cwd=str(self.core_dir),
            )
            out = ((r.stdout or "") + (r.stderr or "")).strip()
            if r.returncode == 0 or "value" in out.lower() or ">>>" in out:
                self.log("流量统计：Stats API 已就绪")
            else:
                self.log("流量统计：API 响应异常，界面速率可能为 0")
        except Exception as e:
            try:
                self.log("流量统计探测失败：%s" % e)
            except Exception:
                pass

    def _query_mihomo_traffic(self):
        """Mihomo external-controller 累计流量 (up, down)。"""
        try:
            if not getattr(self, "mihomo_process", None) or self.mihomo_process.poll() is not None:
                return None
            import urllib.request
            # connections 接口含 downloadTotal / uploadTotal
            req = urllib.request.Request(
                "http://127.0.0.1:9090/connections",
                headers={"User-Agent": "Mobility"},
            )
            with urllib.request.urlopen(req, timeout=1.2) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore") or "{}")
            if not isinstance(data, dict):
                return None
            up = int(data.get("uploadTotal") or 0)
            down = int(data.get("downloadTotal") or 0)
            if up < 0:
                up = 0
            if down < 0:
                down = 0
            return up, down
        except Exception:
            return None

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
            import re as _re

            def _run(args):
                try:
                    r = subprocess.run(
                        args, capture_output=True, text=True, timeout=1.8,
                        creationflags=flags, cwd=str(self.core_dir),
                    )
                    return ((r.stdout or "") + (r.stderr or "")).strip()
                except Exception:
                    return ""

            def _collect_from_mapping(items):
                up = down = 0
                up_i = down_i = 0
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    name = str(it.get("name") or "").lower()
                    try:
                        val = int(it.get("value") or 0)
                    except Exception:
                        val = 0
                    if val < 0:
                        val = 0
                    if "outbound>>>proxy>>>uplink" in name or "outbound>>>proxy>>>traffic>>>uplink" in name:
                        up = max(up, val)
                    elif "outbound>>>proxy>>>downlink" in name or "outbound>>>proxy>>>traffic>>>downlink" in name:
                        down = max(down, val)
                    elif ">>>uplink" in name and "outbound>>>" in name and "api" not in name:
                        up = max(up, val)
                    elif ">>>downlink" in name and "outbound>>>" in name and "api" not in name:
                        down = max(down, val)
                    elif "inbound>>>socks>>>uplink" in name or "inbound>>>http>>>uplink" in name:
                        up_i += val
                    elif "inbound>>>socks>>>downlink" in name or "inbound>>>http>>>downlink" in name:
                        down_i += val
                if up or down:
                    return up, down
                if up_i or down_i:
                    return up_i, down_i
                return 0, 0

            up = down = 0
            out = _run([
                str(xray_exe), "api", "statsquery",
                "--server=127.0.0.1:%d" % api_port, "-pattern", "",
            ])
            if out:
                # JSON
                js = None
                try:
                    s = out.find("{")
                    if s >= 0:
                        js = json.loads(out[s:])
                except Exception:
                    js = None
                if isinstance(js, dict):
                    items = js.get("stat") or js.get("stats") or js.get("Stat") or []
                    if isinstance(items, dict):
                        items = [items]
                    up, down = _collect_from_mapping(items or [])
                if up == 0 and down == 0:
                    # 文本格式 name / value
                    cur = ""
                    up_p = down_p = up_i = down_i = 0
                    for line in out.splitlines():
                        low = line.lower().strip()
                        if ">>>" in low:
                            cur = low
                        if "value" in low and cur:
                            ms = _re.findall(r"(\d+)", line)
                            if not ms:
                                cur = ""
                                continue
                            v = int(ms[-1])
                            if "outbound>>>proxy>>>uplink" in cur:
                                up_p = max(up_p, v)
                            elif "outbound>>>proxy>>>downlink" in cur:
                                down_p = max(down_p, v)
                            elif "inbound>>>socks>>>uplink" in cur or "inbound>>>http>>>uplink" in cur:
                                up_i += v
                            elif "inbound>>>socks>>>downlink" in cur or "inbound>>>http>>>downlink" in cur:
                                down_i += v
                            cur = ""
                    if up_p or down_p:
                        up, down = up_p, down_p
                    elif up_i or down_i:
                        up, down = up_i, down_i

            if up == 0 and down == 0:
                for n in ("outbound>>>proxy>>>uplink", "inbound>>>socks>>>uplink", "inbound>>>http>>>uplink"):
                    o2 = _run([str(xray_exe), "api", "stats", "--server=127.0.0.1:%d" % api_port, "-name", n])
                    ms = _re.findall(r"(\d+)", o2 or "")
                    if ms:
                        up = max(up, int(ms[-1]))
                for n in ("outbound>>>proxy>>>downlink", "inbound>>>socks>>>downlink", "inbound>>>http>>>downlink"):
                    o2 = _run([str(xray_exe), "api", "stats", "--server=127.0.0.1:%d" % api_port, "-name", n])
                    ms = _re.findall(r"(\d+)", o2 or "")
                    if ms:
                        down = max(down, int(ms[-1]))
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
            if not tr:
                try:
                    tr = self._query_mihomo_traffic()
                except Exception:
                    tr = None
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
                    self.status_label.configure(text="运行中", font=("Microsoft YaHei UI", 14, "bold"), text_color=("#16A34A", "#4ADE80"))
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
                    self.status_label.configure(text="未运行", font=("Microsoft YaHei UI", 14, "bold"), text_color=("#DC2626", "#F87171"))
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
        self.after(3500 if getattr(self, "live_stats_enabled", True) else 10000, self.update_home_stats)




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

        if proto in ("hysteria2", "hy2"):
            outbound = {
                "type": "hysteria2",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "password": node.get("password") or "",
                "tls": {
                    "enabled": True,
                    "server_name": node.get("sni") or server,
                    "insecure": bool(node.get("insecure")),
                },
            }
            if node.get("obfs"):
                outbound["obfs"] = {
                    "type": node.get("obfs") or "salamander",
                    "password": node.get("obfs_password") or "",
                }
            return outbound
        if proto == "tuic":
            alpn = node.get("alpn") or "h3"
            if isinstance(alpn, str):
                alpn_list = [a.strip() for a in alpn.split(",") if a.strip()]
            else:
                alpn_list = list(alpn) if alpn else ["h3"]
            outbound = {
                "type": "tuic",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": node.get("uuid") or "",
                "password": node.get("password") or "",
                "congestion_control": node.get("congestion_control") or "bbr",
                "udp_relay_mode": node.get("udp_relay_mode") or "native",
                "tls": {
                    "enabled": True,
                    "server_name": node.get("sni") or server,
                    "insecure": bool(node.get("allow_insecure")),
                    "alpn": alpn_list,
                },
            }
            return outbound
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
        elif proto in ("hysteria2", "hy2"):
            proxy["type"] = "hysteria2"
            proxy["password"] = node.get("password") or ""
            proxy["sni"] = node.get("sni") or server
            proxy["skip-cert-verify"] = bool(node.get("insecure"))
        elif proto == "tuic":
            proxy["type"] = "tuic"
            proxy["uuid"] = node.get("uuid") or ""
            proxy["password"] = node.get("password") or ""
            proxy["sni"] = node.get("sni") or server
            proxy["congestion-controller"] = node.get("congestion_control") or "bbr"
            proxy["udp-relay-mode"] = node.get("udp_relay_mode") or "native"
            proxy["skip-cert-verify"] = bool(node.get("allow_insecure"))
        elif proto == "masque":
            proxy["type"] = "masque"
            proxy["private-key"] = node.get("private_key") or node.get("private-key") or ""
            proxy["public-key"] = node.get("public_key") or node.get("public-key") or ""
            if node.get("ip"):
                proxy["ip"] = node.get("ip")
            if node.get("ipv6"):
                proxy["ipv6"] = node.get("ipv6")
            if node.get("uri"):
                proxy["uri"] = node.get("uri")
            try:
                proxy["mtu"] = int(node.get("mtu") or 1280)
            except Exception:
                proxy["mtu"] = 1280
            proxy["udp"] = True
            proxy["remote-dns-resolve"] = True
            proxy["congestion-controller"] = node.get("congestion_controller") or node.get("congestion-controller") or "bbr"
            proxy["sni"] = node.get("sni") or "www.cloudflareaccess.com"
            dns = node.get("dns") or ""
            if isinstance(dns, str) and dns.strip():
                proxy["dns"] = [x.strip() for x in dns.split(",") if x.strip()]
            elif isinstance(dns, list):
                proxy["dns"] = dns
            else:
                proxy["dns"] = ["1.1.1.1", "8.8.8.8"]
        else:
            raise ValueError(f"Mihomo 暂不支持协议：{proto}")
        return proxy

    def create_mihomo_config(self, node: dict, socks_port: int, http_port: int, enable_tun: bool) -> Path:
        """生成 Mihomo (Clash Meta) 配置。"""
        proxy = self.node_to_mihomo_proxy(node)
        # 代理名避免特殊符号导致分组引用失败
        pname = str(proxy.get("name") or "node").strip() or "node"
        proxy["name"] = pname
        mode = self.proxy_mode or "规则模式"
        proto = (node.get("protocol") or "").lower()
        # 注意：Clash/Mihomo 的 global 模式走内置 GLOBAL 组，不会用我们的 PROXY 组
        # 因此用 rule + MATCH,PROXY 实现“全局走指定节点”
        if "直连" in mode:
            clash_mode = "direct"
        else:
            # 规则 / 全局 / MASQUE：统一 rule，靠 rules 决定
            clash_mode = "rule"

        need_v6 = proto in ("masque",) or (":" in str(node.get("address") or ""))

        rules = [
            "IP-CIDR,127.0.0.0/8,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "IP-CIDR,172.16.0.0/12,DIRECT",
            "IP-CIDR,192.168.0.0/16,DIRECT",
            "IP-CIDR,169.254.0.0/16,DIRECT",
            "IP-CIDR,224.0.0.0/4,DIRECT",
        ]
        if clash_mode == "direct":
            rules.append("MATCH,DIRECT")
        elif "全局" in mode:
            rules.append("MATCH,PROXY")
        else:
            # 规则模式（含 MASQUE）：国内直连，减轻网页卡顿
            rules.extend([
                "GEOSITE,private,DIRECT",
                "GEOIP,private,DIRECT,no-resolve",
                "GEOSITE,cn,DIRECT",
                "DOMAIN-SUFFIX,cn,DIRECT",
                "DOMAIN-SUFFIX,中国,DIRECT",
                "DOMAIN-SUFFIX,公司,DIRECT",
                "DOMAIN-SUFFIX,网络,DIRECT",
                "DOMAIN-KEYWORD,baidu,DIRECT",
                "DOMAIN-KEYWORD,qq.com,DIRECT",
                "DOMAIN-KEYWORD,tencent,DIRECT",
                "DOMAIN-KEYWORD,weixin,DIRECT",
                "DOMAIN-KEYWORD,wechat,DIRECT",
                "DOMAIN-KEYWORD,alipay,DIRECT",
                "DOMAIN-KEYWORD,taobao,DIRECT",
                "DOMAIN-KEYWORD,tmall,DIRECT",
                "DOMAIN-KEYWORD,bilibili,DIRECT",
                "DOMAIN-KEYWORD,zhihu,DIRECT",
                "DOMAIN-KEYWORD,douyin,DIRECT",
                "DOMAIN-KEYWORD,bytedance,DIRECT",
                "DOMAIN-KEYWORD,jd.com,DIRECT",
                "DOMAIN-KEYWORD,163.com,DIRECT",
                "DOMAIN-KEYWORD,aliyun,DIRECT",
                "DOMAIN-KEYWORD,alicdn,DIRECT",
                "DOMAIN-KEYWORD,mi.com,DIRECT",
                "DOMAIN-KEYWORD,xiaomi,DIRECT",
                "DOMAIN-KEYWORD,huawei,DIRECT",
                "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",
                "DOMAIN-SUFFIX,msftncsi.com,DIRECT",
                "GEOIP,CN,DIRECT,no-resolve",
                "MATCH,PROXY",
            ])

        cfg = {
            "mixed-port": int(http_port),
            "allow-lan": bool(getattr(self, "allow_lan", False)),
            "external-controller": "127.0.0.1:9090",
            "secret": "",
            "mode": clash_mode,
            "log-level": "info",
            "ipv6": False,
            "unified-delay": True,
            "tcp-concurrent": True,
            "find-process-mode": "off",
            # 使用 core 目录下 geoip.dat / geosite.dat（与 Xray 共用）
            "geodata-mode": True,
            "geo-auto-update": False,
            "dns": {
                "enable": True,
                "ipv6": False,
                "enhanced-mode": "redir-host",
                "default-nameserver": ["223.5.5.5", "119.29.29.29"],
                "nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"],
                "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
                "nameserver-policy": {
                    "geosite:cn": ["223.5.5.5", "119.29.29.29"],
                    "geosite:private": ["223.5.5.5"],
                    "+.cn": ["223.5.5.5", "119.29.29.29"],
                },
            },
            "proxies": [proxy],
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": [pname]},
            ],
            "rules": rules,
        }
        if enable_tun:
            cfg["tun"] = {
                "enable": True,
                "stack": "mixed",
                "auto-route": True,
                "auto-detect-interface": True,
                "dns-hijack": ["any:53"],
            }
            cfg["dns"]["listen"] = "127.0.0.1:1053"
        # Mihomo 支持 JSON
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
            excludes = [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
            ]
            try:
                addr = (node.get("address") or "").strip()
                if addr and not any(c.isalpha() for c in addr):
                    excludes.append(f"{addr}/32" if ":" not in addr or "." in addr else addr)
            except Exception:
                pass
            inbounds.append({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "Mobility0",
                "address": ["172.19.0.1/30"],
                "mtu": 1400,
                "auto_route": True,
                "strict_route": False,
                "stack": "system",
                "route_exclude_address": excludes,
            })

        mode = self.proxy_mode or "规则模式"
        rules = [{"action": "sniff"}]
        if "全局" in mode:
            final = "proxy"
        elif "直连" in mode:
            final = "direct"
        else:
            rules.append({"ip_is_private": True, "outbound": "direct"})
            rules.append({
                "domain_suffix": [".cn", ".中国", "baidu.com", "qq.com", "weixin.qq.com",
                                  "taobao.com", "alipay.com", "bilibili.com", "163.com"],
                "outbound": "direct",
            })
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

    def create_singbox_tun_config(self, socks_port: int, http_port: int = None, node: dict = None) -> Path:
        """生成 sing-box TUN 配置：流量进 TUN 后转发到本地 Xray SOCKS。

        必须排除节点服务器地址，否则 Xray 访问远端会再次被 TUN 吸走形成环路，
        表现为「先普通启动再开 TUN 才通、冷启动勾选 TUN 不通」。
        """
        if http_port is None:
            try:
                _, http_port = self.get_ports()
            except Exception:
                http_port = 10809
        excludes = [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "224.0.0.0/4",
        ]
        # 排除当前代理节点 IP，避免出站环路
        try:
            n = node or getattr(self, "current_node", None) or {}
            addr = (n.get("address") or "").strip()
            if addr and not any(c.isalpha() for c in addr):
                # 纯 IP
                if ":" in addr and "." not in addr:
                    excludes.append(addr)  # IPv6 literal
                else:
                    excludes.append(f"{addr}/32")
            elif addr:
                # 域名：加入 dns 直连规则，并在 route 里对域名 direct（见下）
                pass
        except Exception:
            pass

        ts = dict(DEFAULT_TUN_SETTINGS)
        ts.update(getattr(self, "tun_settings", {}) or {})
        try:
            extra = (ts.get("route_exclude") or "").replace(";", ",").split(",")
            for x in extra:
                x = x.strip()
                if x and x not in excludes:
                    excludes.append(x)
        except Exception:
            pass

        route_rules = [
            {"action": "sniff"},
            {"ip_is_private": True, "outbound": "direct"},
            # 国内常见域名走直连，避免 TUN 全部进代理导致国内站超时
            {
                "domain_suffix": [
                    ".cn", ".中国", ".公司", ".网络",
                    "baidu.com", "qq.com", "weixin.qq.com", "wechat.com",
                    "taobao.com", "aliyun.com", "alipay.com", "tmall.com",
                    "163.com", "126.com", "yeah.net",
                    "bilibili.com", "hdslb.com",
                    "zhihu.com", "douyin.com", "bytedance.com",
                    "jd.com", "360.cn", "huawei.com", "mi.com", "xiaomi.com",
                    "microsoft.com", "office.com", "live.com", "windows.com",
                    "apple.com", "icloud.com",
                    "gtimg.com", "qpic.cn", "dhgate.com",
                ],
                "outbound": "direct",
            },
            {
                "domain_keyword": [
                    "baidu", "weixin", "wechat", "alipay", "taobao",
                    "bilibili", "douyin", "zhihu",
                ],
                "outbound": "direct",
            },
        ]
        # 节点域名单直连（不走 TUN 出站环）
        try:
            n = node or getattr(self, "current_node", None) or {}
            addr = (n.get("address") or "").strip()
            if addr and any(c.isalpha() for c in addr):
                route_rules.insert(1, {"domain": [addr], "outbound": "direct"})
        except Exception:
            pass

        cfg = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": ts.get("interface_name") or "Mobility0",
                    "address": [ts.get("ipv4_address") or "172.19.0.1/30"],
                    "mtu": int(ts.get("mtu") or 1400),
                    "auto_route": bool(ts.get("auto_route", True)),
                    "strict_route": bool(ts.get("strict_route", False)),
                    "stack": ts.get("stack") or "system",
                    "route_exclude_address": excludes,
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
                "rules": route_rules,
            },
        }
        # 规则/PAC：保留国内直连；全局：去掉域名直连规则，全部进代理
        try:
            mode = getattr(self, "proxy_mode", "") or ""
            if "全局" in mode:
                cfg["route"]["rules"] = [r for r in route_rules if "domain_suffix" not in r and "domain_keyword" not in r]
            # 额外路由设置
            extra_d = []
            for line in (getattr(self, "routing_extra_direct", "") or "").splitlines():
                d = line.strip()
                if d:
                    extra_d.append(d.lstrip("*").lstrip("."))
            if extra_d:
                cfg["route"]["rules"].insert(1, {"domain_suffix": extra_d, "outbound": "direct"})
            extra_p = []
            for line in (getattr(self, "routing_extra_proxy", "") or "").splitlines():
                d = line.strip()
                if d:
                    extra_p.append(d.lstrip("*").lstrip("."))
            if extra_p:
                cfg["route"]["rules"].insert(1, {"domain_suffix": extra_p, "outbound": "proxy"})
        except Exception:
            pass
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

    def _restart_proxy_quick(self):
        """运行中换节点：快速停旧核心并按新节点启动（避免整机假死）。"""
        try:
            # 标记重启中，防止重复点启动
            self._restarting = True
            old_core = getattr(self, "proxy_core", "") or ""
            try:
                self.stop_proxy()
            except Exception as e:
                try:
                    self.log("停止旧代理：%s" % e)
                except Exception:
                    pass
            # 短等待释放端口，避免 bind 失败
            try:
                time.sleep(0.35)
            except Exception:
                pass
            node = self.get_selected_node()
            if node and hasattr(self, "resolve_live_node"):
                node = self.resolve_live_node(node) or node
            if not node:
                self.log("重启失败：无有效节点")
                return
            new_core = self.resolve_core_for_node(node)
            if (node.get("protocol") or "").lower() == "masque":
                new_core = "Mihomo"
            try:
                self.log("核心切换：%s → %s（协议 %s）" % (old_core or "无", new_core, node.get("protocol")))
            except Exception:
                pass
            # 直接走 start（内部会清残留进程）
            self.start_proxy()
        except Exception as e:
            try:
                self.log("自动重启失败：%s" % e)
            except Exception:
                pass
        finally:
            self._restarting = False

    def start_proxy_thread(self):
        if self.is_running:
            self.log("代理已在运行中，请先停止；或回车确认新节点以自动切换")
            return
        if getattr(self, "_restarting", False):
            self.log("正在切换节点，请稍候…")
            return
        Thread(target=self.start_proxy, daemon=True).start()

    def start_proxy(self):
        self.after(0, lambda: self.start_btn and self.start_btn.configure(state="disabled") if self.start_btn else None)
        self.log("---------- 开始启动 ----------")
        # 清理可能残留的核心进程，保证冷启动勾选 TUN 与二次启动路径一致
        try:
            if getattr(self, "singbox_process", None):
                self.stop_singbox()
        except Exception:
            pass
        try:
            if getattr(self, "mihomo_process", None):
                self.stop_mihomo()
        except Exception:
            pass

        node = self.get_selected_node()
        if node and hasattr(self, "resolve_live_node"):
            node = self.resolve_live_node(node) or node
        if not node:
            text = self.entry.get().strip()
            if text and not text.startswith(("http://", "https://")):
                node = parse_link(text)
            if not node:
                self.log("错误：请先加载订阅并选择节点（点节点后按回车确认）")
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return

        if not node.get("address") or not node.get("port"):
            self.log("错误：节点地址或端口无效")
            self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
            return

        # 代理只用当前确认节点，与橙色测速分组无关
        self.current_node = node
        g = (node.get("_group") or node.get("group") or "").strip()
        if g:
            self._active_test_group = g
        if g:
            self.log("节点所属分组：%s" % g)
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
        _p = (node.get("protocol") or "").lower()
        if _p == "ss":
            _p = "shadowsocks"
        mapped = (getattr(self, "core_map", {}) or {}).get(_p, "")
        self.log(f"节点协议 [{node.get('protocol')}] 映射={mapped or '自动'} → 实际核心 {core_name}")
        if (node.get("protocol") or "").lower() == "masque":
            self.log("提示：MASQUE 使用 Mihomo；规则模式=国内直连+境外代理")
            core_name = "Mihomo"
            self.proxy_core = core_name

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
                if self.apply_system_proxy_for_mode(http_port):
                    self.log(f"系统代理已设置 127.0.0.1:{http_port}")
                self.is_running = True
                self.after(0, lambda: self.status_label.configure(text="运行中", font=("Microsoft YaHei UI", 14, "bold"), text_color=("#16A34A", "#4ADE80")))
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

        # ========== Mihomo 核心 ==========
        if core_name.lower().startswith("mihomo") or core_name.lower() == "clash":
            mh = ensure_mihomo(self.core_dir, log_fn=self.log)
            if not mh:
                self.log("错误：找不到 Mihomo 核心")
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return
            if getattr(self, "tun_enabled", False):
                try:
                    ensure_wintun(self.core_dir, log_fn=self.log)
                except Exception:
                    pass
            try:
                mh_cfg = self.create_mihomo_config(
                    node, socks_port, http_port, bool(getattr(self, "tun_enabled", False))
                )
                self.log("Mihomo 配置已生成")
            except Exception as e:
                self.log("生成 Mihomo 配置失败：%s" % e)
                self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                return
            try:
                mh_log = self.core_dir / "mihomo.log"
                try:
                    mh_log_handle = open(mh_log, "w", encoding="utf-8", errors="ignore")
                except Exception:
                    mh_log_handle = subprocess.DEVNULL
                self.mihomo_process = subprocess.Popen(
                    [str(mh), "-d", str(self.core_dir), "-f", str(mh_cfg)],
                    cwd=str(self.core_dir),
                    creationflags=flags,
                    stdout=mh_log_handle,
                    stderr=subprocess.STDOUT,
                )
                time.sleep(0.8)
                if self.mihomo_process.poll() is not None:
                    self.log("Mihomo 启动失败，请查看 core/mihomo.log")
                    try:
                        if mh_log.exists():
                            txt = mh_log.read_text(encoding="utf-8", errors="ignore")
                            for ln in txt.strip().splitlines()[-15:]:
                                self.log("  " + ln[:220])
                    except Exception:
                        pass
                    self.mihomo_process = None
                    self.after(0, lambda: self.start_btn and self.start_btn.configure(state="normal") if self.start_btn else None)
                    return
                port_ok = False
                try:
                    port_ok = wait_local_port(int(http_port), timeout=12)
                except Exception:
                    port_ok = False
                if port_ok:
                    self.log("本地端口 %s 已监听" % http_port)
                else:
                    self.log("警告：本地端口 %s 未监听" % http_port)
                    try:
                        if self.mihomo_process.poll() is not None:
                            self.log("Mihomo 进程已退出")
                        if mh_log.exists():
                            txt = mh_log.read_text(encoding="utf-8", errors="ignore")
                            for ln in txt.strip().splitlines()[-20:]:
                                self.log("  " + ln[:220])
                    except Exception:
                        pass
                if not getattr(self, "tun_enabled", False):
                    if self.apply_system_proxy_for_mode(http_port):
                        self.log("系统代理已设置 127.0.0.1:%s" % http_port)
                self.is_running = True
                self.after(0, lambda: self.status_label.configure(
                    text="运行中", font=("Microsoft YaHei UI", 14, "bold"), text_color=("#16A34A", "#4ADE80")
                ))
                tun_s = " + TUN" if getattr(self, "tun_enabled", False) else ""
                self.log("代理已启动（Mihomo%s）" % tun_s)
                self._run_started_at = time.time()
                self.set_tray_state("connected")
                self.save_settings()
            except Exception as e:
                self.log("启动 Mihomo 失败：%s" % e)
                self.mihomo_process = None
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
                # 1) 先确认 Xray 本地端口就绪，避免 TUN 转发打到空端口
                if not wait_local_port(socks_port, timeout=8):
                    self.log(f"等待本地 SOCKS {socks_port} 超时，TUN 可能无法转发")
                else:
                    self.log(f"本地 SOCKS {socks_port} 已就绪")
                # 2) 系统代理（浏览器兼容）
                if self.apply_system_proxy_for_mode(http_port):
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
                # 3) 生成 TUN 配置时排除节点地址，防止路由环路
                sb_cfg = self.create_singbox_tun_config(socks_port, http_port, node=self.current_node)
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
                time.sleep(1.5)
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
                proxy_ok = bool(self.apply_system_proxy_for_mode(http_port))
                if proxy_ok:
                    self.log(f"系统代理已设置为 127.0.0.1:{http_port}")

            if proxy_ok:
                self.is_running = True
                # 实时统计默认保持用户开关（不再因 TUN 强制关闭）
                self.after(0, lambda: self.status_label.configure(
                    text="运行中", font=("Microsoft YaHei UI", 14, "bold"), text_color=("#16A34A", "#4ADE80")
                ))
                self.log("代理已启动" + ("（sing-box TUN）" if getattr(self, "tun_enabled", False) else ""))
                try:
                    if not getattr(self, "tun_enabled", False):
                        self.after(800, self._probe_stats_api)
                except Exception:
                    pass
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
        # 停止时务必还原系统代理，避免影响 v2rayN 等
        # 清核心 + 系统代理/PAC/WinHTTP（内部会处理 xray/sing-box/mihomo）
        try:
            self.restore_network_environment(kill_cores=True)
        except Exception:
            try:
                self.set_system_proxy(False)
            except Exception:
                pass
        self.is_running = False
        self.tun_enabled = False
        try:
            if hasattr(self, "tun_check"):
                self.tun_check.deselect()
        except Exception:
            pass
        self._run_started_at = None
        try:
            self.status_label.configure(text="未运行", font=("Microsoft YaHei UI", 14, "bold"), text_color=("#DC2626", "#F87171"))
        except Exception:
            pass
        try:
            self.set_tray_state("disconnected")
        except Exception:
            pass
        self._stats_api_probed = False
        self.log("代理已停止，系统代理已还原")
        # 恢复启动按钮
        try:
            self.after(0, lambda: self.start_btn.configure(state="normal"))
        except Exception:
            try:
                self.start_btn.configure(state="normal")
            except Exception:
                pass


    def cleanup_logs_on_exit(self):
        """退出时清理常规日志：仅保留含警告/错误的内容或文件。"""
        logs_dir = getattr(self, "logs_dir", None)
        if logs_dir is None:
            try:
                logs_dir = Path(getattr(self, "base_dir", Path("."))) / "logs"
            except Exception:
                return
        try:
            logs_dir = Path(logs_dir)
        except Exception:
            return
        if not logs_dir.is_dir():
            return

        # 判定严重行的关键词（中英）
        serious_kw = (
            "error", "err]", "[error", "warning", "warn]", "[warn",
            "failed", "failure", "exception", "traceback", "critical", "fatal",
            "错误", "失败", "异常", "警告", "严重", "崩溃", "拒绝", "无法",
        )

        def line_is_serious(line: str) -> bool:
            low = (line or "").lower()
            if not low.strip():
                return False
            for k in serious_kw:
                if k in low:
                    return True
            return False

        for fp in list(logs_dir.glob("*")):
            try:
                if not fp.is_file():
                    continue
                # 过大的二进制直接跳过
                if fp.suffix.lower() in (".dll", ".exe", ".dat"):
                    continue
                try:
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    try:
                        fp.unlink()
                    except Exception:
                        pass
                    continue
                lines = text.splitlines()
                serious_lines = [ln for ln in lines if line_is_serious(ln)]
                if not serious_lines:
                    # 无警告/错误：删除整个文件
                    try:
                        fp.unlink()
                    except Exception:
                        pass
                    continue
                # 有严重内容：只保留这些行，并加上说明头
                try:
                    header = [
                        "# Mobility 退出时保留的警告/错误日志",
                        "# 常规信息日志已自动清理",
                        "",
                    ]
                    fp.write_text("\n".join(header + serious_lines) + "\n", encoding="utf-8")
                except Exception:
                    pass
            except Exception:
                continue

    def on_closing(self):
        # 关闭到托盘（代理可继续跑）
        if self.close_to_tray and TRAY_AVAILABLE and self.tray_icon is not None:
            self.save_settings()
            self.withdraw()
            self.log("已最小化到系统托盘")
            return
        # 真正退出：只清理一次，避免重复 taskkill/netsh 导致退出很慢
        try:
            self.stop_proxy()
        except Exception:
            pass
        # 再保险还原系统代理（兼容 v2rayN：还原备份 + 多次通知）
        try:
            self.stop_mihomo()
        except Exception:
            pass
        for _ in range(2):
            try:
                self.restore_proxy_backup()
            except Exception:
                pass
            try:
                self._notify_proxy_change()
            except Exception:
                pass
            try:
                time.sleep(0.12)
            except Exception:
                pass
        try:
            self.save_settings()
        except Exception:
            pass
        try:
            self.cleanup_logs_on_exit()
        except Exception:
            pass
        try:
            if self.tray_icon is not None:
                self.tray_icon.stop()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass


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
    import atexit

    def _atexit_restore():
        # 仅还原本进程若曾接管的系统代理；禁止全局 taskkill，避免误杀 v2rayN
        pass

    atexit.register(_atexit_restore)

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
