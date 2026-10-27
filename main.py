import customtkinter as ctk
import subprocess
import os
import sys
import json
import requests
import zipfile
import io
import winreg
import ctypes
import shutil
from pathlib import Path
from threading import Thread

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


def get_base_dir() -> Path:
    """获取程序所在目录（兼容源码和打包后）"""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def get_resource_path(relative: str) -> Path:
    """获取打包进 exe 的资源路径（PyInstaller / Nuitka 通用）"""
    if getattr(sys, 'frozen', False):
        # PyInstaller
        if hasattr(sys, '_MEIPASS'):
            return Path(sys._MEIPASS) / relative
        # Nuitka onefile
        return Path(sys.executable).parent / relative
    return Path(__file__).parent / relative


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Mobility")
        self.geometry("560x420")
        self.resizable(False, False)

        self.base_dir = get_base_dir()
        self.core_dir = self.base_dir / "core"
        self.core_dir.mkdir(exist_ok=True)

        self.xray_process = None
        self.is_running = False

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # 启动时准备核心
        self.after(200, self.prepare_core)

    def create_widgets(self):
        title = ctk.CTkLabel(self, text="Mobility", font=("Microsoft YaHei UI", 22, "bold"))
        title.pack(pady=(18, 5))

        subtitle = ctk.CTkLabel(self, text="基础启动 / 停止 + 系统代理", font=("Microsoft YaHei UI", 12))
        subtitle.pack(pady=(0, 15))

        self.entry_label = ctk.CTkLabel(self, text="订阅 / 节点链接：", font=("Microsoft YaHei UI", 13))
        self.entry_label.pack(anchor="w", padx=40)

        self.entry = ctk.CTkEntry(self, width=480, height=36, placeholder_text="当前版本仅测试启动功能，链接暂时无效")
        self.entry.pack(pady=6)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=18)

        self.start_btn = ctk.CTkButton(
            btn_frame, text="启动代理", width=150, height=42,
            font=("Microsoft YaHei UI", 14),
            command=self.start_proxy_thread
        )
        self.start_btn.pack(side="left", padx=12)

        self.stop_btn = ctk.CTkButton(
            btn_frame, text="停止代理", width=150, height=42,
            font=("Microsoft YaHei UI", 14),
            fg_color="#c0392b", hover_color="#922b21",
            command=self.stop_proxy
        )
        self.stop_btn.pack(side="left", padx=12)

        self.status_label = ctk.CTkLabel(
            self, text="状态：未运行",
            font=("Microsoft YaHei UI", 14)
        )
        self.status_label.pack(pady=8)

        self.log_box = ctk.CTkTextbox(self, width=500, height=140, font=("Consolas", 12))
        self.log_box.pack(pady=8)
        self.log("欢迎使用 Mobility")

    def log(self, msg: str):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def prepare_core(self):
        """准备 Xray 核心：优先使用已存在的，其次从 exe 内部提取，最后尝试下载"""
        xray_exe = self.core_dir / "xray.exe"

        # 1. 已经存在
        if xray_exe.exists():
            self.log("已检测到 Xray-core")
            return

        # 2. 尝试从打包资源中提取
        try:
            bundled = get_resource_path("core/xray.exe")
            self.log(f"尝试提取内置核心: {bundled}")
            if bundled.exists():
                shutil.copy2(bundled, xray_exe)
                self.log("已成功从程序内部提取 Xray-core")
                return
            else:
                self.log("内置核心文件不存在")
        except Exception as e:
            self.log(f"提取内置核心失败: {e}")

        # 3. 在线下载（备用）
        self.log("未找到内置核心，尝试在线下载...")
        Thread(target=self.download_xray, daemon=True).start()

    def download_xray(self) -> bool:
        xray_exe = self.core_dir / "xray.exe"
        if xray_exe.exists():
            return True

        try:
            api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
            resp = requests.get(api_url, timeout=20)
            resp.raise_for_status()
            assets = resp.json().get("assets", [])

            download_url = None
            for asset in assets:
                name = asset.get("name", "")
                if "windows-64.zip" in name and "windows-arm64" not in name:
                    download_url = asset["browser_download_url"]
                    break

            if not download_url:
                self.log("错误：未找到 Windows 64 位安装包")
                return False

            self.log("正在下载 Xray-core...")
            data = requests.get(download_url, timeout=120).content

            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(self.core_dir)

            if xray_exe.exists():
                self.log("Xray-core 下载完成")
                return True
            else:
                self.log("错误：解压后未找到 xray.exe")
                return False

        except Exception as e:
            self.log(f"下载失败：{e}")
            return False

    def create_config(self):
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "tag": "socks",
                    "port": 10808,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True}
                },
                {
                    "tag": "http",
                    "port": 10809,
                    "listen": "127.0.0.1",
                    "protocol": "http"
                }
            ],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"}
            ]
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

    def start_proxy_thread(self):
        if self.is_running:
            self.log("代理已在运行中")
            return
        Thread(target=self.start_proxy, daemon=True).start()

    def start_proxy(self):
        self.start_btn.configure(state="disabled")
        self.log("---------- 开始启动 ----------")

        xray_exe = self.core_dir / "xray.exe"
        if not xray_exe.exists():
            self.log("核心文件不存在，正在尝试准备...")
            self.prepare_core()
            # 等待一下提取/下载
            import time
            for _ in range(30):
                if xray_exe.exists():
                    break
                time.sleep(0.5)

        if not xray_exe.exists():
            self.log("无法获取 Xray-core，启动失败")
            self.start_btn.configure(state="normal")
            return

        config_path = self.create_config()

        try:
            self.xray_process = subprocess.Popen(
                [str(xray_exe), "run", "-c", str(config_path)],
                cwd=str(self.core_dir),
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            if self.set_system_proxy(True, 10809):
                self.is_running = True
                self.status_label.configure(text="状态：运行中（当前为直连测试）", text_color="#27ae60")
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
