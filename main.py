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
from pathlib import Path
from threading import Thread

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Mobility")
        self.geometry("560x420")
        self.resizable(False, False)

        # 路径设置（兼容打包后和源码运行）
        if getattr(sys, 'frozen', False):
            self.base_dir = Path(sys.executable).parent
        else:
            self.base_dir = Path(__file__).parent

        self.core_dir = self.base_dir / "core"
        self.core_dir.mkdir(exist_ok=True)

        self.xray_process = None
        self.is_running = False

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        # 标题
        title = ctk.CTkLabel(self, text="Mobility", font=("Microsoft YaHei UI", 22, "bold"))
        title.pack(pady=(18, 5))

        subtitle = ctk.CTkLabel(self, text="基础启动 / 停止 + 系统代理", font=("Microsoft YaHei UI", 12))
        subtitle.pack(pady=(0, 15))

        # 输入框（预留，后续阶段启用）
        self.entry_label = ctk.CTkLabel(self, text="订阅 / 节点链接：", font=("Microsoft YaHei UI", 13))
        self.entry_label.pack(anchor="w", padx=40)

        self.entry = ctk.CTkEntry(self, width=480, height=36, placeholder_text="当前版本仅测试启动功能，链接暂时无效")
        self.entry.pack(pady=6)

        # 按钮区域
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

        # 状态
        self.status_label = ctk.CTkLabel(
            self, text="状态：未运行",
            font=("Microsoft YaHei UI", 14)
        )
        self.status_label.pack(pady=8)

        # 日志
        self.log_box = ctk.CTkTextbox(self, width=500, height=140, font=("Consolas", 12))
        self.log_box.pack(pady=8)
        self.log("欢迎使用 Mobility")
        self.log("功能：自动下载 Xray-core + 启动本地代理 + 设置系统代理")
        self.log("当前出站为直连（freedom），用于测试程序本身是否正常")
        self.log("后续将加入真实节点解析和代理转发")

    def log(self, msg: str):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def download_xray(self) -> bool:
        xray_exe = self.core_dir / "xray.exe"
        if xray_exe.exists():
            self.log("Xray-core 已存在，跳过下载")
            return True

        self.log("正在获取 Xray-core 最新版本信息...")
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

            self.log("正在下载 Xray-core，请稍候...")
            data = requests.get(download_url, timeout=120).content

            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(self.core_dir)

            if not xray_exe.exists():
                self.log("错误：解压后未找到 xray.exe")
                return False

            self.log("Xray-core 下载并解压完成")
            return True

        except Exception as e:
            self.log(f"下载失败：{e}")
            return False

    def create_config(self):
        """生成最简单的本地配置（直连测试用）"""
        config = {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "tag": "socks",
                    "port": 10808,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "udp": True
                    }
                },
                {
                    "tag": "http",
                    "port": 10809,
                    "listen": "127.0.0.1",
                    "protocol": "http"
                }
            ],
            "outbounds": [
                {
                    "tag": "direct",
                    "protocol": "freedom"
                }
            ]
        }

        config_path = self.core_dir / "config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return config_path

    def set_system_proxy(self, enable: bool, port: int = 10809):
        """设置或取消 Windows 系统代理"""
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

            # 通知系统代理已更改
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

        if not self.download_xray():
            self.start_btn.configure(state="normal")
            return

        config_path = self.create_config()
        xray_exe = self.core_dir / "xray.exe"

        try:
            # 启动 Xray（隐藏窗口）
            self.xray_process = subprocess.Popen(
                [str(xray_exe), "run", "-c", str(config_path)],
                cwd=str(self.core_dir),
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # 设置系统代理
            if self.set_system_proxy(True, 10809):
                self.is_running = True
                self.status_label.configure(text="状态：运行中（当前为直连测试）", text_color="#27ae60")
                self.log("Xray 已启动")
                self.log("系统代理已设置为 127.0.0.1:10809")
                self.log("当前为直连模式，仅用于验证程序功能正常")
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
    # 高 DPI 支持
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = App()
    app.mainloop()
