<div align="center">

# Mobility

**Windows 便携版 · 多核心代理客户端**

[![Release](https://img.shields.io/github/v/release/your-org/Mobility?style=flat-square)](../../releases)
[![Downloads](https://img.shields.io/github/downloads/your-org/Mobility/total?style=flat-square)](../../releases)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

解压即用 · 多核心内置 · 订阅测速 · 系统代理 / TUN

[下载最新版](../../releases/latest) · [提交问题](../../issues/new/choose) · [贡献指南](CONTRIBUTING.md)

</div>

---

## 目录

- [简介](#简介)
- [功能特性](#功能特性)
- [内置组件](#内置组件)
- [快速开始](#快速开始)
- [界面与使用说明](#界面与使用说明)
- [核心与协议映射](#核心与协议映射)
- [代理模式与路由](#代理模式与路由)
- [TUN 模式](#tun-模式)
- [订阅与节点](#订阅与节点)
- [目录结构](#目录结构)
- [系统要求](#系统要求)
- [常见问题](#常见问题)
- [构建与发布](#构建与发布)
- [反馈与贡献](#反馈与贡献)
- [免责声明](#免责声明)

---

## 简介

**Mobility** 是面向 Windows 的绿色便携代理客户端，目标是在尽量少的配置步骤下完成：

1. 导入订阅 / 节点  
2. 测速并选择可用节点  
3. 一键启动本地代理（系统代理或 TUN）  

构建流水线会在打包阶段自动下载并写入 **Xray-core**、**sing-box**、**Mihomo** 以及 **geoip / geosite / wintun**，用户无需再单独寻找核心文件。

---

## 功能特性

### 代理与核心

| 能力 | 说明 |
| --- | --- |
| 多核心 | Xray / sing-box / Mihomo，可按协议分别指定 |
| 协议 | VMess、VLESS、Trojan、Shadowsocks 等 |
| 入站 | 本地 SOCKS / HTTP（端口可配置） |
| 系统代理 | 启动时写入、停止时还原 Windows 代理设置 |
| TUN | 系统级流量接管（需管理员权限） |
| 路由模式 | 规则模式 / 全局模式 / 直连模式 |
| 自定义域名 | 直连域名、代理域名列表（支持简单通配） |

### 订阅与节点

| 能力 | 说明 |
| --- | --- |
| 多订阅 | 添加、删除、重命名、全部更新 |
| 导入 | 订阅 URL、剪贴板节点、屏幕扫码、生成节点二维码 |
| 测速 | 全部测速 / 筛选测速，并发路数可调 |
| 选最快 | 按延迟自动选中最优节点 |
| 连通性 | 节点 TCP + 可选经代理访问常见站点 |
| 搜索 | 按名称 / 地址 / 协议过滤节点列表 |
| 持久化 | 订阅与节点本地保存，重启后恢复 |

### 体验与系统集成

| 能力 | 说明 |
| --- | --- |
| 托盘 | 关闭到托盘、托盘图标状态 |
| 热键 | 显示/隐藏窗口、启停代理（可自定义） |
| 开机自启 / 启动后连接 / 启动后最小化 | 设置面板开关 |
| 主题与字体 | 外观主题、界面字体大小 |
| 日志 | 首页运行日志、过滤、复制、清空、自动滚动 |
| 更新 | 检查软件更新；可手动更新核心文件 |

---

## 内置组件

每次 GitHub Actions 构建会从官方 Release 拉取并打入安装包：

| 文件 | 来源与用途 |
| --- | --- |
| `core/xray.exe` | [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — 默认协议出站 |
| `core/sing-box.exe` | [SagerNet/sing-box](https://github.com/SagerNet/sing-box) — TUN / 完整出站 |
| `core/mihomo.exe` | [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) — Clash Meta 兼容 |
| `core/geoip.dat` | [v2fly/geoip](https://github.com/v2fly/geoip) — IP 分流数据 |
| `core/geosite.dat` | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) — 域名分流数据 |
| `core/wintun.dll` | WireGuard 用户态驱动 — Windows TUN |

> 请勿单独移动 `Mobility.exe` 而丢掉 `core` 目录，否则无法启动核心。

---

## 快速开始

1. 打开 [Releases](../../releases) ，下载 **Mobility.zip**  
2. 解压到任意目录（建议路径中避免过于特殊的权限限制）  
3. 双击运行 `Mobility.exe`  
4. 在订阅栏粘贴订阅地址 → **加载**，或使用剪贴板 / 扫码导入节点  
5. （可选）**测速全部** → **选最快**  
6. 点击 **启动**；需要全局接管时勾选 **TUN 模式**（管理员运行）  

---

## 界面与使用说明

- **顶部**：运行状态、当前节点摘要、软件版本与**当前核心版本**、启动 / 停止  
- **订阅栏**：多订阅切换、URL、加载 / 添加 / 删除 / 重命名 / 更新全部  
- **工具栏**：测速、选最快、复制节点、连通性；右侧为并发与代理模式  
- **节点列表**：搜索、选中高亮；右侧为设置（托盘、自启、端口、协议核心映射等）  
- **运行日志**：实时输出；支持过滤、复制、清空、自动滚动  

标题栏版本示例：

- `v0.18.x | Xray 26.x`  
- `v0.18.x | sing-box 1.x`  
- `v0.18.x | Mihomo 1.x`  

会随**当前节点协议所映射的核心**变化。

---

## 核心与协议映射

在右侧 **设置 → 核心类型（按协议）** 中，可为下列协议分别选择核心：

- VMess  
- VLESS  
- Trojan  
- Shadowsocks  
- Socks  
- HTTP  

可选核心：**Xray** / **sing-box** / **Mihomo**。

启动时逻辑：

1. 读取当前选中节点的协议  
2. 查询该协议映射的核心  
3. 生成对应配置并拉起进程  
4. 标题栏刷新为该核心的版本号  

---

## 代理模式与路由

| 模式 | 行为概要 |
| --- | --- |
| 规则模式 | 按路由规则分流（含自定义直连/代理域名，结合 geo 数据） |
| 全局模式 | 尽可能将流量送入代理出站 |
| 直连模式 | 不走代理出站（便于排查） |

可在设置中维护 **直连域名** 与 **代理域名** 列表，修改后需重新启动代理生效。

---

## TUN 模式

- 勾选 **TUN 模式** 并启动后，尝试通过虚拟网卡接管系统流量  
- **需要管理员权限**；包内已带 `wintun.dll`  
- 为兼容浏览器，仍可能同时设置系统代理  
- 若仅 TUN 异常，可先关闭 TUN，仅使用系统代理排查节点与核心  

---

## 订阅与节点

- **多订阅**：彼此独立管理，支持合并去重策略  
- **更新**：手动「更新全部」，或设置定时/自定义间隔  
- **测速并发**：界面可选 8～256 路（过大可能受网络与机器性能限制）  
- **二维码**：支持扫码导入与为当前节点生成二维码便于手机扫描  

---

## 目录结构

```text
Mobility/
├── Mobility.exe          # 主程序
├── core/
│   ├── xray.exe
│   ├── sing-box.exe
│   ├── mihomo.exe
│   ├── geoip.dat
│   ├── geosite.dat
│   └── wintun.dll
└── （运行后）配置、订阅缓存、日志等
```

---

## 系统要求

- Windows 10 / 11（**64 位**）  
- 使用 TUN 时：管理员权限  
- 建议将安装目录加入杀毒软件白名单，避免核心被隔离  

---

## 常见问题

**Q: 启动后浏览器无法上网？**  
A: 确认节点延迟与连通性；尝试更换节点或代理模式；查看运行日志中的核心报错。

**Q: TUN 无效或提示 wintun？**  
A: 以管理员运行；确认 `core/wintun.dll` 存在且未被删除。

**Q: 标题栏一直显示某个核心？**  
A: 显示的是**当前节点协议所映射的核心**；请到设置中修改对应协议的映射。

**Q: 能否只更新某一个核心？**  
A: 可使用设置中的「更新核心」；亦可用官方发布包中的单文件替换 `core` 目录下对应 exe。

---

## 构建与发布

本仓库通过 **GitHub Actions + PyInstaller** 在 `windows-latest` 上构建：

1. 安装依赖并打包 `Mobility.exe`  
2. 下载 Xray / sing-box / Mihomo / geo 数据 / wintun  
3. 组装为 `Mobility.zip`  
4. 更新 README 并创建 GitHub Release  

手动触发：Actions → **Build Portable** → **Run workflow**，填写版本号（如 `0.18.1`）。

---

## 反馈与贡献

- 缺陷与需求：请使用 [Issue 模板](../../issues/new/choose)  
- 代码贡献：请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 后提交 PR  

---

## 免责声明

本软件仅供学习、研究网络与代理技术使用。请确保你的使用行为符合所在地法律法规以及相关服务条款。作者不对任何滥用或由此产生的后果承担责任。
