# Mobility

Windows 代理客户端

## 功能

- 已内置 Xray-core 与 geoip/geosite 数据
- 支持 vmess / vless / trojan 节点
- 一键启动 / 停止本地代理
- 自动设置 / 取消 Windows 系统代理
- 绿色便携版，解压即用

## 使用方法

1. 在 [Releases](../../releases) 下载 `Mobility.zip`
2. 解压到任意目录
3. 双击运行 `Mobility.exe`
4. 粘贴节点链接后点击「启动代理」

> 解压后请保持目录完整（包含 core 文件夹），不要单独移动 exe。

## 反馈与贡献

- **提交 Bug 或功能建议**：请到 [Issues](../../issues/new/choose) 页面选择对应模板提交
- **参与开发**：欢迎提交 Pull Request，请先阅读 [贡献指南](CONTRIBUTING.md)

## 构建

使用 GitHub Actions + PyInstaller 自动打包。

Actions 页面点击 **Build Portable** → **Run workflow**，填写版本号后即可自动构建并发布。

