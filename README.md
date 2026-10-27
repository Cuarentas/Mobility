# Mobility

Windows 代理客户端

## 功能

- 自动下载并内置 Xray-core
- 一键启动 / 停止本地代理
- 自动设置 / 取消 Windows 系统代理
- 单文件便携版（无需安装 Python）

## 使用方法

1. 在 [Releases](../../releases) 下载 `Mobility.exe`
2. 双击运行
3. 点击「启动代理」

## 反馈与贡献

- **提交 Bug 或功能建议**：请到 [Issues](../../issues/new/choose) 页面选择对应模板提交
- **参与开发**：欢迎提交 Pull Request，请先阅读 [贡献指南](CONTRIBUTING.md)

## 构建

使用 GitHub Actions + Nuitka 自动打包。

Actions 页面点击 **Build Portable EXE** → **Run workflow**，填写版本号后即可自动构建并发布。
