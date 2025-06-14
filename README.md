# Docker Sing-box Manager

⚠️ **重要声明：本项目仅供学习和技术研究使用**

本工具仅用于学习网络技术和研究目的。请用户严格遵守当地法律法规，不得用于任何违法用途。使用本工具即表示您已了解并同意承担相应的法律责任。

一个基于 Docker 的 Sing-box 管理工具，提供简单易用的界面来管理和配置 Sing-box 网络服务。

## 快速安装

使用以下命令一键安装：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/imjettzhang/docker_singbox_manager/main/quickstart.sh)
```

## 支持的协议类型

本工具支持以下网络协议：

- **Hysteria2** - 基于 QUIC 的高性能网络协议
- **VLESS** - 轻量级网络协议
- **Trojan** - 模拟 HTTPS 流量的网络协议
- **Shadowsocks** - 经典的网络协议
- **VMess** - V2Ray 原生协议
- **TUIC** - 基于 QUIC 的网络协议
- **HTTP** - HTTP 协议
- **SOCKS5** - SOCKS5 协议

## 主要功能

- 🚀 一键安装和配置 Sing-box
- 📝 支持多种网络协议的节点管理
- 🐳 Docker 容器化部署
- 🔧 简单的配置管理界面

## 系统要求

- Linux 系统（推荐 Ubuntu/Debian）
- Docker 和 Docker Compose

## 注意事项

- 请确保服务器防火墙已开放相应端口
- 建议在全新的系统上安装，避免端口冲突
- 安装过程需要网络连接下载必要组件
- tuic节点导入V2rayN和Nekobox客户端请手动勾选不检查证书

## 免责声明

本项目开发者不对使用本工具产生的任何后果承担责任。用户应当自行承担使用风险，并确保其使用行为符合所在地区的法律法规要求。
