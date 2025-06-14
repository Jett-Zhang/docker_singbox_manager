# Docker Sing-box Manager

一个基于 Docker 的 Sing-box 管理工具，提供简单易用的界面来管理和配置 Sing-box 代理服务。

## 快速安装

使用以下命令一键安装：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Jett-Zhang/singbox_manager/main/quickstart.sh)
```

## 支持的节点类型

本工具支持以下代理协议：

- **Hysteria2** - 基于 QUIC 的高性能代理协议
- **VLESS** - 轻量级代理协议
- **Trojan** - 模拟 HTTPS 流量的代理协议
- **Shadowsocks** - 经典的代理协议
- **VMess** - V2Ray 原生协议
- **TUIC** - 基于 QUIC 的代理协议
- **HTTP** - HTTP 代理
- **SOCKS5** - SOCKS5 代理

## 主要功能

- 🚀 一键安装和配置 Sing-box
- 📝 支持多种代理协议的节点管理
- 🐳 Docker 容器化部署
- 🔧 简单的配置管理界面


## 系统要求

- Linux 系统（推荐 Ubuntu/Debian/CentOS）
- Docker 和 Docker Compose
- Curl 工具
- 管理员权限

## 注意事项

- 请确保服务器防火墙已开放相应端口
- 建议在全新的系统上安装，避免端口冲突
- 安装过程需要网络连接下载必要组件
