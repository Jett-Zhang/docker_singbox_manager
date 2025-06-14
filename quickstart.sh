#!/bin/bash
set -e

# 你所有脚本的文件名
files=(
  common.sh
  docker_manager.sh
  installer.sh
  main.sh
  menus.sh
  singbox_config.sh
  singbox_manager.sh
)

# 创建目标目录
mkdir -p docker_singbox_manager/sh

# 下载所有脚本
for file in "${files[@]}"; do
  # echo "正在下载 $file ..."
  curl -fsSL -o "docker_singbox_manager/sh/$file" "https://raw.githubusercontent.com/Jett-Zhang/docker_singbox_manager/main/$file"
done

# 给所有脚本加执行权限
chmod +x docker_singbox_manager/sh/*.sh

# 运行主程序
./docker_singbox_manager/sh/main.sh