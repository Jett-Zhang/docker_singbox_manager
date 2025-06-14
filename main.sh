#!/bin/bash

# Sing-Box 管理脚本 v3.0 模块化版本
# 主程序入口

set -e

# 获取脚本所在目录
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# 引入所有模块
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/menus.sh"

# 主程序
main() {
    # 检查依赖
    check_dependencies
    
    # 主循环
    while true; do
        show_menu
        read -p "请输入选择 [0-5]: " choice
        
        case $choice in
            1)
                install_singbox_system
                read -p "按回车键继续..."
                ;;
            2)
                node_management_menu
                ;;
            3)
                outbound_strategy_menu
                ;;
            4)
                management_menu
                ;;
            5)
                bbr_management_menu
                ;;
            0)
                echo -e "${GREEN}感谢使用 Sing-Box 管理脚本！${NC}"
                exit 0
                ;;
            *)
                log_error "无效选择，请重新输入"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 运行主程序
main "$@" 