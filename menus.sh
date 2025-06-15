#!/bin/bash

# 菜单模块
# 包含所有用户界面菜单和主菜单显示功能

# 引入所有必要模块
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/docker_manager.sh"
source "$(dirname "$0")/singbox_config.sh"
source "$(dirname "$0")/installer.sh"

# 节点管理菜单
node_management_menu() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "配置文件不存在，请先安装系统"
        return
    fi
    
    while true; do
        clear
        echo -e "${BLUE}================================${NC}"
        echo -e "${BLUE}        节点管理菜单${NC}"
        echo -e "${BLUE}================================${NC}"
        echo ""
        
        local node_count=$(jq '.inbounds | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
        echo -e "${GREEN}● 当前节点数量: $node_count${NC}"
        echo ""
        
        echo -e "${BLUE}请选择操作:${NC}"
        echo "1. 添加节点"
        echo "2. 删除节点"
        echo "3. 显示所有节点"
        echo "4. 查看配置文件"
        echo "0. 返回主菜单"
        echo ""
        
        read -p "请输入选择 [0-4]: " node_choice
        
        case $node_choice in
            1) 
                add_node_menu
                ;;
            2) 
                delete_node
                read -p "按回车键继续..."
                ;;
            3) 
                show_nodes
                read -p "按回车键继续..."
                ;;
            4) 
                view_config
                ;;
            0) 
                break
                ;;
            *) 
                log_error "无效选择，请重新输入"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 简化的出站策略菜单
outbound_strategy_menu() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "配置文件不存在，请先安装 Sing-Box"
        return
    fi
    
    while true; do
        clear
        echo -e "${BLUE}================================${NC}"
        echo -e "${BLUE}        出站IP策略设置${NC}"
        echo -e "${BLUE}================================${NC}"
        echo ""
        
        # 显示当前策略
        local current_strategy=$(jq -r '.outbounds[] | select(.type == "direct") | .domain_strategy // "未设置"' "$CONFIG_FILE" 2>/dev/null | head -1)
        local current_dns=$(jq -r '.dns.strategy // "未设置"' "$CONFIG_FILE" 2>/dev/null)
        local current_final=$(jq -r '.route.final // "未设置"' "$CONFIG_FILE" 2>/dev/null)
        
        echo -e "${GREEN}● 当前出站策略: $current_strategy${NC}"
        echo -e "${GREEN}● 当前DNS策略: $current_dns${NC}"
        echo -e "${GREEN}● 当前最终出站: $current_final${NC}"
        echo ""
        
        echo -e "${BLUE}请选择出站IP策略:${NC}"
        echo "1. IPv4 优先 (推荐)"
        echo "2. IPv6 优先"
        echo "3. 仅 IPv4"
        echo "4. 仅 IPv6"
        echo "0. 返回主菜单"
        echo ""
        
        read -p "请选择 (0-4): " strategy_choice
        
        case $strategy_choice in
            1)
                set_strategy "prefer_ipv4" "cf-ipv4" "prefer_ipv4"
                ;;
            2)
                set_strategy "prefer_ipv6" "cf-ipv6" "prefer_ipv6"
                ;;
            3)
                set_strategy "ipv4_only" "cf-ipv4" "ipv4_only"
                ;;
            4)
                set_strategy "ipv6_only" "cf-ipv6" "ipv6_only"
                ;;
            0)
                break
                ;;
            *)
                log_error "无效选择"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 设置策略的辅助函数
set_strategy() {
    local strategy=$1
    local dns_final=$2
    local dns_strategy=$3
    
    log_step "设置出站策略: $strategy"
    
    # 确定对应的直连出站标签
    local direct_outbound
    case $strategy in
        "prefer_ipv4"|"ipv4_only")
            direct_outbound="direct-ipv4"
            ;;
        "prefer_ipv6"|"ipv6_only") 
            direct_outbound="direct-ipv6"
            ;;
        *)
            direct_outbound="direct-ipv4"
            ;;
    esac
    
    # 更新配置文件 - 更新所有direct类型的出站，并设置正确的final出站
    jq --arg strategy "$strategy" --arg dns_final "$dns_final" --arg dns_strategy "$dns_strategy" --arg final_outbound "$direct_outbound" '
    .outbounds = (.outbounds | map(
        if .type == "direct" then 
            .domain_strategy = $strategy 
        else 
            . 
        end
    )) |
    .dns.final = $dns_final | 
    .dns.strategy = $dns_strategy |
    .route.final = $final_outbound' "$CONFIG_FILE" > /tmp/config_tmp.json
    mv /tmp/config_tmp.json "$CONFIG_FILE"
    
    restart_singbox
    
    log_success "出站IP策略已设置为: $strategy (最终出站: $direct_outbound)"
    read -p "按回车键继续..."
}

# 服务管理菜单
management_menu() {
    while true; do
        clear
        echo -e "${BLUE}================================${NC}"
        echo -e "${BLUE}        服务管理菜单${NC}"
        echo -e "${BLUE}================================${NC}"
        echo ""
        
        if docker ps | grep -q jett-sing-box; then
            echo -e "${GREEN}● Sing-Box: 运行中${NC}"
        else
            echo -e "${RED}● Sing-Box: 未运行${NC}"
        fi
        echo ""
        
        echo -e "${BLUE}请选择操作:${NC}"
        echo "1. 重启 Sing-Box"
        echo "2. 停止 Sing-Box"
        echo "3. 启动 Sing-Box"
        echo "4. 查看 Sing-Box 日志"
        echo "5. 卸载 Sing-Box"
        echo "0. 返回主菜单"
        echo ""
        
        read -p "请输入选择 [0-6]: " mgmt_choice
        
        case $mgmt_choice in
            1)
                restart_singbox
                read -p "按回车键继续..."
                ;;
            2)
                stop_singbox
                read -p "按回车键继续..."
                ;;
            3)
                start_singbox
                read -p "按回车键继续..."
                ;;
            4)
                view_singbox_logs
                ;;
            5)
                uninstall_singbox
                read -p "按回车键继续..."
                ;;
            0)
                break
                ;;
            *)
                log_error "无效选择"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 主菜单显示函数
show_menu() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Docker Sing-Box 管理脚本${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    echo -e "${GREEN}● 操作系统: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Linux")${NC}"

    if ! command -v docker &> /dev/null; then
        echo -e "${RED}● Docker 状态: 未安装${NC}"
        echo -e "${RED}● Sing-Box 状态: 未安装${NC}"
    else
        echo -e "${GREEN}● Docker 状态: 已安装${NC}"
        
        if docker ps 2>/dev/null | grep -q jett-sing-box; then
            echo -e "${GREEN}● Sing-Box 状态: 运行中${NC}"
        else
            echo -e "${RED}● Sing-Box 状态: 未运行${NC}"
        fi
    fi
    
    if [ -f "$CONFIG_FILE" ]; then
        local current_outbound=$(jq -r '.route.final' "$CONFIG_FILE" 2>/dev/null || echo "未设置")
        local node_count=$(jq '.inbounds | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
        echo -e "${GREEN}● 默认出站: $current_outbound${NC}"
        echo -e "${GREEN}● 配置节点数: $node_count${NC}"
    fi
    
    local current_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d' ' -f3 || echo "未知")
    local firewall_type=$(get_firewall_type)
    local ipv4=$(curl -4 -s --connect-timeout 3 https://api.ipify.org 2>/dev/null || echo "获取失败")
    local ipv6=$(curl -6 -s --connect-timeout 3 https://api6.ipify.org 2>/dev/null || echo "获取失败")
    echo -e "${GREEN}● 本机 IPv4: $ipv4${NC}"
    echo -e "${GREEN}● 本机 IPv6: $ipv6${NC}"
    echo -e "${GREEN}● 当前拥塞控制算法: $current_congestion${NC}"
    
    case $firewall_type in
        "ufw")
            echo -e "${GREEN}● 防火墙状态: ufw 已安装${NC}"
            ;;
        "none")
            echo -e "${YELLOW}● 防火墙状态: 未安装 ufw (端口默认开放)${NC}"
            ;;
    esac
    
    echo ""
    echo -e "${BLUE}请选择操作:${NC}"
    echo "1. 安装 Sing-Box"
    echo "2. 节点管理"
    echo "3. 出站策略配置"
    echo "4. 服务管理"
    echo "5. 开启/关闭BBR"
    echo "0. 退出"
    echo ""
}

# BBR 管理菜单
bbr_management_menu() {
    while true; do
        clear
        echo -e "${BLUE}================================${NC}"
        echo -e "${BLUE}        BBR 管理菜单${NC}"
        echo -e "${BLUE}================================${NC}"
        echo ""
        
        # 获取BBR状态信息
        local bbr_info=$(check_bbr_status)
        local current_congestion=$(echo "$bbr_info" | grep "current:" | cut -d: -f2)
        local kernel_version=$(uname -r)
        
        echo -e "${GREEN}● 内核版本: $kernel_version${NC}"
        echo -e "${GREEN}● 当前拥塞控制算法: $current_congestion${NC}"
        
        if [ "$current_congestion" = "bbr" ]; then
            echo -e "${GREEN}● BBR 状态: 已启用${NC}"
        else
            echo -e "${RED}● BBR 状态: 未启用${NC}"
        fi
        
        echo ""
        echo -e "${BLUE}请选择操作:${NC}"
        echo "1. 开启 BBR"
        echo "2. 关闭 BBR"
        echo "3. 查看 BBR 状态"
        echo "0. 返回主菜单"
        echo ""
        
        read -p "请输入选择 [0-3]: " bbr_choice
        
        case $bbr_choice in
            1)
                enable_bbr
                read -p "按回车键继续..."
                ;;
            2)
                disable_bbr
                read -p "按回车键继续..."
                ;;
            3)
                echo ""
                echo -e "${BLUE}=== BBR 详细状态 ===${NC}"
                echo -e "${GREEN}内核版本: $(uname -r)${NC}"
                echo -e "${GREEN}当前拥塞控制: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d' ' -f3)${NC}"
                echo -e "${GREEN}默认队列规则: $(sysctl net.core.default_qdisc 2>/dev/null | cut -d' ' -f3)${NC}"
                echo -e "${GREEN}可用拥塞控制: $(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | cut -d' ' -f3-)${NC}"
                echo ""
                if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
                    echo -e "${GREEN}✔ BBR 已启用并正在运行${NC}"
                else
                    echo -e "${RED}✖ BBR 未启用${NC}"
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            0)
                break
                ;;
            *)
                log_error "无效选择"
                read -p "按回车键继续..."
                ;;
        esac
    done
} 