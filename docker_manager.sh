#!/bin/bash

# Docker 管理模块
# 包含 Docker 安装、服务管理等功能

# 引入通用模块
source "$(dirname "$0")/common.sh"

# 检查并安装Docker
check_and_install_docker() {
    if ! command -v docker &> /dev/null; then
        log_warning "未检测到 Docker"
        echo -e "${YELLOW}Docker 是运行 Sing-Box 的必要组件${NC}"
        read -p "是否现在安装 Docker？(y/n): " install_docker
        
        if [[ "$install_docker" != "y" ]]; then
            log_error "取消安装，Docker 是必需的"
            return 1
        fi
        
        log_step "开始安装 Docker..."
        curl -fsSL https://get.docker.com | bash
        sudo systemctl enable docker
        sudo systemctl start docker
        sudo usermod -aG docker $USER
        
        log_success "Docker 安装完成"
        return 0
    else
        log_success "Docker 已安装"
        return 0
    fi
}

# 查看Sing-Box日志
view_singbox_logs() {
    if docker ps -a | grep -q jett-sing-box; then
        echo -e "${BLUE}显示 Sing-Box 最近 50 条日志:${NC}"
        docker logs --tail 50 jett-sing-box
        echo ""
        read -p "按回车键返回..."
    else
        log_error "Sing-Box 容器未找到"
        read -p "按回车键返回..."
    fi
}

# 系统状态检查
system_status_check() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}        系统状态检查${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    echo -e "${GREEN}=== 系统信息 ===${NC}"
    echo "操作系统: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Linux")"
    echo "内核版本: $(uname -r)"
    echo ""
    
    echo -e "${GREEN}=== 网络信息 ===${NC}"
    local ipv4=$(curl -4 -s --connect-timeout 3 https://api.ipify.org 2>/dev/null || echo "获取失败")
    local ipv6=$(curl -6 -s --connect-timeout 3 https://api6.ipify.org 2>/dev/null || echo "获取失败")
    echo "本机IPv4: $ipv4"
    echo "本机IPv6: $ipv6"
    echo ""
    
    echo -e "${GREEN}=== Sing-Box 状态 ===${NC}"
    if docker ps | grep -q jett-sing-box; then
        echo "Sing-Box容器: 运行中"
        if [ -f "$CONFIG_FILE" ]; then
            local current_outbound=$(jq -r '.route.final' "$CONFIG_FILE" 2>/dev/null || echo "未知")
            echo "默认出站: $current_outbound"
            
            local node_count=$(jq '.inbounds | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
            echo "配置节点数: $node_count"
        fi
    else
        echo "Sing-Box容器: 未运行"
    fi
}

# 卸载Sing-Box
uninstall_singbox() {
    log_step "卸载 Sing-Box"
    
    echo -e "${YELLOW}警告：此操作将完全删除 Sing-Box 及其所有数据！${NC}"
    read -p "是否确认卸载？(y/n): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_warning "卸载操作已取消"
        return
    fi
    
    # 关闭所有节点端口
    close_all_node_ports
    
    docker stop jett-sing-box >/dev/null 2>&1 || true
    docker rm jett-sing-box >/dev/null 2>&1 || true
    
    rm -rf "$DATA_DIR"
    
    log_success "Sing-Box 卸载完成"
} 