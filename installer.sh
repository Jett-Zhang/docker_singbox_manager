#!/bin/bash

# Sing-Box 安装模块
# 包含 Sing-Box 安装和初始化功能

# 引入必要模块
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/docker_manager.sh"
source "$(dirname "$0")/singbox_config.sh"

# 安装Sing-Box系统
install_singbox_system() {
    log_step "开始安装 Sing-Box 系统"
    
    if ! check_and_install_docker; then
        return 1
    fi
    
    if docker ps -a | grep -q jett-sing-box; then
        log_warning "检测到已存在的容器"
        read -p "是否重新安装？(y/n): " reinstall
        if [[ "$reinstall" != "y" ]]; then
            return
        fi
        
        # 先根据旧配置关闭防火墙端口
        close_all_node_ports
        
        # 然后停止和删除容器及配置
        docker stop jett-sing-box >/dev/null 2>&1 || true
        docker rm jett-sing-box >/dev/null 2>&1 || true
        rm -rf "$DATA_DIR"
    fi
    
    IPV4=$(curl -4 -s https://api.ipify.org || echo "162.211.228.142")
    
    read -p "请输入节点域名/IP（默认使用IP: $IPV4）: " DOMAIN_INPUT
    DOMAIN=$(process_domain_input "$DOMAIN_INPUT" "$IPV4")
    
    # 创建默认配置
    create_default_config
    echo "$DOMAIN" > "$DATA_DIR/data/domain.txt"
    
    cat > "$DATA_DIR/docker-compose.yml" << EOF
services:
  sing-box:
    image: ghcr.io/sagernet/sing-box
    container_name: jett-sing-box
    restart: unless-stopped
    network_mode: "host"
    privileged: true
    volumes:
      - $DATA_DIR/data:/data/sing-box/data
      - $DATA_DIR/tls:/data/sing-box/tls
    command: ["-c", "/data/sing-box/data/config.json", "run"]
EOF
    
    log_step "启动 Sing-Box 容器"
    cd "$DATA_DIR"
    docker compose up -d
    
    sleep 5
    
    if docker ps | grep -q jett-sing-box; then
        log_success "Sing-Box 系统安装成功"
        echo -e "${GREEN}域名/IP: $DOMAIN${NC}"
        echo -e "${GREEN}配置文件: $CONFIG_FILE${NC}"
    else
        log_error "Sing-Box 启动失败"
        docker logs jett-sing-box
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
        fi
    else
        echo "Sing-Box容器: 未运行"
    fi
} 