#!/bin/bash

# 公共函数和变量定义
# 包含通用的日志函数、颜色定义等

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置文件路径
DATA_DIR="/data/jett-sing-box"
CONFIG_FILE="$DATA_DIR/data/config.json"

# 日志函数
log_step() {
    echo -e "\n${BLUE}>>> $1 <<<${NC}"
}

log_success() {
    echo -e "${GREEN}✔ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

log_error() {
    echo -e "${RED}✖ $1${NC}" >&2
}

# 处理域名/IP输入，自动为IPv6地址添加方括号
process_domain_input() {
    local input="$1"
    local default_ip="$2"
    
    # 如果输入为空，使用默认IP
    if [[ -z "$input" ]]; then
        echo "$default_ip"
        return
    fi
    
    # 检查是否为IPv6地址（包含冒号且不是IPv4:port格式）
    if [[ "$input" =~ : ]] && [[ ! "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
        # 如果已经有方括号，直接返回
        if [[ "$input" =~ ^\[.*\]$ ]]; then
            echo "$input"
        else
            # 为IPv6地址添加方括号
            echo "[$input]"
        fi
    else
        # IPv4地址或域名，直接返回
        echo "$input"
    fi
}

# 检查依赖
check_dependencies() {
    if ! command -v jq &> /dev/null; then
        log_step "安装 jq..."
        apt install -y sudo
        sudo apt update -qq
        sudo apt install -y jq
    fi
    
    # 检查防火墙状态
    check_firewall_status
}

# 检查防火墙状态
check_firewall_status() {
    # 只检查是否安装了ufw
    if command -v ufw &> /dev/null; then
        export FIREWALL_TYPE="ufw"
        log_success "检测到 ufw 防火墙"
        return
    fi
    
    # 没有ufw，设置为none（iptables默认全放行，无需管理）
    export FIREWALL_TYPE="none"
    log_success "未检测到 ufw 防火墙，端口默认开放"
}

# 获取防火墙类型
get_firewall_type() {
    echo "${FIREWALL_TYPE:-none}"
}

# 生成随机字符串
generate_random() {
    local type=$1
    case $type in
        "uuid")
            if command -v uuidgen &> /dev/null; then
                uuidgen
            else
                cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1 | sed 's/\(.{8}\)\(.{4}\)\(.{4}\)\(.{4}\)\(.{12}\)/\1-\2-\3-\4-\5/')"
            fi
            ;;
        "password")
            openssl rand -base64 16 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1
            ;;
        "short")
            openssl rand -hex 8 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 8 | head -n 1
            ;;
        "base64")
            openssl rand -base64 8 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1
            ;;
    esac
}

# 获取可用端口
get_free_port() {
    local start_port=${1:-20000}
    local end_port=${2:-60000}
    
    for port in $(shuf -i $start_port-$end_port -n 50); do
        if ! ss -tuln | grep -q ":$port\s" && ! jq -r '.inbounds[].listen_port' "$CONFIG_FILE" 2>/dev/null | grep -q "^$port$"; then
            echo $port
            return
        fi
    done
    echo "0"
}

# 重启sing-box
restart_singbox() {
    if docker ps | grep -q jett-sing-box; then
        log_step "重启 Sing-Box..."
        cd "$DATA_DIR"
        docker compose restart sing-box
        sleep 3
        
        if docker ps | grep -q jett-sing-box; then
            log_success "Sing-Box 重启成功"
        else
            log_error "Sing-Box 重启失败"
        fi
    fi
}

# 停止Sing-Box
stop_singbox() {
    log_step "停止 Sing-Box"
    
    if docker ps | grep -q jett-sing-box; then
        docker stop jett-sing-box
        log_success "Sing-Box 已停止"
    else
        log_warning "Sing-Box 未运行"
    fi
}

# 启动Sing-Box
start_singbox() {
    log_step "启动 Sing-Box"
    
    if docker ps -a | grep -q jett-sing-box && ! docker ps | grep -q jett-sing-box; then
        docker start jett-sing-box
        sleep 5
        log_success "Sing-Box 已启动"
    else
        log_warning "Sing-Box 容器不存在或已运行"
    fi
}

# 检查BBR状态
check_bbr_status() {
    local current_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d' ' -f3)
    local available_congestion=$(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | cut -d' ' -f3-)
    
    echo "current:$current_congestion"
    echo "available:$available_congestion"
}

# 开启BBR
enable_bbr() {
    log_step "开启 BBR 拥塞控制算法"
    
    # 检查内核版本
    local kernel_version=$(uname -r | cut -d. -f1-2)
    local major_version=$(echo $kernel_version | cut -d. -f1)
    local minor_version=$(echo $kernel_version | cut -d. -f2)
    
    if [ "$major_version" -lt 4 ] || ([ "$major_version" -eq 4 ] && [ "$minor_version" -lt 9 ]); then
        log_error "内核版本过低 ($kernel_version)，BBR 需要内核版本 4.9 或更高"
        return 1
    fi
    
    # 检查是否已经启用BBR
    local current_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d' ' -f3)
    if [ "$current_congestion" = "bbr" ]; then
        log_warning "BBR 已经启用"
        return 0
    fi
    
    # 检查BBR是否可用
    if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
        log_error "BBR 模块不可用，可能需要更新内核"
        return 1
    fi
    
    # 备份原始配置
    if [ ! -f /etc/sysctl.conf.bak ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
        log_step "已备份原始配置到 /etc/sysctl.conf.bak"
    fi
    
    # 添加BBR配置
    cat >> /etc/sysctl.conf << EOF

# BBR 拥塞控制算法配置
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    # 应用配置（静默模式）
    sysctl -p > /dev/null 2>&1
    
    # 验证配置
    local new_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d' ' -f3)
    if [ "$new_congestion" = "bbr" ]; then
        log_success "BBR 已成功启用"
        return 0
    else
        log_error "BBR 启用失败"
        return 1
    fi
}

# 关闭BBR
disable_bbr() {
    log_step "关闭 BBR 拥塞控制算法"
    
    # 检查是否启用了BBR
    local current_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d' ' -f3)
    if [ "$current_congestion" != "bbr" ]; then
        log_warning "BBR 未启用"
        return 0
    fi
    
    # 恢复默认配置
    sysctl -w net.ipv4.tcp_congestion_control=cubic
    sysctl -w net.core.default_qdisc=pfifo_fast
    
    # 从配置文件中移除BBR配置
    if [ -f /etc/sysctl.conf ]; then
        sed -i '/# BBR 拥塞控制算法配置/,+2d' /etc/sysctl.conf
    fi
    
    # 验证配置
    local new_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d' ' -f3)
    if [ "$new_congestion" != "bbr" ]; then
        log_success "BBR 已关闭，当前使用: $new_congestion"
        return 0
    else
        log_error "BBR 关闭失败"
        return 1
    fi
}

# 开放防火墙端口
open_firewall_port() {
    local port=$1
    local protocol=$2
    local firewall_type=$(get_firewall_type)
    
    case $firewall_type in
        "ufw")
            log_step "开放防火墙端口 $port/$protocol (ufw)"
            sudo ufw allow $port/$protocol > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                log_success "防火墙端口 $port/$protocol 已开放"
            else
                log_warning "防火墙端口 $port/$protocol 开放失败"
            fi
            ;;
        "none")
            log_step "无 ufw 防火墙，端口 $port/$protocol 默认开放"
            ;;
    esac
}

# 关闭防火墙端口
close_firewall_port() {
    local port=$1
    local protocol=$2
    local firewall_type=$(get_firewall_type)
    
    case $firewall_type in
        "ufw")
            log_step "关闭防火墙端口 $port/$protocol (ufw)"
            sudo ufw delete allow $port/$protocol > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                log_success "防火墙端口 $port/$protocol 已关闭"
            else
                log_warning "防火墙端口 $port/$protocol 关闭失败"
            fi
            ;;
        "none")
            log_step "无 ufw 防火墙，跳过端口 $port/$protocol 关闭"
            ;;
    esac
}

# 关闭所有节点端口
close_all_node_ports() {
    local firewall_type=$(get_firewall_type)
    
    if [ "$firewall_type" = "none" ]; then
        log_step "无 ufw 防火墙，跳过端口关闭操作"
        return
    fi
    
    if [ ! -f "$CONFIG_FILE" ]; then
        log_warning "配置文件不存在，跳过端口关闭"
        return
    fi
    
    local node_count=$(jq '.inbounds | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
    if [ "$node_count" -eq 0 ]; then
        log_warning "没有找到节点配置，跳过端口关闭"
        return
    fi
    
    log_step "关闭所有节点防火墙端口..."
    
    for i in $(seq 0 $((node_count - 1))); do
        local node_type=$(jq -r ".inbounds[$i].type" "$CONFIG_FILE" 2>/dev/null)
        local node_port=$(jq -r ".inbounds[$i].listen_port" "$CONFIG_FILE" 2>/dev/null)
        local node_tag=$(jq -r ".inbounds[$i].tag // \"节点$((i + 1))\"" "$CONFIG_FILE" 2>/dev/null)
        
        if [ "$node_port" != "null" ] && [ "$node_port" != "" ]; then
            case $node_type in
                "hysteria2"|"tuic")
                    close_firewall_port $node_port "udp"
                    ;;
                *)
                    close_firewall_port $node_port "tcp"
                    ;;
            esac
        fi
    done
    
    log_success "所有节点防火墙端口已关闭"
} 