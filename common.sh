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