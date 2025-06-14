#!/bin/bash

set -e

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

# 检查依赖
check_dependencies() {
    if ! command -v jq &> /dev/null; then
        log_step "安装 jq..."
        sudo apt update -qq
        sudo apt install -y jq
    fi
}

# 创建默认配置文件
create_default_config() {
    log_step "创建默认配置文件"
    
    mkdir -p "$DATA_DIR/data" "$DATA_DIR/tls" "$DATA_DIR/logs"
    
    if [ ! -f "$DATA_DIR/tls/fullchain.cer" ]; then
        cd "$DATA_DIR/tls"
        openssl req -x509 -newkey rsa:2048 -keyout private.key -out fullchain.cer -days 1825 -nodes -subj "/CN=bing.com" >/dev/null 2>&1
        log_success "SSL 证书生成完成"
    fi
    
    cat > "$CONFIG_FILE" << 'EOF'
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "cf-ipv4",
        "address": "1.1.1.1",
        "strategy": "ipv4_only"
      },
      {
        "tag": "cf-ipv6", 
        "address": "2606:4700:4700::1111",
        "strategy": "ipv6_only"
      },
      {
        "tag": "google",
        "address": "8.8.8.8",
        "strategy": "prefer_ipv4"
      }
    ],
    "final": "cf-ipv4",
    "strategy": "ipv4_only"
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-ipv4",
      "domain_strategy": "ipv4_only"
    },
    {
      "type": "direct",
      "tag": "direct-ipv6",
      "domain_strategy": "ipv6_only"
    },
    {
      "type": "direct",
      "tag": "direct",
      "domain_strategy": "prefer_ipv4"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": ["bittorrent", "quic"],
        "outbound": "block"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      }
    ],
    "final": "direct"
  }
}
EOF
    
    log_success "默认配置文件创建完成"
}

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
        
        docker stop jett-sing-box >/dev/null 2>&1 || true
        docker rm jett-sing-box >/dev/null 2>&1 || true
        rm -rf "$DATA_DIR"
    fi
    
    IPV4=$(curl -4 -s https://api.ipify.org || echo "未知")
    
    read -p "请输入节点域名/IP（默认使用IP: $IPV4）: " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        DOMAIN="$IPV4"
    fi
    
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

# 添加 Hysteria2 节点
add_hysteria2() {
    log_step "添加 Hysteria2 节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    local password=$(generate_random "uuid")
    
    read -p "请输入端口 (默认随机端口: $port): " input_port
    port=${input_port:-$port}
    
    read -p "请输入密码 (默认随机生成): " input_password
    password=${input_password:-$password}
    
    local new_inbound=$(cat << EOF
{
  "type": "hysteria2",
  "tag": "hy2-$port",
  "listen": "::",
  "listen_port": $port,
  "up_mbps": 100,
  "down_mbps": 100,
  "users": [{"password": "$password"}],
  "tls": {
    "enabled": true,
    "server_name": "bing.com",
    "certificate_path": "/data/sing-box/tls/fullchain.cer",
    "key_path": "/data/sing-box/tls/private.key"
  }
}
EOF
)
    
    echo "$new_inbound" | jq . > /tmp/new_inbound.json
    jq '.inbounds += [input]' "$CONFIG_FILE" /tmp/new_inbound.json > /tmp/config_tmp.json
    mv /tmp/config_tmp.json "$CONFIG_FILE"
    
    restart_singbox
    
    log_success "Hysteria2 节点添加成功"
    echo -e "${GREEN}端口: $port${NC}"
    echo -e "${GREEN}密码: $password${NC}"
    
    local domain=$(cat "$DATA_DIR/data/domain.txt")
    local formatted_domain=$(format_address "$domain")
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}hysteria2://$password@$formatted_domain:$port/?sni=bing.com&alpn=h3&insecure=1#hy2-$port${NC}"
}

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
        echo "1. 添加 Hysteria2 节点"
        echo "2. 显示所有节点"
        echo "0. 返回主菜单"
        echo ""
        
        read -p "请输入选择 [0-2]: " node_choice
        
        case $node_choice in
            1) 
                add_hysteria2
                read -p "按回车键继续..."
                ;;
            2) 
                show_nodes
                read -p "按回车键继续..."
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

# 显示所有节点
show_nodes() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "配置文件不存在，请先安装系统"
        return
    fi
    
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}        所有节点信息${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    local node_count=$(jq '.inbounds | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
    
    if [ "$node_count" -eq 0 ]; then
        log_warning "当前没有配置任何节点"
        return
    fi
    
    echo -e "${GREEN}● 总节点数: $node_count${NC}"
    local domain=$(cat "$DATA_DIR/data/domain.txt" 2>/dev/null || echo "未设置")
    echo -e "${GREEN}● 服务器域名/IP: $domain${NC}"
    echo ""
    
    # 格式化域名/IP地址（IPv6需要加方括号）
    local formatted_domain=$(format_address "$domain")
    
    for i in $(seq 0 $((node_count-1))); do
        local node_type=$(jq -r ".inbounds[$i].type" "$CONFIG_FILE")
        local node_tag=$(jq -r ".inbounds[$i].tag // \"节点$((i+1))\"" "$CONFIG_FILE")
        local node_port=$(jq -r ".inbounds[$i].listen_port" "$CONFIG_FILE")
        
        echo -e "${BLUE}节点 $((i+1)): $node_tag${NC}"
        echo -e "  类型: $node_type"
        echo -e "  端口: $node_port"
        
        if [[ "$node_type" == "hysteria2" ]]; then
            local password=$(jq -r ".inbounds[$i].users[0].password" "$CONFIG_FILE")
            echo -e "  密码: $password"
            echo -e "  客户端链接: ${GREEN}hysteria2://$password@$formatted_domain:$node_port/?sni=bing.com&alpn=h3&insecure=1#$node_tag${NC}"
        fi
        echo ""
    done
}

# 出站策略菜单
outbound_strategy_menu() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "配置文件不存在，请先安装 Sing-Box"
        return
    fi
    
    while true; do
        clear
        echo -e "${BLUE}================================${NC}"
        echo -e "${BLUE}      出站策略设置菜单${NC}"
        echo -e "${BLUE}================================${NC}"
        echo ""
        
        # 显示当前策略
        local current_strategy=$(jq -r '.outbounds[] | select(.type == "direct") | .domain_strategy // "未设置"' "$CONFIG_FILE" 2>/dev/null | head -1)
        local current_dns=$(jq -r '.dns.strategy // "未设置"' "$CONFIG_FILE" 2>/dev/null)
        echo -e "${GREEN}● 当前出站策略: $current_strategy${NC}"
        echo -e "${GREEN}● 当前DNS策略: $current_dns${NC}"
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
    
    # 更新配置文件 - 更新所有direct类型的出站
    jq --arg strategy "$strategy" --arg dns_final "$dns_final" --arg dns_strategy "$dns_strategy" '
    .outbounds = (.outbounds | map(
        if .type == "direct" then 
            .domain_strategy = $strategy 
        else 
            . 
        end
    )) |
    .dns.final = $dns_final | 
    .dns.strategy = $dns_strategy' "$CONFIG_FILE" > /tmp/config_tmp.json
    mv /tmp/config_tmp.json "$CONFIG_FILE"
    
    restart_singbox
    
    log_success "出站IP策略已设置为: $strategy"
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
                system_status_check
                read -p "按回车键继续..."
                ;;
            6)
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

# 查看Sing-Box日志
view_singbox_logs() {
    if docker ps -a | grep -q jett-sing-box; then
        echo -e "${BLUE}显示 Sing-Box 最近 100 条日志:${NC}"
        docker logs --tail 100 jett-sing-box
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
    
    docker stop jett-sing-box >/dev/null 2>&1 || true
    docker rm jett-sing-box >/dev/null 2>&1 || true
    
    rm -rf "$DATA_DIR"
    
    log_success "Sing-Box 卸载完成"
}

# 主菜单
show_menu() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Sing-Box 管理脚本${NC}"
    echo -e "${BLUE}         v3.0 简化版${NC}"
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
    
    local ipv4=$(curl -4 -s --connect-timeout 3 https://api.ipify.org 2>/dev/null || echo "获取失败")
    local ipv6=$(curl -6 -s --connect-timeout 3 https://api6.ipify.org 2>/dev/null || echo "获取失败")
    echo -e "${GREEN}● 本机 IPv4: $ipv4${NC}"
    echo -e "${GREEN}● 本机 IPv6: $ipv6${NC}"
    
    echo ""
    echo -e "${BLUE}请选择操作:${NC}"
    echo "1. 安装 Sing-Box"
    echo "2. 节点管理"
    echo "3. 出站策略配置"
    echo "4. 服务管理"
    echo "0. 退出"
    echo ""
}

# 主程序
main() {
    check_dependencies
    
    while true; do
        show_menu
        read -p "请输入选择 [0-4]: " choice
        
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