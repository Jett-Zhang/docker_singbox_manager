#!/bin/bash

# Sing-Box 配置管理模块
# 包含配置文件生成、节点管理等功能

# 引入通用模块
source "$(dirname "$0")/common.sh"

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

# 添加节点菜单
add_node_menu() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}          添加节点${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    echo -e "${BLUE}请选择要添加的节点类型:${NC}"
    echo "1. Hysteria2"
    echo "2. VLESS"
    echo "3. Trojan"
    echo "4. Shadowsocks"
    echo "5. VMess"
    echo "6. TUIC"
    echo "7. HTTP"
    echo "8. SOCKS5"
    echo "0. 返回上级菜单"
    echo ""
    
    read -p "请选择 [0-8]: " protocol_choice
    
    case $protocol_choice in
        1)
            add_hysteria2
            ;;
        2)
            add_vless
            ;;
        3)
            add_trojan
            ;;
        4)
            add_shadowsocks
            ;;
        5)
            add_vmess
            ;;
        6)
            add_tuic
            ;;
        7)
            add_http
            ;;
        8)
            add_socks5
            ;;
        0)
            return
            ;;
        *)
            log_error "无效选择"
            read -p "按回车键继续..."
            ;;
    esac
}

# 添加 Hysteria2 节点
add_hysteria2() {
    log_step "添加 Hysteria2 节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    read -p "请输入端口 (随机端口: $port): " input_port
    port=${input_port:-$port}
    
    local password=$(generate_random "uuid")
    
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
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}hysteria2://$password@$domain:$port/?sni=bing.com&alpn=h3&insecure=1#hy2-$port${NC}"
    
    read -p "按回车键继续..."
}

# 添加 VLESS 节点
add_vless() {
    log_step "添加 VLESS 节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    read -p "请输入端口 (随机端口: $port): " input_port
    port=${input_port:-$port}
    
    local uuid=$(generate_random "uuid")
    
    local new_inbound=$(cat << EOF
{
  "type": "vless",
  "tag": "vless-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [{"uuid": "$uuid", "flow": "xtls-rprx-vision"}],
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
    
    log_success "VLESS 节点添加成功"
    echo -e "${GREEN}端口: $port${NC}"
    echo -e "${GREEN}UUID: $uuid${NC}"
    
    local domain=$(cat "$DATA_DIR/data/domain.txt")
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}vless://$uuid@$domain:$port?encryption=none&security=tls&sni=bing.com&fp=chrome&type=tcp&flow=xtls-rprx-vision&allowInsecure=1#vless-$port${NC}"
    
    read -p "按回车键继续..."
}

# 添加 Trojan 节点
add_trojan() {
    log_step "添加 Trojan 节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    read -p "请输入端口 (随机端口: $port): " input_port
    port=${input_port:-$port}
    
    local password=$(generate_random "password")
    
    local new_inbound=$(cat << EOF
{
  "type": "trojan",
  "tag": "trojan-$port",
  "listen": "::",
  "listen_port": $port,
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
    
    log_success "Trojan 节点添加成功"
    echo -e "${GREEN}端口: $port${NC}"
    echo -e "${GREEN}密码: $password${NC}"
    
    local domain=$(cat "$DATA_DIR/data/domain.txt")
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}trojan://$password@$domain:$port?security=tls&sni=bing.com&type=tcp&allowInsecure=1#trojan-$port${NC}"
    
    read -p "按回车键继续..."
}

# 添加 Shadowsocks 节点
add_shadowsocks() {
    log_step "添加 Shadowsocks 节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    read -p "请输入端口 (随机端口: $port): " input_port
    port=${input_port:-$port}
    
    local password=$(generate_random "password")
    
    echo "请选择加密方法:"
    echo "1. aes-128-gcm"
    echo "2. 2022-blake3-aes-128-gcm (推荐)"
    echo "3. aes-256-gcm"
    echo "4. 2022-blake3-aes-256-gcm"
    echo "5. chacha20-ietf-poly1305"
    echo "6. xchacha20-ietf-poly1305"
    read -p "请选择 [1-6]: " method_choice
    
    case $method_choice in
        1) local method="aes-128-gcm" ;;
        2) local method="2022-blake3-aes-128-gcm" ;;
        3) local method="aes-256-gcm" ;;
        4) local method="2022-blake3-aes-256-gcm" ;;
        5) local method="chacha20-ietf-poly1305" ;;
        6) local method="xchacha20-ietf-poly1305" ;;
        *) local method="2022-blake3-aes-128-gcm" ;;  # 默认使用推荐的加密方法
    esac
    
    local new_inbound=$(cat << EOF
{
  "type": "shadowsocks",
  "tag": "ss-$port",
  "listen": "::",
  "listen_port": $port,
  "method": "$method",
  "password": "$password"
}
EOF
)
    
    echo "$new_inbound" | jq . > /tmp/new_inbound.json
    jq '.inbounds += [input]' "$CONFIG_FILE" /tmp/new_inbound.json > /tmp/config_tmp.json
    mv /tmp/config_tmp.json "$CONFIG_FILE"
    
    restart_singbox
    
    log_success "Shadowsocks 节点添加成功"
    echo -e "${GREEN}端口: $port${NC}"
    echo -e "${GREEN}密码: $password${NC}"
    echo -e "${GREEN}加密: $method${NC}"
    
    local domain=$(cat "$DATA_DIR/data/domain.txt")
    local ss_url=$(echo -n "$method:$password" | base64 -w 0)
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}ss://$ss_url@$domain:$port#ss-$port${NC}"
    
    read -p "按回车键继续..."
}

# 添加 VMess 节点
add_vmess() {
    log_step "添加 VMess 节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    read -p "请输入端口 (随机端口: $port): " input_port
    port=${input_port:-$port}
    
    local uuid=$(generate_random "uuid")
    local ws_path="/v6"
    local ws_host="fe2.update.microsoft.com"
    
    local new_inbound=$(cat << EOF
{
  "type": "vmess",
  "tag": "vmess-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "name": "user",
      "uuid": "$uuid"
    }
  ],
  "transport": {
    "type": "ws",
    "path": "$ws_path",
    "headers": {
      "Host": "$ws_host"
    }
  }
}
EOF
)
    
    echo "$new_inbound" | jq . > /tmp/new_inbound.json
    jq '.inbounds += [input]' "$CONFIG_FILE" /tmp/new_inbound.json > /tmp/config_tmp.json
    mv /tmp/config_tmp.json "$CONFIG_FILE"
    
    restart_singbox
    
    log_success "VMess 节点添加成功"
    echo -e "${GREEN}端口: $port${NC}"
    echo -e "${GREEN}UUID: $uuid${NC}"
    echo -e "${GREEN}路径: $ws_path${NC}"
    echo -e "${GREEN}Host: $ws_host${NC}"
    
    local domain=$(cat "$DATA_DIR/data/domain.txt")
    local vmess_config=$(cat << EOF
{
  "v": "2",
  "ps": "vmess-$port",
  "add": "$domain",
  "port": $port,
  "id": "$uuid",
  "aid": 0,
  "net": "ws",
  "type": "none",
  "host": "$ws_host",
  "path": "$ws_path",
  "tls": "none"
}
EOF
)
    local encoded_config=$(echo "$vmess_config" | base64 -w 0)
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}vmess://$encoded_config${NC}"
    
    read -p "按回车键继续..."
}

# 添加 TUIC 节点
add_tuic() {
    log_step "添加 TUIC 节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    read -p "请输入端口 (随机端口: $port): " input_port
    port=${input_port:-$port}
    
    local uuid=$(generate_random "uuid")
    local password=$(generate_random "password")
    local congestion_control="bbr"  # 硬编码使用BBR拥塞控制算法
    
    local new_inbound=$(cat << EOF
{
  "type": "tuic",
  "tag": "tuic-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$uuid",
      "password": "$password"
    }
  ],
  "congestion_control": "$congestion_control",
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
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
    
    log_success "TUIC 节点添加成功"
    echo -e "${GREEN}端口: $port${NC}"
    echo -e "${GREEN}UUID: $uuid${NC}"
    echo -e "${GREEN}密码: $password${NC}"
    echo -e "${GREEN}拥塞控制: $congestion_control${NC}"
    
    local domain=$(cat "$DATA_DIR/data/domain.txt")
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}tuic://$uuid:$password@$domain:$port?sni=bing.com&alpn=h3&congestion_control=$congestion_control&insecure=1#tuic-$port${NC}"
    
    read -p "按回车键继续..."
}

# 添加 HTTP 代理节点
add_http() {
    log_step "添加 HTTP 代理节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    read -p "请输入端口 (随机端口: $port): " input_port
    port=${input_port:-$port}
    
    local username=$(generate_random "base64")
    local password=$(generate_random "password")
    
    local new_inbound=$(cat << EOF
{
  "type": "http",
  "tag": "http-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "username": "$username",
      "password": "$password"
    }
  ]
}
EOF
)
    
    echo "$new_inbound" | jq . > /tmp/new_inbound.json
    jq '.inbounds += [input]' "$CONFIG_FILE" /tmp/new_inbound.json > /tmp/config_tmp.json
    mv /tmp/config_tmp.json "$CONFIG_FILE"
    
    restart_singbox
    
    log_success "HTTP 代理节点添加成功"
    echo -e "${GREEN}端口: $port${NC}"
    echo -e "${GREEN}用户名: $username${NC}"
    echo -e "${GREEN}密码: $password${NC}"
    
    local domain=$(cat "$DATA_DIR/data/domain.txt")
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}http://$username:$password@$domain:$port#http-$port${NC}"
    
    read -p "按回车键继续..."
}

# 添加 SOCKS5 代理节点
add_socks5() {
    log_step "添加 SOCKS5 代理节点"
    
    local port=$(get_free_port)
    if [ "$port" = "0" ]; then
        log_error "无法获取可用端口"
        return
    fi
    
    read -p "请输入端口 (随机端口: $port): " input_port
    port=${input_port:-$port}
    
    local username=$(generate_random "base64")
    local password=$(generate_random "password")
    
    local new_inbound=$(cat << EOF
{
  "type": "socks",
  "tag": "socks5-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "username": "$username",
      "password": "$password"
    }
  ]
}
EOF
)
    
    echo "$new_inbound" | jq . > /tmp/new_inbound.json
    jq '.inbounds += [input]' "$CONFIG_FILE" /tmp/new_inbound.json > /tmp/config_tmp.json
    mv /tmp/config_tmp.json "$CONFIG_FILE"
    
    restart_singbox
    
    log_success "SOCKS5 代理节点添加成功"
    echo -e "${GREEN}端口: $port${NC}"
    echo -e "${GREEN}用户名: $username${NC}"
    echo -e "${GREEN}密码: $password${NC}"
    
    local domain=$(cat "$DATA_DIR/data/domain.txt")
    echo -e "\n${BLUE}客户端链接:${NC}"
    echo -e "${GREEN}socks5://$username:$password@$domain:$port#socks5-$port${NC}"
    
    read -p "按回车键继续..."
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
    
    for i in $(seq 0 $((node_count-1))); do
        local node_type=$(jq -r ".inbounds[$i].type" "$CONFIG_FILE")
        local node_tag=$(jq -r ".inbounds[$i].tag // \"节点$((i+1))\"" "$CONFIG_FILE")
        local node_port=$(jq -r ".inbounds[$i].listen_port" "$CONFIG_FILE")
        
        echo -e "${BLUE}节点 $((i+1)): $node_tag${NC}"
        echo -e "  类型: $node_type"
        echo -e "  端口: $node_port"
        
        case $node_type in
            "hysteria2")
                local password=$(jq -r ".inbounds[$i].users[0].password" "$CONFIG_FILE")
                echo -e "  密码: $password"
                echo -e "  客户端链接: ${GREEN}hysteria2://$password@$domain:$node_port/?sni=bing.com&alpn=h3&insecure=1#$node_tag${NC}"
                ;;
            "vless")
                local uuid=$(jq -r ".inbounds[$i].users[0].uuid" "$CONFIG_FILE")
                echo -e "  UUID: $uuid"
                echo -e "  客户端链接: ${GREEN}vless://$uuid@$domain:$node_port?encryption=none&security=tls&sni=bing.com&fp=chrome&type=tcp&flow=xtls-rprx-vision&allowInsecure=1#$node_tag${NC}"
                ;;
            "trojan")
                local password=$(jq -r ".inbounds[$i].users[0].password" "$CONFIG_FILE")
                echo -e "  密码: $password"
                echo -e "  客户端链接: ${GREEN}trojan://$password@$domain:$node_port?security=tls&sni=bing.com&type=tcp&allowInsecure=1#$node_tag${NC}"
                ;;
            "shadowsocks")
                local method=$(jq -r ".inbounds[$i].method" "$CONFIG_FILE")
                local password=$(jq -r ".inbounds[$i].password" "$CONFIG_FILE")
                echo -e "  加密: $method"
                echo -e "  密码: $password"
                local ss_url=$(echo -n "$method:$password" | base64 -w 0)
                echo -e "  客户端链接: ${GREEN}ss://$ss_url@$domain:$node_port#$node_tag${NC}"
                ;;
            "vmess")
                local uuid=$(jq -r ".inbounds[$i].users[0].uuid" "$CONFIG_FILE")
                local ws_path=$(jq -r ".inbounds[$i].transport.path" "$CONFIG_FILE")
                local ws_host=$(jq -r ".inbounds[$i].transport.headers.Host" "$CONFIG_FILE")
                echo -e "  UUID: $uuid"
                echo -e "  WebSocket路径: $ws_path"
                echo -e "  Host: $ws_host"
                local vmess_config="{\"v\":\"2\",\"ps\":\"$node_tag\",\"add\":\"$domain\",\"port\":$node_port,\"id\":\"$uuid\",\"aid\":0,\"net\":\"ws\",\"type\":\"none\",\"host\":\"$ws_host\",\"path\":\"$ws_path\",\"tls\":\"none\"}"
                local encoded_config=$(echo "$vmess_config" | base64 -w 0)
                echo -e "  客户端链接: ${GREEN}vmess://$encoded_config${NC}"
                ;;
            "tuic")
                local uuid=$(jq -r ".inbounds[$i].users[0].uuid" "$CONFIG_FILE")
                local password=$(jq -r ".inbounds[$i].users[0].password" "$CONFIG_FILE")
                local congestion_control=$(jq -r ".inbounds[$i].congestion_control" "$CONFIG_FILE")
                echo -e "  UUID: $uuid"
                echo -e "  密码: $password"
                echo -e "  拥塞控制: $congestion_control"
                echo -e "  客户端链接: ${GREEN}tuic://$uuid:$password@$domain:$node_port?sni=bing.com&alpn=h3&congestion_control=$congestion_control&insecure=1#$node_tag${NC}"
                ;;
            "http")
                local username=$(jq -r ".inbounds[$i].users[0].username" "$CONFIG_FILE")
                local password=$(jq -r ".inbounds[$i].users[0].password" "$CONFIG_FILE")
                echo -e "  用户名: $username"
                echo -e "  密码: $password"
                echo -e "  客户端链接: ${GREEN}http://$username:$password@$domain:$node_port#$node_tag${NC}"
                ;;
            "socks")
                local username=$(jq -r ".inbounds[$i].users[0].username" "$CONFIG_FILE")
                local password=$(jq -r ".inbounds[$i].users[0].password" "$CONFIG_FILE")
                echo -e "  用户名: $username"
                echo -e "  密码: $password"
                echo -e "  客户端链接: ${GREEN}socks5://$username:$password@$domain:$node_port#$node_tag${NC}"
                ;;
        esac
        echo ""
    done
}

# 删除节点
delete_node() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "配置文件不存在"
        return
    fi
    
    local node_count=$(jq '.inbounds | length' "$CONFIG_FILE")
    if [ "$node_count" -eq 0 ]; then
        log_warning "当前没有节点可删除"
        return
    fi
    
    echo -e "${BLUE}当前节点列表:${NC}"
    for i in $(seq 0 $((node_count-1))); do
        local node_tag=$(jq -r ".inbounds[$i].tag // \"节点$((i+1))\"" "$CONFIG_FILE")
        local node_type=$(jq -r ".inbounds[$i].type" "$CONFIG_FILE")
        local node_port=$(jq -r ".inbounds[$i].listen_port" "$CONFIG_FILE")
        echo "$((i+1)). $node_tag ($node_type:$node_port)"
    done
    
    read -p "请输入要删除的节点编号: " node_index
    
    if ! [[ "$node_index" =~ ^[0-9]+$ ]] || [ "$node_index" -lt 1 ] || [ "$node_index" -gt "$node_count" ]; then
        log_error "无效的节点编号"
        return
    fi
    
    local array_index=$((node_index-1))
    local node_tag=$(jq -r ".inbounds[$array_index].tag // \"节点$node_index\"" "$CONFIG_FILE")
    
    read -p "确认删除节点 \"$node_tag\"？(y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        log_warning "取消删除操作"
        return
    fi
    
    jq "del(.inbounds[$array_index])" "$CONFIG_FILE" > /tmp/config_tmp.json
    mv /tmp/config_tmp.json "$CONFIG_FILE"
    
    restart_singbox
    
    log_success "节点 \"$node_tag\" 删除成功"
} 